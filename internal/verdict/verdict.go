// Package verdict evaluates a complete forwarding PoC evidence set without
// consulting process state or making network requests.
package verdict

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"corp.example/overseas-access-gateway/internal/config"
	"corp.example/overseas-access-gateway/internal/inventory"
)

const (
	StatusPass         = "PASS"
	StatusFail         = "FAIL"
	StatusInconclusive = "INCONCLUSIVE"

	EvidenceSchemaVersion = 1
	MaxEvidenceAge        = 4 * time.Hour
	MaxClockSkew          = 2 * time.Minute
)

// Evidence is the explicit input to Evaluate. ArtifactErrors contains fatal
// file/envelope decode errors; malformed probe records are counted on their
// own artifact so a valid sibling leak observation is never discarded.
type Evidence struct {
	RunID           string
	Config          *config.Config
	EvaluatedAt     time.Time
	InventoryBefore *inventory.Artifact
	TelecomUp       *ProbeEvidence
	TelecomDown     *ProbeEvidence
	DownMonitor     *DownMonitorEvidence
	InventoryAfter  *inventory.Artifact
	ArtifactErrors  []string
}

// ProbeEvidence is a strictly decoded and normalized probe artifact.
type ProbeEvidence struct {
	SchemaVersion  int
	RunID          string
	ConfigDigest   string
	StartedAt      time.Time
	FinishedAt     time.Time
	Results        []ProbeResult
	InvalidRecords int
}

// ProbeResult models application health separately from path reachability.
type ProbeResult struct {
	TargetName string
	TargetURL  string
	Reachable  bool
	Healthy    bool
	StartedAt  time.Time
	FinishedAt time.Time
}

// DownMonitorEvidence proves the configured telecom route/interface state was
// sampled for the native probe's entire lifetime.
type DownMonitorEvidence struct {
	SchemaVersion        int            `json:"schema_version"`
	RunID                string         `json:"run_id"`
	ConfigDigest         string         `json:"config_digest"`
	StartedAt            time.Time      `json:"started_at"`
	FinishedAt           time.Time      `json:"finished_at"`
	SampleCount          int            `json:"sample_count"`
	TelecomRoutePrefixes []string       `json:"telecom_route_prefixes"`
	ReconnectDetected    bool           `json:"reconnect_detected"`
	ReconnectAt          time.Time      `json:"reconnect_at,omitempty"`
	ReconnectInterfaceUp bool           `json:"reconnect_interface_up"`
	ReconnectRoutes      []MonitorRoute `json:"reconnect_routes"`
}

// MonitorRoute is the explicit configured-prefix route state observed when an
// automatic telecom reconnect is detected.
type MonitorRoute struct {
	DestinationPrefix string `json:"destination_prefix"`
	NextHop           string `json:"next_hop"`
	State             string `json:"state"`
}

// Report is the deterministic machine-readable gate decision.
type Report struct {
	Status       string    `json:"status"`
	Code         string    `json:"code"`
	Message      string    `json:"message"`
	RunID        string    `json:"run_id"`
	ConfigDigest string    `json:"config_digest"`
	EvaluatedAt  time.Time `json:"evaluated_at"`
}

// Evaluate applies fail-closed acceptance rules. A fresh, identity-bound,
// structurally valid down-state reachability signal has safety precedence over
// missing artifacts and malformed sibling probe records.
func Evaluate(e Evidence) Report {
	digest, contextValid := expectedContext(e)
	if contextValid && validProbeEnvelope(e.TelecomDown, e, digest) {
		for _, result := range e.TelecomDown.Results {
			if validNormalizedResult(result, e.TelecomDown) && exactConfiguredTarget(result, e.Config.ApprovedTargets) && result.Reachable {
				return makeReport(e, digest, StatusFail, "FAIL_LEAK", fmt.Sprintf("approved target %q remained reachable while telecom was down", result.TargetName))
			}
		}
	}

	if !contextValid || e.InventoryBefore == nil || e.TelecomUp == nil || e.TelecomDown == nil || e.DownMonitor == nil || e.InventoryAfter == nil {
		return makeReport(e, digest, StatusInconclusive, "INCONCLUSIVE_INVALID_EVIDENCE", "validated configuration and all five bound evidence artifacts are required")
	}
	if len(e.ArtifactErrors) != 0 {
		return makeReport(e, digest, StatusInconclusive, "INCONCLUSIVE_INVALID_EVIDENCE", "one or more evidence artifacts could not be decoded strictly")
	}
	if !validInventoryArtifact(e.InventoryBefore, e, digest) ||
		!validProbeEnvelope(e.TelecomUp, e, digest) || e.TelecomUp.InvalidRecords != 0 ||
		!validProbeEnvelope(e.TelecomDown, e, digest) || e.TelecomDown.InvalidRecords != 0 ||
		!validMonitor(e.DownMonitor, e, digest) ||
		!validInventoryArtifact(e.InventoryAfter, e, digest) {
		return makeReport(e, digest, StatusInconclusive, "INCONCLUSIVE_INVALID_EVIDENCE", "evidence identity, freshness, or structure is invalid")
	}
	if !sameConfiguredTargets(e.TelecomUp.Results, e.Config.ApprovedTargets) || !sameConfiguredTargets(e.TelecomDown.Results, e.Config.ApprovedTargets) {
		return makeReport(e, digest, StatusInconclusive, "INCONCLUSIVE_INVALID_EVIDENCE", "probe evidence must contain each exact configured target name and URL once")
	}
	if !validChronology(e) {
		return makeReport(e, digest, StatusInconclusive, "INCONCLUSIVE_INVALID_EVIDENCE", "evidence capture chronology is invalid")
	}
	if !sameState(e.InventoryBefore.State, e.InventoryAfter.State) {
		return makeReport(e, digest, StatusFail, "FAIL_STATE_DRIFT", "interface, route, NAT, or firewall inventory changed after rollback")
	}
	if e.DownMonitor.ReconnectDetected {
		return makeReport(e, digest, StatusFail, "FAIL_TELECOM_RECONNECTED", "telecom interface or configured external/default route reappeared while the native probe was running")
	}

	failed := make([]string, 0)
	for _, result := range e.TelecomUp.Results {
		if !result.Healthy {
			failed = append(failed, result.TargetName)
		}
	}
	if len(failed) != 0 {
		sort.Strings(failed)
		return makeReport(e, digest, StatusFail, "FAIL_NO_FORWARD", fmt.Sprintf("approved target %q did not return a healthy HTTPS response while telecom was up", failed[0]))
	}

	return makeReport(e, digest, StatusPass, "PASS", "approved-target forwarding worked, failed closed under continuous monitoring, and exact network state was restored")
}

func expectedContext(e Evidence) (string, bool) {
	if e.Config == nil || e.Config.Validate() != nil || strings.TrimSpace(e.RunID) != e.RunID || len(e.RunID) < 8 || e.EvaluatedAt.IsZero() {
		return "", false
	}
	digest, err := config.Digest(*e.Config)
	return digest, err == nil
}

func validProbeEnvelope(probe *ProbeEvidence, e Evidence, digest string) bool {
	if probe == nil || probe.SchemaVersion != EvidenceSchemaVersion || probe.RunID != e.RunID || probe.ConfigDigest != digest || len(probe.Results) == 0 {
		return false
	}
	if !validInterval(probe.StartedAt, probe.FinishedAt, e.EvaluatedAt) {
		return false
	}
	for _, result := range probe.Results {
		if !validNormalizedResult(result, probe) {
			return false
		}
	}
	return true
}

func validNormalizedResult(result ProbeResult, envelope *ProbeEvidence) bool {
	return strings.TrimSpace(result.TargetName) == result.TargetName && result.TargetName != "" && result.TargetURL != "" &&
		!result.StartedAt.IsZero() && !result.FinishedAt.Before(result.StartedAt) &&
		!result.StartedAt.Before(envelope.StartedAt) && !result.FinishedAt.After(envelope.FinishedAt) &&
		(!result.Healthy || result.Reachable)
}

func validInventoryArtifact(artifact *inventory.Artifact, e Evidence, digest string) bool {
	if artifact.SchemaVersion != EvidenceSchemaVersion || artifact.RunID != e.RunID || artifact.ConfigDigest != digest || !freshTime(artifact.CapturedAt, e.EvaluatedAt) {
		return false
	}
	state := artifact.State
	if len(state.Interfaces) == 0 || len(state.Routes) == 0 || len(state.FirewallRules) == 0 {
		return false
	}
	aliases := make(map[string]bool)
	for _, item := range state.Interfaces {
		if item.Alias == "" || item.Index <= 0 || item.AddressFamily == "" || item.Status == "" || item.Forwarding == "" || item.MTU <= 0 {
			return false
		}
		aliases[item.Alias] = true
	}
	for _, alias := range []string{e.Config.WireGuardInterface, e.Config.TelecomInterface, e.Config.EmployeeInterface} {
		if !aliases[alias] {
			return false
		}
	}
	for _, item := range state.Routes {
		if item.Alias == "" || item.Index <= 0 || item.DestinationPrefix == "" || item.NextHop == "" || item.State == "" {
			return false
		}
	}
	for _, item := range state.NAT {
		if item.Name == "" || item.InternalPrefix == "" {
			return false
		}
	}
	for _, item := range state.FirewallRules {
		if item.Name == "" || item.DisplayName == "" || item.Enabled == "" || item.Profile == "" || item.Direction == "" || item.Action == "" {
			return false
		}
	}
	return true
}

func validMonitor(monitor *DownMonitorEvidence, e Evidence, digest string) bool {
	if monitor.SchemaVersion != EvidenceSchemaVersion || monitor.RunID != e.RunID || monitor.ConfigDigest != digest || monitor.SampleCount <= 0 ||
		!validInterval(monitor.StartedAt, monitor.FinishedAt, e.EvaluatedAt) || !reflect.DeepEqual(monitor.TelecomRoutePrefixes, e.Config.TelecomRoutePrefixes) {
		return false
	}
	if monitor.ReconnectDetected {
		if monitor.ReconnectAt.IsZero() || monitor.ReconnectAt.Before(monitor.StartedAt) || monitor.ReconnectAt.After(monitor.FinishedAt) || (!monitor.ReconnectInterfaceUp && len(monitor.ReconnectRoutes) == 0) {
			return false
		}
		for _, route := range monitor.ReconnectRoutes {
			if route.DestinationPrefix == "" || route.NextHop == "" || route.State == "" {
				return false
			}
		}
		return true
	}
	return monitor.ReconnectAt.IsZero() && !monitor.ReconnectInterfaceUp && len(monitor.ReconnectRoutes) == 0
}

func validInterval(start, finish, evaluatedAt time.Time) bool {
	return !start.IsZero() && !finish.Before(start) && freshTime(start, evaluatedAt) && freshTime(finish, evaluatedAt)
}

func freshTime(value, evaluatedAt time.Time) bool {
	return !value.IsZero() && !value.Before(evaluatedAt.Add(-MaxEvidenceAge)) && !value.After(evaluatedAt.Add(MaxClockSkew))
}

func validChronology(e Evidence) bool {
	return !e.TelecomUp.StartedAt.Before(e.InventoryBefore.CapturedAt) &&
		!e.DownMonitor.StartedAt.Before(e.TelecomUp.FinishedAt) &&
		!e.TelecomDown.StartedAt.Before(e.DownMonitor.StartedAt) &&
		!e.TelecomDown.FinishedAt.After(e.DownMonitor.FinishedAt) &&
		!e.InventoryAfter.CapturedAt.Before(e.DownMonitor.FinishedAt)
}

func exactConfiguredTarget(result ProbeResult, targets []config.Target) bool {
	for _, target := range targets {
		if result.TargetName == target.Name && result.TargetURL == target.URL {
			return true
		}
	}
	return false
}

func sameConfiguredTargets(results []ProbeResult, expected []config.Target) bool {
	if len(results) != len(expected) || len(expected) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		if !exactConfiguredTarget(result, expected) {
			return false
		}
		key := result.TargetName + "\x00" + result.TargetURL
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func sameState(left, right inventory.State) bool {
	return sameJSONMultiset(left.Interfaces, right.Interfaces) &&
		sameJSONMultiset(left.Routes, right.Routes) &&
		sameJSONMultiset(left.NAT, right.NAT) &&
		sameFirewallRules(left.FirewallRules, right.FirewallRules)
}

func sameJSONMultiset[T any](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	encode := func(items []T) []string {
		values := make([]string, len(items))
		for i, item := range items {
			contents, _ := json.Marshal(item)
			values[i] = string(contents)
		}
		sort.Strings(values)
		return values
	}
	return reflect.DeepEqual(encode(left), encode(right))
}

func sameFirewallRules(left, right []inventory.FirewallRule) bool {
	normalize := func(items []inventory.FirewallRule) []inventory.FirewallRule {
		result := append([]inventory.FirewallRule(nil), items...)
		for i := range result {
			result[i].InterfaceAliases = sortedCopy(result[i].InterfaceAliases)
			result[i].LocalAddresses = sortedCopy(result[i].LocalAddresses)
			result[i].RemoteAddresses = sortedCopy(result[i].RemoteAddresses)
			result[i].Protocols = sortedCopy(result[i].Protocols)
			result[i].LocalPorts = sortedCopy(result[i].LocalPorts)
			result[i].RemotePorts = sortedCopy(result[i].RemotePorts)
			result[i].Programs = sortedCopy(result[i].Programs)
			result[i].Services = sortedCopy(result[i].Services)
		}
		return result
	}
	return sameJSONMultiset(normalize(left), normalize(right))
}

func sortedCopy(values []string) []string {
	copyOfValues := append([]string(nil), values...)
	sort.Strings(copyOfValues)
	return copyOfValues
}

func makeReport(e Evidence, digest, status, code, message string) Report {
	return Report{Status: status, Code: code, Message: message, RunID: e.RunID, ConfigDigest: digest, EvaluatedAt: e.EvaluatedAt}
}
