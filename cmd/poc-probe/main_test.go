package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/config"
	"corp.example/overseas-access-gateway/internal/inventory"
	"corp.example/overseas-access-gateway/internal/probe"
	"corp.example/overseas-access-gateway/internal/verdict"
)

func TestRunPreflightPrintsSuccessForValidConfiguration(t *testing.T) {
	path := t.TempDir() + "/poc.yaml"
	configContents := `wireguard_subnet: 100.127.77.0/24
wireguard_interface: wg-overseas-poc
telecom_interface: Telecom-Client
telecom_route_prefixes:
  - 0.0.0.0/0
employee_interface: Ethernet
internal_cidrs:
  - 10.0.0.0/8
approved_targets:
  - name: operator-approved-test
    url: https://approved-test.example.invalid/
probe_timeout: 8s
`
	if err := os.WriteFile(path, []byte(configContents), 0o600); err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"preflight", "--config", path}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if got := stdout.String(); got != "PREFLIGHT_CONFIG_OK\n" {
		t.Fatalf("stdout = %q, want success marker", got)
	}
}

func TestRunPreflightPrintsOneActionableErrorForInvalidConfiguration(t *testing.T) {
	path := t.TempDir() + "/poc.yaml"
	contents := `wireguard_subnet: not-a-cidr
wireguard_interface: wg-overseas-poc
telecom_interface: Telecom-Client
telecom_route_prefixes:
  - 0.0.0.0/0
employee_interface: Ethernet
internal_cidrs:
  - 10.0.0.0/8
approved_targets:
  - name: operator-approved-test
    url: https://approved-test.example.invalid/
probe_timeout: 8s
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"preflight", "--config", path}, &stdout, &stderr); exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no success output", stdout.String())
	}
	if got := stderr.String(); !strings.HasPrefix(got, "PREFLIGHT_CONFIG_ERROR: wireguard_subnet") || strings.Count(got, "\n") != 1 {
		t.Fatalf("stderr = %q, want one actionable configuration error", got)
	}
}

func TestRunInventoryWritesNewEvidenceAndRefusesReplacement(t *testing.T) {
	configPath := t.TempDir() + "/poc.yaml"
	configContents := `wireguard_subnet: 100.127.77.0/24
wireguard_interface: wg-overseas-poc
telecom_interface: Telecom-Client
telecom_route_prefixes:
  - 0.0.0.0/0
employee_interface: Ethernet
internal_cidrs:
  - 10.0.0.0/8
approved_targets:
  - name: operator-approved-test
    url: https://approved-test.example.invalid/
probe_timeout: 8s
`
	if err := os.WriteFile(configPath, []byte(configContents), 0o600); err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	previousSnapshot := snapshot
	snapshot = func(context.Context) (inventory.State, error) {
		return inventory.State{
			Interfaces: []inventory.Interface{
				{Alias: "Ethernet", Index: 7, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1500},
				{Alias: "Telecom-Client", Index: 11, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1400},
				{Alias: "wg-overseas-poc", Index: 19, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1420},
			},
			Routes: []inventory.Route{
				{Alias: "Ethernet", Index: 7, DestinationPrefix: "0.0.0.0/0", NextHop: "172.20.10.1", State: "Alive"},
				{Alias: "wg-overseas-poc", Index: 19, DestinationPrefix: "100.127.77.0/24", NextHop: "0.0.0.0", State: "Alive"},
			},
			NAT:           []inventory.NAT{},
			FirewallRules: []inventory.FirewallRule{completeFirewallRuleForTest()},
		}, nil
	}
	t.Cleanup(func() { snapshot = previousSnapshot })

	outputPath := t.TempDir() + "/inventory-before.json"
	var stdout, stderr bytes.Buffer
	args := []string{"inventory", "--config", configPath, "--run-id", "run-inventory-test", "--out", outputPath}
	if exitCode := run(args, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if got := stdout.String(); got != "INVENTORY_OK\n" {
		t.Fatalf("stdout = %q, want success marker", got)
	}

	evidenceContents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var artifact inventory.Artifact
	if err := json.Unmarshal(evidenceContents, &artifact); err != nil {
		t.Fatalf("decode written evidence: %v", err)
	}
	if artifact.SchemaVersion != 1 || artifact.RunID != "run-inventory-test" || len(artifact.ConfigDigest) != 64 || artifact.CapturedAt.IsZero() || len(artifact.State.Interfaces) != 3 {
		t.Fatalf("written inventory artifact = %#v", artifact)
	}

	stdout.Reset()
	stderr.Reset()
	if exitCode := run(args, &stdout, &stderr); exitCode != 1 {
		t.Fatalf("second run() exit code = %d, want 1; stderr = %q", exitCode, stderr.String())
	}
	if !strings.HasPrefix(stderr.String(), "INVENTORY_OUTPUT_ERROR:") {
		t.Fatalf("stderr = %q, want create-new output error", stderr.String())
	}
}

func TestRunProbeWritesEvidenceForConfiguredApprovedTargets(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "local approved target")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer server.Close()

	configPath := t.TempDir() + "/poc.yaml"
	configContents := `wireguard_subnet: 100.127.77.0/24
wireguard_interface: wg-overseas-poc
telecom_interface: Telecom-Client
telecom_route_prefixes:
  - 0.0.0.0/0
employee_interface: Ethernet
internal_cidrs:
  - 10.0.0.0/8
approved_targets:
  - name: operator-approved-local-test
    url: ` + server.URL + `
probe_timeout: 1s
`
	if err := os.WriteFile(configPath, []byte(configContents), 0o600); err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	outputPath := t.TempDir() + "/probe-evidence.json"
	var stdout, stderr bytes.Buffer
	args := []string{"probe", "--config", configPath, "--run-id", "run-probe-test", "--out", outputPath}
	if exitCode := run(args, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if got := stdout.String(); got != "PROBE_EVIDENCE_WRITTEN\n" {
		t.Fatalf("stdout = %q, want evidence marker", got)
	}

	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read probe evidence: %v", err)
	}
	var artifact probe.Artifact
	if err := json.Unmarshal(contents, &artifact); err != nil {
		t.Fatalf("decode probe evidence: %v", err)
	}
	results := artifact.Results
	if artifact.SchemaVersion != 1 || artifact.RunID != "run-probe-test" || len(artifact.ConfigDigest) != 64 || artifact.StartedAt.IsZero() || artifact.FinishedAt.Before(artifact.StartedAt) {
		t.Fatalf("probe artifact = %#v", artifact)
	}
	if len(results) != 1 || results[0].TargetName != "operator-approved-local-test" {
		t.Fatalf("results = %#v, want exactly configured target", results)
	}
	if results[0].ErrorCode != "tls_failed" {
		t.Fatalf("result error = %q, want local server validation failure evidence", results[0].ErrorCode)
	}
}

func TestNormalizeProbeResultModelsReachabilityIndependentlyFromTwoHundredStatus(t *testing.T) {
	now := time.Now().UTC()
	base := probe.Result{
		TargetName: "operator-approved-test", TargetURL: "https://approved.example.invalid/health",
		ResolvedIPs: []string{"192.0.2.10"}, SelectedIP: "192.0.2.10", TCPLatency: time.Millisecond,
		TLSStatus: "validated", HTTPStatus: http.StatusInternalServerError,
		StartedAt: now, FinishedAt: now.Add(time.Second), ErrorCode: "http_rejected",
	}

	tests := []struct {
		name      string
		result    probe.Result
		valid     bool
		reachable bool
		healthy   bool
	}{
		{name: "HTTP 500 proves path", result: base, valid: true, reachable: true},
		{name: "body failure proves path", result: func() probe.Result { r := base; r.HTTPStatus = http.StatusOK; r.ErrorCode = "body_failed"; return r }(), valid: true, reachable: true},
		{name: "TLS failure proves path", result: func() probe.Result {
			r := base
			r.TLSStatus = "failed"
			r.HTTPStatus = 0
			r.ErrorCode = "tls_failed"
			return r
		}(), valid: true, reachable: true},
		{name: "TCP failure is unreachable", result: func() probe.Result {
			r := base
			r.TCPLatency = 0
			r.TLSStatus = "not_attempted"
			r.HTTPStatus = 0
			r.ErrorCode = "tcp_failed"
			return r
		}(), valid: true},
		{name: "two hundred is healthy", result: func() probe.Result { r := base; r.HTTPStatus = http.StatusNoContent; r.ErrorCode = ""; return r }(), valid: true, reachable: true, healthy: true},
		{name: "contradictory TCP failure rejected", result: func() probe.Result {
			r := base
			r.TLSStatus = "not_attempted"
			r.HTTPStatus = 0
			r.ErrorCode = "tcp_failed"
			return r
		}()},
		{name: "unknown error rejected", result: func() probe.Result { r := base; r.ErrorCode = "made_up"; return r }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			normalized, valid := normalizeProbeResult(test.result)
			if valid != test.valid || (valid && (normalized.Reachable != test.reachable || normalized.Healthy != test.healthy)) {
				t.Fatalf("normalizeProbeResult() = %#v, %v", normalized, valid)
			}
		})
	}
}

func TestRunVerdictBindsArtifactsToConfigAndRunAndPreservesCreateNewOutput(t *testing.T) {
	artifacts := t.TempDir()
	configPath, cfg := writeVerdictConfig(t)
	runID := "run-verdict-pass"
	writePassingVerdictArtifacts(t, artifacts, cfg, runID, time.Now().UTC())

	outputPath := filepath.Join(artifacts, "verdict.json")
	var stdout, stderr bytes.Buffer
	args := []string{"verdict", "--config", configPath, "--run-id", runID, "--artifacts", artifacts, "--out", outputPath}
	if exitCode := run(args, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read verdict: %v", err)
	}
	var report verdict.Report
	if err := json.Unmarshal(contents, &report); err != nil {
		t.Fatalf("decode verdict: %v", err)
	}
	if report.Status != verdict.StatusPass || report.RunID != runID || len(report.ConfigDigest) != 64 {
		t.Fatalf("report = %#v", report)
	}

	stdout.Reset()
	stderr.Reset()
	if exitCode := run(args, &stdout, &stderr); exitCode != 1 || !strings.HasPrefix(stderr.String(), "VERDICT_OUTPUT_ERROR:") {
		t.Fatalf("second run exit = %d stderr = %q", exitCode, stderr.String())
	}
}

func TestRunVerdictStrictlyRejectsUnknownArtifactFields(t *testing.T) {
	artifacts := t.TempDir()
	configPath, cfg := writeVerdictConfig(t)
	runID := "run-verdict-unknown"
	writePassingVerdictArtifacts(t, artifacts, cfg, runID, time.Now().UTC())

	path := filepath.Join(artifacts, "inventory-after.json")
	var object map[string]any
	contents, _ := os.ReadFile(path)
	if err := json.Unmarshal(contents, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	writeTestJSONReplace(t, path, object)

	report := runVerdictForTest(t, configPath, runID, artifacts)
	if report.Status != verdict.StatusInconclusive || report.Code != "INCONCLUSIVE_INVALID_EVIDENCE" {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunVerdictRejectsOmittedRequiredInventoryCollectionsAndFirewallFilters(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "nat", mutate: func(object map[string]any) {
			state := object["state"].(map[string]any)
			delete(state, "nat")
		}},
		{name: "firewall filter", mutate: func(object map[string]any) {
			state := object["state"].(map[string]any)
			rule := state["firewall_rules"].([]any)[0].(map[string]any)
			delete(rule, "remote_addresses")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := t.TempDir()
			configPath, cfg := writeVerdictConfig(t)
			runID := "run-omitted-" + strings.ReplaceAll(test.name, " ", "-")
			writePassingVerdictArtifacts(t, artifacts, cfg, runID, time.Now().UTC())

			path := filepath.Join(artifacts, "inventory-after.json")
			var object map[string]any
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(contents, &object); err != nil {
				t.Fatal(err)
			}
			test.mutate(object)
			writeTestJSONReplace(t, path, object)

			report := runVerdictForTest(t, configPath, runID, artifacts)
			if report.Status != verdict.StatusInconclusive || report.Code != "INCONCLUSIVE_INVALID_EVIDENCE" {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestRunVerdictKeepsValidLeakWhenSiblingJSONRecordIsUnknown(t *testing.T) {
	artifacts := t.TempDir()
	configPath, cfg := writeVerdictConfig(t)
	runID := "run-verdict-leak"
	now := time.Now().UTC()
	writePassingVerdictArtifacts(t, artifacts, cfg, runID, now)
	digest, _ := config.Digest(cfg)
	leak := probe.Result{
		TargetName: cfg.ApprovedTargets[0].Name, TargetURL: cfg.ApprovedTargets[0].URL,
		ResolvedIPs: []string{"192.0.2.10"}, SelectedIP: "192.0.2.10", TCPLatency: time.Millisecond,
		TLSStatus: "failed", StartedAt: now.Add(-26 * time.Minute), FinishedAt: now.Add(-25 * time.Minute), ErrorCode: "tls_failed",
	}
	leakJSON, _ := json.Marshal(leak)
	raw := struct {
		SchemaVersion int               `json:"schema_version"`
		RunID         string            `json:"run_id"`
		ConfigDigest  string            `json:"config_digest"`
		StartedAt     time.Time         `json:"started_at"`
		FinishedAt    time.Time         `json:"finished_at"`
		Results       []json.RawMessage `json:"results"`
	}{1, runID, digest, now.Add(-26 * time.Minute), now.Add(-25 * time.Minute), []json.RawMessage{leakJSON, json.RawMessage(`{"unexpected":true}`)}}
	writeTestJSONReplace(t, filepath.Join(artifacts, "probe-telecom-down.json"), raw)

	report := runVerdictForTest(t, configPath, runID, artifacts)
	if report.Status != verdict.StatusFail || report.Code != "FAIL_LEAK" {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunDescribeConfigReturnsStrictMonitorInputs(t *testing.T) {
	configPath, cfg := writeVerdictConfig(t)
	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"describe-config", "--config", configPath}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run exit = %d stderr = %q", exitCode, stderr.String())
	}
	var got struct {
		TelecomInterface     string   `json:"telecom_interface"`
		TelecomRoutePrefixes []string `json:"telecom_route_prefixes"`
		ConfigDigest         string   `json:"config_digest"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if got.TelecomInterface != cfg.TelecomInterface || len(got.TelecomRoutePrefixes) != 1 || got.TelecomRoutePrefixes[0] != "0.0.0.0/0" || len(got.ConfigDigest) != 64 {
		t.Fatalf("metadata = %#v", got)
	}
}

func runVerdictForTest(t *testing.T, configPath, runID, artifacts string) verdict.Report {
	t.Helper()
	output := filepath.Join(artifacts, "verdict-"+runID+".json")
	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"verdict", "--config", configPath, "--run-id", runID, "--artifacts", artifacts, "--out", output}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run exit = %d stderr = %q", exitCode, stderr.String())
	}
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report verdict.Report
	if err := json.Unmarshal(contents, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func writeVerdictConfig(t *testing.T) (string, config.Config) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "poc.yaml")
	contents := `wireguard_subnet: 100.127.77.0/24
wireguard_interface: wg-overseas-poc
telecom_interface: Telecom-Client
telecom_route_prefixes:
  - 0.0.0.0/0
employee_interface: Ethernet
internal_cidrs:
  - 10.0.0.0/8
approved_targets:
  - name: operator-approved-test
    url: https://approved.example.invalid/health
probe_timeout: 8s
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

func writePassingVerdictArtifacts(t *testing.T, dir string, cfg config.Config, runID string, now time.Time) {
	t.Helper()
	digest, _ := config.Digest(cfg)
	state := inventory.State{
		Interfaces: []inventory.Interface{
			{Alias: cfg.EmployeeInterface, Index: 7, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1500},
			{Alias: cfg.TelecomInterface, Index: 11, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1400},
			{Alias: cfg.WireGuardInterface, Index: 19, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1420},
		},
		Routes: []inventory.Route{
			{Alias: cfg.EmployeeInterface, Index: 7, DestinationPrefix: "0.0.0.0/0", NextHop: "172.20.10.1", Metric: 25, State: "Alive"},
			{Alias: cfg.WireGuardInterface, Index: 19, DestinationPrefix: cfg.WireGuardSubnet, NextHop: "0.0.0.0", State: "Alive"},
		},
		NAT:           []inventory.NAT{},
		FirewallRules: []inventory.FirewallRule{completeFirewallRuleForTest()},
	}
	writeTestJSON(t, filepath.Join(dir, "inventory-before.json"), inventory.Artifact{SchemaVersion: 1, RunID: runID, ConfigDigest: digest, CapturedAt: now.Add(-30 * time.Minute), State: state})
	writeTestJSON(t, filepath.Join(dir, "probe-telecom-up.json"), probe.Artifact{
		SchemaVersion: 1, RunID: runID, ConfigDigest: digest, StartedAt: now.Add(-29 * time.Minute), FinishedAt: now.Add(-28 * time.Minute),
		Results: []probe.Result{{TargetName: cfg.ApprovedTargets[0].Name, TargetURL: cfg.ApprovedTargets[0].URL, ResolvedIPs: []string{"192.0.2.10"}, SelectedIP: "192.0.2.10", TCPLatency: time.Millisecond, TLSStatus: "validated", HTTPStatus: http.StatusNoContent, StartedAt: now.Add(-29 * time.Minute), FinishedAt: now.Add(-28 * time.Minute)}},
	})
	writeTestJSON(t, filepath.Join(dir, "probe-telecom-down.json"), probe.Artifact{
		SchemaVersion: 1, RunID: runID, ConfigDigest: digest, StartedAt: now.Add(-26 * time.Minute), FinishedAt: now.Add(-25 * time.Minute),
		Results: []probe.Result{{TargetName: cfg.ApprovedTargets[0].Name, TargetURL: cfg.ApprovedTargets[0].URL, ResolvedIPs: []string{"192.0.2.10"}, SelectedIP: "192.0.2.10", TLSStatus: "not_attempted", StartedAt: now.Add(-26 * time.Minute), FinishedAt: now.Add(-25 * time.Minute), ErrorCode: "tcp_failed"}},
	})
	writeTestJSON(t, filepath.Join(dir, "probe-telecom-down-monitor.json"), verdict.DownMonitorEvidence{SchemaVersion: 1, RunID: runID, ConfigDigest: digest, StartedAt: now.Add(-27 * time.Minute), FinishedAt: now.Add(-24 * time.Minute), SampleCount: 3, TelecomRoutePrefixes: cfg.TelecomRoutePrefixes})
	writeTestJSON(t, filepath.Join(dir, "inventory-after.json"), inventory.Artifact{SchemaVersion: 1, RunID: runID, ConfigDigest: digest, CapturedAt: now.Add(-23 * time.Minute), State: state})
}

func completeFirewallRuleForTest() inventory.FirewallRule {
	return inventory.FirewallRule{
		Name: "Baseline", DisplayName: "Baseline", Description: "", Group: "", Enabled: "True", Profile: "Any", Direction: "Outbound", Action: "Allow",
		EdgeTraversalPolicy: "Block", LooseSourceMapping: false, LocalOnlyMapping: false, Owner: "", PolicyStoreSource: "PersistentStore", PolicyStoreSourceType: "Local",
		Platforms: []string{}, InterfaceAliases: []string{}, InterfaceTypes: []string{}, LocalAddresses: []string{"Any"}, RemoteAddresses: []string{"Internet"}, RemoteDynamicKeywordAddresses: []string{},
		Protocols: []string{"TCP"}, LocalPorts: []string{"Any"}, RemotePorts: []string{"443"}, IcmpTypes: []string{}, DynamicTargets: []string{},
		Programs: []string{}, Packages: []string{}, Services: []string{}, Authentications: []string{}, Encryptions: []string{}, OverrideBlockRules: []bool{}, LocalUsers: []string{}, RemoteUsers: []string{}, RemoteMachines: []string{},
	}
}

func writeTestJSONReplace(t *testing.T, path string, value any) {
	t.Helper()
	contents, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	contents, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
