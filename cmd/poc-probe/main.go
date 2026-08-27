package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"corp.example/overseas-access-gateway/internal/config"
	"corp.example/overseas-access-gateway/internal/inventory"
	"corp.example/overseas-access-gateway/internal/probe"
	"corp.example/overseas-access-gateway/internal/verdict"
)

var snapshot = inventory.Snapshot

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "USAGE: poc-probe <preflight|describe-config|inventory|probe|verdict> [options]")
		return 2
	}
	switch args[0] {
	case "preflight":
		return runPreflight(args[1:], stdout, stderr)
	case "describe-config":
		return runDescribeConfig(args[1:], stdout, stderr)
	case "inventory":
		return runInventory(args[1:], stdout, stderr)
	case "probe":
		return runProbe(args[1:], stdout, stderr)
	case "verdict":
		return runVerdict(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "USAGE: poc-probe <preflight|describe-config|inventory|probe|verdict> [options]")
		return 2
	}
}

func runVerdict(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verdict", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "validated PoC configuration")
	runID := flags.String("run-id", "", "evidence run identifier")
	artifactsPath := flags.String("artifacts", "", "directory containing fixed evidence files")
	outputPath := flags.String("out", "", "path for a new JSON verdict report")
	if err := flags.Parse(args); err != nil || *configPath == "" || !validRunID(*runID) || *artifactsPath == "" || *outputPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "VERDICT_USAGE: poc-probe verdict --config <path> --run-id <id> --artifacts <directory> --out <path>")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "VERDICT_CONFIG_ERROR: %v\n", err)
		return 1
	}

	evidence := loadVerdictEvidence(*artifactsPath, cfg, *runID, time.Now().UTC())
	report := verdict.Evaluate(evidence)
	if err := writeNewJSON(*outputPath, report); err != nil {
		fmt.Fprintf(stderr, "VERDICT_OUTPUT_ERROR: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "VERDICT_WRITTEN: %s %s\n", report.Status, report.Code)
	return 0
}

func loadVerdictEvidence(artifactsPath string, cfg config.Config, runID string, evaluatedAt time.Time) verdict.Evidence {
	evidence := verdict.Evidence{RunID: runID, Config: &cfg, EvaluatedAt: evaluatedAt}

	var before inventory.Artifact
	if err := readStrictJSON(filepath.Join(artifactsPath, "inventory-before.json"), &before); err != nil {
		evidence.ArtifactErrors = append(evidence.ArtifactErrors, "inventory-before.json: "+err.Error())
	} else {
		evidence.InventoryBefore = &before
	}
	if up, err := readProbeEvidence(filepath.Join(artifactsPath, "probe-telecom-up.json")); err != nil {
		evidence.ArtifactErrors = append(evidence.ArtifactErrors, "probe-telecom-up.json: "+err.Error())
	} else {
		evidence.TelecomUp = up
	}
	if down, err := readProbeEvidence(filepath.Join(artifactsPath, "probe-telecom-down.json")); err != nil {
		evidence.ArtifactErrors = append(evidence.ArtifactErrors, "probe-telecom-down.json: "+err.Error())
	} else {
		evidence.TelecomDown = down
	}
	var monitor verdict.DownMonitorEvidence
	if err := readStrictJSON(filepath.Join(artifactsPath, "probe-telecom-down-monitor.json"), &monitor); err != nil {
		evidence.ArtifactErrors = append(evidence.ArtifactErrors, "probe-telecom-down-monitor.json: "+err.Error())
	} else {
		evidence.DownMonitor = &monitor
	}
	var after inventory.Artifact
	if err := readStrictJSON(filepath.Join(artifactsPath, "inventory-after.json"), &after); err != nil {
		evidence.ArtifactErrors = append(evidence.ArtifactErrors, "inventory-after.json: "+err.Error())
	} else {
		evidence.InventoryAfter = &after
	}
	return evidence
}

type rawProbeArtifact struct {
	SchemaVersion int               `json:"schema_version"`
	RunID         string            `json:"run_id"`
	ConfigDigest  string            `json:"config_digest"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Results       []json.RawMessage `json:"results"`
}

func readProbeEvidence(path string) (*verdict.ProbeEvidence, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw rawProbeArtifact
	if err := decodeStrictJSON(contents, &raw); err != nil {
		return nil, err
	}
	normalized := &verdict.ProbeEvidence{
		SchemaVersion: raw.SchemaVersion,
		RunID:         raw.RunID,
		ConfigDigest:  raw.ConfigDigest,
		StartedAt:     raw.StartedAt,
		FinishedAt:    raw.FinishedAt,
		Results:       make([]verdict.ProbeResult, 0, len(raw.Results)),
	}
	for _, record := range raw.Results {
		var result probe.Result
		if err := decodeStrictJSON(record, &result); err != nil {
			normalized.InvalidRecords++
			continue
		}
		converted, ok := normalizeProbeResult(result)
		if !ok {
			normalized.InvalidRecords++
			continue
		}
		normalized.Results = append(normalized.Results, converted)
	}
	return normalized, nil
}

func normalizeProbeResult(result probe.Result) (verdict.ProbeResult, bool) {
	normalized := verdict.ProbeResult{
		TargetName: result.TargetName,
		TargetURL:  result.TargetURL,
		StartedAt:  result.StartedAt,
		FinishedAt: result.FinishedAt,
	}
	parsedURL, urlErr := url.Parse(result.TargetURL)
	if strings.TrimSpace(result.TargetName) != result.TargetName || result.TargetName == "" || urlErr != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" ||
		result.StartedAt.IsZero() || result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || result.TCPLatency < 0 || result.Bytes < 0 {
		return verdict.ProbeResult{}, false
	}
	httpObserved := result.HTTPStatus >= 100 && result.HTTPStatus <= 599
	if result.HTTPStatus != 0 && !httpObserved {
		return verdict.ProbeResult{}, false
	}
	networkIdentity := validSelectedIP(result.ResolvedIPs, result.SelectedIP)
	noNetworkFields := len(result.ResolvedIPs) == 0 && result.SelectedIP == "" && result.TCPLatency == 0 && result.TLSStatus == "not_attempted" && result.HTTPStatus == 0 && result.Bytes == 0
	preTLSFailure := networkIdentity && result.TCPLatency == 0 && result.TLSStatus == "not_attempted" && result.HTTPStatus == 0 && result.Bytes == 0
	tcpObserved := networkIdentity && result.TCPLatency > 0
	tlsFailed := tcpObserved && result.TLSStatus == "failed" && result.HTTPStatus == 0 && result.Bytes == 0
	tlsValidated := tcpObserved && result.TLSStatus == "validated"
	if httpObserved && !tlsValidated {
		return verdict.ProbeResult{}, false
	}

	switch result.ErrorCode {
	case "":
		if !tlsValidated || result.HTTPStatus < 200 || result.HTTPStatus >= 300 {
			return verdict.ProbeResult{}, false
		}
		normalized.Reachable = true
		normalized.Healthy = true
	case "dns_failed":
		if !noNetworkFields {
			return verdict.ProbeResult{}, false
		}
	case "tcp_failed":
		if !preTLSFailure {
			return verdict.ProbeResult{}, false
		}
	case "tls_failed":
		if !tlsFailed {
			return verdict.ProbeResult{}, false
		}
		normalized.Reachable = true
	case "http_rejected":
		if !tlsValidated || !httpObserved || (result.HTTPStatus >= 200 && result.HTTPStatus < 300) {
			return verdict.ProbeResult{}, false
		}
		normalized.Reachable = true
	case "body_failed":
		if !tlsValidated || !httpObserved {
			return verdict.ProbeResult{}, false
		}
		normalized.Reachable = true
	case "context_deadline":
		switch {
		case noNetworkFields, preTLSFailure:
		case tcpObserved && result.TLSStatus == "not_attempted" && result.HTTPStatus == 0 && result.Bytes == 0:
			normalized.Reachable = true
		case tlsFailed:
			normalized.Reachable = true
		case tlsValidated && (result.HTTPStatus == 0 || httpObserved):
			normalized.Reachable = true
		default:
			return verdict.ProbeResult{}, false
		}
	default:
		return verdict.ProbeResult{}, false
	}
	return normalized, true
}

func validSelectedIP(resolved []string, selected string) bool {
	selectedIP := net.ParseIP(selected)
	if selectedIP == nil || len(resolved) == 0 {
		return false
	}
	found := false
	seen := make(map[string]struct{}, len(resolved))
	for _, value := range resolved {
		candidate := net.ParseIP(value)
		if candidate == nil {
			return false
		}
		canonical := candidate.String()
		if _, exists := seen[canonical]; exists {
			return false
		}
		seen[canonical] = struct{}{}
		if candidate.Equal(selectedIP) {
			found = true
		}
	}
	return found
}

func readStrictJSON(path string, destination any) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return decodeStrictJSON(contents, destination)
}

func decodeStrictJSON(contents []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var additional any
	if err := decoder.Decode(&additional); err != io.EOF {
		return fmt.Errorf("evidence must contain exactly one JSON value")
	}
	return nil
}

func runProbe(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to PoC configuration")
	runID := flags.String("run-id", "", "evidence run identifier")
	outputPath := flags.String("out", "", "path for new JSON evidence")
	sourceText := flags.String("source-ip", "", "optional source IP address")
	if err := flags.Parse(args); err != nil || *configPath == "" || !validRunID(*runID) || *outputPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "PROBE_USAGE: poc-probe probe --config <path> --run-id <id> --out <path> [--source-ip <ip>]")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "PROBE_CONFIG_ERROR: %v\n", err)
		return 1
	}
	digest, err := config.Digest(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "PROBE_CONFIG_ERROR: %v\n", err)
		return 1
	}

	var source net.IP
	if *sourceText != "" {
		source = net.ParseIP(*sourceText)
		if source == nil {
			fmt.Fprintln(stderr, "PROBE_SOURCE_ERROR: source-ip must be a valid IP address")
			return 1
		}
	}
	artifact := probe.Artifact{SchemaVersion: verdict.EvidenceSchemaVersion, RunID: *runID, ConfigDigest: digest, StartedAt: time.Now().UTC()}
	artifact.Results = make([]probe.Result, 0, len(cfg.ApprovedTargets))
	for _, target := range cfg.ApprovedTargets {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ProbeTimeout)
		result := probe.Run(ctx, target, source)
		cancel()
		artifact.Results = append(artifact.Results, result)
	}
	artifact.FinishedAt = time.Now().UTC()
	if err := writeNewJSON(*outputPath, artifact); err != nil {
		fmt.Fprintf(stderr, "PROBE_OUTPUT_ERROR: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PROBE_EVIDENCE_WRITTEN")
	return 0
}

func runPreflight(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to PoC configuration")
	if err := flags.Parse(args); err != nil || *configPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "PREFLIGHT_USAGE: poc-probe preflight --config <path>")
		return 2
	}
	if _, err := config.Load(*configPath); err != nil {
		fmt.Fprintf(stderr, "PREFLIGHT_CONFIG_ERROR: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PREFLIGHT_CONFIG_OK")
	return 0
}

func runDescribeConfig(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("describe-config", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to PoC configuration")
	if err := flags.Parse(args); err != nil || *configPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "DESCRIBE_CONFIG_USAGE: poc-probe describe-config --config <path>")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "DESCRIBE_CONFIG_ERROR: %v\n", err)
		return 1
	}
	digest, err := config.Digest(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "DESCRIBE_CONFIG_ERROR: %v\n", err)
		return 1
	}
	metadata := struct {
		TelecomInterface     string   `json:"telecom_interface"`
		TelecomRoutePrefixes []string `json:"telecom_route_prefixes"`
		ConfigDigest         string   `json:"config_digest"`
	}{cfg.TelecomInterface, cfg.TelecomRoutePrefixes, digest}
	if err := json.NewEncoder(stdout).Encode(metadata); err != nil {
		fmt.Fprintf(stderr, "DESCRIBE_CONFIG_OUTPUT_ERROR: %v\n", err)
		return 1
	}
	return 0
}

func runInventory(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to PoC configuration")
	runID := flags.String("run-id", "", "evidence run identifier")
	outputPath := flags.String("out", "", "path for new JSON evidence")
	if err := flags.Parse(args); err != nil || *configPath == "" || !validRunID(*runID) || *outputPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "INVENTORY_USAGE: poc-probe inventory --config <path> --run-id <id> --out <path>")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "INVENTORY_CONFIG_ERROR: %v\n", err)
		return 1
	}
	digest, err := config.Digest(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "INVENTORY_CONFIG_ERROR: %v\n", err)
		return 1
	}
	state, err := snapshot(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "INVENTORY_SNAPSHOT_ERROR: %v\n", err)
		return 1
	}
	if err := inventory.Validate(state, cfg); err != nil {
		fmt.Fprintf(stderr, "INVENTORY_VALIDATION_ERROR: %v\n", err)
		return 1
	}
	artifact := inventory.Artifact{SchemaVersion: verdict.EvidenceSchemaVersion, RunID: *runID, ConfigDigest: digest, CapturedAt: time.Now().UTC(), State: state}
	if err := writeNewJSON(*outputPath, artifact); err != nil {
		fmt.Fprintf(stderr, "INVENTORY_OUTPUT_ERROR: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "INVENTORY_OK")
	return 0
}

func validRunID(value string) bool {
	return runIDPattern.MatchString(value)
}

func writeNewJSON(path string, value any) error {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	contents = append(contents, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create evidence file: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write evidence file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close evidence file: %w", err)
	}
	return nil
}
