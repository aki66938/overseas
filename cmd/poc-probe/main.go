package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"corp.example/overseas-access-gateway/internal/config"
	"corp.example/overseas-access-gateway/internal/inventory"
	"corp.example/overseas-access-gateway/internal/probe"
	"corp.example/overseas-access-gateway/internal/verdict"
)

var snapshot = inventory.Snapshot

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "PREFLIGHT_USAGE: poc-probe preflight --config <path>")
		return 2
	}

	switch args[0] {
	case "preflight":
		return runPreflight(args[1:], stdout, stderr)
	case "inventory":
		return runInventory(args[1:], stdout, stderr)
	case "probe":
		return runProbe(args[1:], stdout, stderr)
	case "verdict":
		return runVerdict(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "PREFLIGHT_USAGE: poc-probe preflight --config <path>")
		return 2
	}
}

func runVerdict(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verdict", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifactsPath := flags.String("artifacts", "", "directory containing the four fixed evidence files")
	outputPath := flags.String("out", "", "path for a new JSON verdict report")
	if err := flags.Parse(args); err != nil || *artifactsPath == "" || *outputPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "VERDICT_USAGE: poc-probe verdict --artifacts <directory> --out <path>")
		return 2
	}

	evidence := loadVerdictEvidence(*artifactsPath)
	report := verdict.Evaluate(evidence)
	if err := writeNewJSON(*outputPath, report); err != nil {
		fmt.Fprintf(stderr, "VERDICT_OUTPUT_ERROR: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "VERDICT_WRITTEN: %s %s\n", report.Status, report.Code)
	return 0
}

func loadVerdictEvidence(artifactsPath string) verdict.Evidence {
	var evidence verdict.Evidence

	var before inventory.State
	if err := readJSON(filepath.Join(artifactsPath, "inventory-before.json"), &before); err == nil {
		evidence.InventoryBefore = &before
	}

	var up []probe.Result
	if err := readJSON(filepath.Join(artifactsPath, "probe-telecom-up.json"), &up); err == nil {
		evidence.TelecomUp = normalizeProbeEvidence(up)
	}

	var down []probe.Result
	if err := readJSON(filepath.Join(artifactsPath, "probe-telecom-down.json"), &down); err == nil {
		evidence.TelecomDown = normalizeProbeEvidence(down)
	}

	var after inventory.State
	if err := readJSON(filepath.Join(artifactsPath, "inventory-after.json"), &after); err == nil {
		evidence.InventoryAfter = &after
	}

	return evidence
}

func normalizeProbeEvidence(results []probe.Result) *verdict.ProbeEvidence {
	normalized := &verdict.ProbeEvidence{Results: make([]verdict.ProbeResult, 0, len(results))}
	for _, result := range results {
		if !validProbeRecord(result) {
			return &verdict.ProbeEvidence{}
		}
		normalized.Results = append(normalized.Results, verdict.ProbeResult{
			TargetName: result.TargetName,
			Success:    successfulHTTPS(result),
		})
	}
	return normalized
}

func validProbeRecord(result probe.Result) bool {
	if strings.TrimSpace(result.TargetName) == "" || result.StartedAt.IsZero() || result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		return false
	}
	if result.ErrorCode == "" {
		return successfulHTTPS(result)
	}
	switch result.ErrorCode {
	case "dns_failed", "tcp_failed", "tls_failed", "http_rejected", "context_deadline":
		return true
	default:
		return false
	}
}

func successfulHTTPS(result probe.Result) bool {
	if result.ErrorCode != "" || result.TLSStatus != "validated" || result.HTTPStatus < 200 || result.HTTPStatus >= 300 {
		return false
	}
	selected := net.ParseIP(result.SelectedIP)
	if selected == nil {
		return false
	}
	for _, resolved := range result.ResolvedIPs {
		if candidate := net.ParseIP(resolved); candidate != nil && candidate.Equal(selected) {
			return true
		}
	}
	return false
}

func readJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
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
	outputPath := flags.String("out", "", "path for new JSON evidence")
	sourceText := flags.String("source-ip", "", "optional source IP address")
	if err := flags.Parse(args); err != nil || *configPath == "" || *outputPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "PROBE_USAGE: poc-probe probe --config <path> --out <path> [--source-ip <ip>]")
		return 2
	}

	cfg, err := config.Load(*configPath)
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

	results := make([]probe.Result, 0, len(cfg.ApprovedTargets))
	for _, target := range cfg.ApprovedTargets {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ProbeTimeout)
		result := probe.Run(ctx, target, source)
		cancel()
		results = append(results, result)
	}
	if err := writeNewJSON(*outputPath, results); err != nil {
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

func runInventory(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to PoC configuration")
	outputPath := flags.String("out", "", "path for new JSON evidence")
	if err := flags.Parse(args); err != nil || *configPath == "" || *outputPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "INVENTORY_USAGE: poc-probe inventory --config <path> --out <path>")
		return 2
	}

	cfg, err := config.Load(*configPath)
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
	if err := writeNewJSON(*outputPath, state); err != nil {
		fmt.Fprintf(stderr, "INVENTORY_OUTPUT_ERROR: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "INVENTORY_OK")
	return 0
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
