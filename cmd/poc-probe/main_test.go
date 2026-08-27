package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"corp.example/overseas-access-gateway/internal/inventory"
)

func TestRunPreflightPrintsSuccessForValidConfiguration(t *testing.T) {
	path := t.TempDir() + "/poc.yaml"
	configContents := `wireguard_subnet: 100.127.77.0/24
wireguard_interface: wg-overseas-poc
telecom_interface: Telecom-Client
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
				{Alias: "Ethernet", Index: 7},
				{Alias: "Telecom-Client", Index: 11},
				{Alias: "wg-overseas-poc", Index: 19},
			},
			Routes: []inventory.Route{
				{Alias: "Ethernet", Index: 7, DestinationPrefix: "0.0.0.0/0", State: "Alive"},
				{Alias: "wg-overseas-poc", Index: 19, DestinationPrefix: "100.127.77.0/24", State: "Alive"},
			},
		}, nil
	}
	t.Cleanup(func() { snapshot = previousSnapshot })

	outputPath := t.TempDir() + "/inventory-before.json"
	var stdout, stderr bytes.Buffer
	args := []string{"inventory", "--config", configPath, "--out", outputPath}
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
	var state inventory.State
	if err := json.Unmarshal(evidenceContents, &state); err != nil {
		t.Fatalf("decode written evidence: %v", err)
	}
	if len(state.Interfaces) != 3 {
		t.Fatalf("written state has %d interfaces, want 3", len(state.Interfaces))
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
