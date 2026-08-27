package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunPreflightPrintsSuccessForValidConfiguration(t *testing.T) {
	path := t.TempDir() + "/poc.yaml"
	contents := `wireguard_subnet: 100.127.77.0/24
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
