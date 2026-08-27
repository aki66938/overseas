package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateAcceptsValidConfiguration(t *testing.T) {
	cfg := validConfig()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned an error for valid configuration: %v", err)
	}
}

func TestLoadDecodesValidConfiguration(t *testing.T) {
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

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() returned an error: %v", err)
	}
	if cfg.ProbeTimeout != 8*time.Second {
		t.Fatalf("ProbeTimeout = %s, want 8s", cfg.ProbeTimeout)
	}
}

func TestLoadRejectsUnknownYAMLField(t *testing.T) {
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
unexpected_setting: true
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected an unknown YAML field to be rejected")
	} else if !strings.Contains(err.Error(), "unexpected_setting") {
		t.Fatalf("expected error to name the unknown field, got %q", err)
	}
}

func TestLoadRejectsTrailingYAMLDocument(t *testing.T) {
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
---
unexpected_setting: true
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected trailing YAML document to be rejected")
	}
}

func TestValidateRejectsEmptyInterfaceNames(t *testing.T) {
	tests := []struct {
		name  string
		field string
		clear func(*Config)
	}{
		{"WireGuard", "wireguard_interface", func(cfg *Config) { cfg.WireGuardInterface = "" }},
		{"telecom", "telecom_interface", func(cfg *Config) { cfg.TelecomInterface = "" }},
		{"employee", "employee_interface", func(cfg *Config) { cfg.EmployeeInterface = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.clear(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected an error for empty %s", tt.field)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("expected error to name %q, got %q", tt.field, err)
			}
		})
	}
}

func TestValidateRejectsOverlappingCIDRs(t *testing.T) {
	cfg := validConfig()
	cfg.WireGuardSubnet = "10.77.0.0/24"
	cfg.InternalCIDRs = []string{"10.0.0.0/8"}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected overlapping CIDRs to be rejected")
	}
}

func TestValidateRejectsEmptyRequiredLists(t *testing.T) {
	tests := []struct {
		name  string
		clear func(*Config)
	}{
		{"internal CIDRs", func(cfg *Config) { cfg.InternalCIDRs = nil }},
		{"approved targets", func(cfg *Config) { cfg.ApprovedTargets = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.clear(&cfg)

			if err := cfg.Validate(); err == nil {
				t.Fatal("expected empty required list to be rejected")
			}
		})
	}
}

func TestValidateRejectsHTTPProbeTarget(t *testing.T) {
	cfg := validConfig()
	cfg.ApprovedTargets = []Target{{Name: "bad", URL: "http://example.com/"}}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-HTTPS target to be rejected")
	}
}

func TestValidateRejectsDuplicateTargetNames(t *testing.T) {
	cfg := validConfig()
	cfg.ApprovedTargets = []Target{
		{Name: "operator-approved-test", URL: "https://approved-test.example.invalid/one"},
		{Name: "operator-approved-test", URL: "https://approved-test.example.invalid/two"},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected duplicate target names to be rejected")
	}
}

func TestValidateRejectsEmptyTargetName(t *testing.T) {
	cfg := validConfig()
	cfg.ApprovedTargets[0].Name = ""

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an empty target name to be rejected")
	}
}

func TestValidateRejectsTimeoutOutsideAllowedRange(t *testing.T) {
	for _, timeout := range []time.Duration{0, 31 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			cfg := validConfig()
			cfg.ProbeTimeout = timeout

			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected timeout %s to be rejected", timeout)
			}
		})
	}
}

func validConfig() Config {
	return Config{
		WireGuardSubnet:    "100.127.77.0/24",
		WireGuardInterface: "wg-overseas-poc",
		TelecomInterface:   "Telecom-Client",
		EmployeeInterface:  "Ethernet",
		InternalCIDRs: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		ApprovedTargets: []Target{{
			Name: "operator-approved-test",
			URL:  "https://approved-test.example.invalid/",
		}},
		ProbeTimeout: 8 * time.Second,
	}
}
