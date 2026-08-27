package config

import (
	"os"
	"regexp"
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
telecom_route_prefixes:
  - 0.0.0.0/0
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
telecom_route_prefixes:
  - 0.0.0.0/0
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
		{"telecom route prefixes", func(cfg *Config) { cfg.TelecomRoutePrefixes = nil }},
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

func TestValidateRejectsInvalidOrDuplicateTelecomRoutePrefixes(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
	}{
		{name: "non IPv4", prefixes: []string{"2001:db8::/32"}},
		{name: "not a prefix", prefixes: []string{"not-a-prefix"}},
		{name: "private route is not external", prefixes: []string{"10.0.0.0/8"}},
		{name: "duplicate", prefixes: []string{"0.0.0.0/0", "0.0.0.0/0"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.TelecomRoutePrefixes = test.prefixes
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "telecom_route_prefixes") {
				t.Fatalf("Validate() error = %v, want telecom_route_prefixes rejection", err)
			}
		})
	}
}

func TestDigestIsStableAndCoversExactApprovedTargetURL(t *testing.T) {
	first := validConfig()
	second := validConfig()

	firstDigest, err := Digest(first)
	if err != nil {
		t.Fatalf("Digest(first) error: %v", err)
	}
	secondDigest, err := Digest(second)
	if err != nil {
		t.Fatalf("Digest(second) error: %v", err)
	}
	if firstDigest != secondDigest || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(firstDigest) {
		t.Fatalf("digests = %q and %q, want the same lowercase SHA-256", firstDigest, secondDigest)
	}

	second.ApprovedTargets[0].URL = "https://approved-test.example.invalid/different"
	changedDigest, err := Digest(second)
	if err != nil {
		t.Fatalf("Digest(changed) error: %v", err)
	}
	if changedDigest == firstDigest {
		t.Fatal("configuration digest did not cover the exact approved target URL")
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

func TestValidateRejectsTargetNameWithSurroundingWhitespace(t *testing.T) {
	cfg := validConfig()
	cfg.ApprovedTargets[0].Name = " operator-approved-test "

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected a target name with surrounding whitespace to be rejected")
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
		TelecomRoutePrefixes: []string{
			"0.0.0.0/0",
		},
		EmployeeInterface: "Ethernet",
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
