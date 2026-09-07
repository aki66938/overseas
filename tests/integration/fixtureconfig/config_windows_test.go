//go:build windows

package fixtureconfig

import (
	"strings"
	"testing"
	"time"
)

func TestServerAttestationBindsRemoteServiceCoreConfigAndListener(t *testing.T) {
	manifest := validWindowsManifest()
	now := time.Date(2026, 8, 31, 9, 5, 0, 0, time.UTC)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	attestation := ServerAttestation{
		SchemaVersion:       1,
		HostIdentity:        "DESKTOP-1BVR2H6",
		HostKeyFingerprint:  fingerprint,
		RunNonce:            "20260831T090000Z-4d41c0de",
		ObservedAt:          "2026-08-31T09:00:00Z",
		ListenerEndpoint:    "172.20.9.15:18443",
		ServiceName:         "RegenBioOverseasAccessServer",
		ServicePath:         `C:\Program Files\RegenBio\OverseasAccessServer\overseas-server-service.exe`,
		ServiceSHA256:       manifest.Artifacts["server-service"].SHA256,
		ServicePID:          51,
		CorePath:            `C:\Program Files\RegenBio\OverseasAccessServer\sing-box.exe`,
		CoreSHA256:          manifest.Artifacts["core"].SHA256,
		CorePID:             52,
		CoreParentPID:       51,
		ConfigPath:          `C:\ProgramData\RegenBio\OverseasAccessServer\config.json`,
		ConfigSHA256:        strings.Repeat("a", 64),
		ListenerPID:         52,
		ListenerImagePath:   `C:\Program Files\RegenBio\OverseasAccessServer\sing-box.exe`,
		ListenerImageSHA256: manifest.Artifacts["core"].SHA256,
	}
	if err := attestation.ValidateAt(manifest, "172.20.9.15:18443", strings.Repeat("a", 64), fingerprint, "20260831T090000Z-4d41c0de", now); err != nil {
		t.Fatalf("Validate()=%v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*ServerAttestation)
		want string
	}{
		{name: "listener", edit: func(v *ServerAttestation) { v.ListenerEndpoint = "172.20.9.15:9443" }, want: "listener"},
		{name: "host key", edit: func(v *ServerAttestation) { v.HostKeyFingerprint = "SHA256:other" }, want: "host key"},
		{name: "host identity", edit: func(v *ServerAttestation) { v.HostIdentity = "OTHER" }, want: "host identity"},
		{name: "run nonce", edit: func(v *ServerAttestation) { v.RunNonce = "other-run" }, want: "run nonce"},
		{name: "stale", edit: func(v *ServerAttestation) { v.ObservedAt = now.Add(-25 * time.Hour).Format(time.RFC3339) }, want: "fresh"},
		{name: "future", edit: func(v *ServerAttestation) { v.ObservedAt = now.Add(6 * time.Minute).Format(time.RFC3339) }, want: "future"},
		{name: "service path", edit: func(v *ServerAttestation) { v.ServicePath = `C:\Program Files\RegenBio\other.exe` }, want: "service path"},
		{name: "core path", edit: func(v *ServerAttestation) { v.CorePath = `C:\Program Files\RegenBio\other.exe` }, want: "core path"},
		{name: "config path", edit: func(v *ServerAttestation) { v.ConfigPath = `C:\ProgramData\RegenBio\other.json` }, want: "config path"},
		{name: "listener path", edit: func(v *ServerAttestation) { v.ListenerImagePath = `C:\Program Files\RegenBio\other.exe` }, want: "listener image path"},
		{name: "core parent", edit: func(v *ServerAttestation) { v.CoreParentPID = 99 }, want: "parent"},
		{name: "config hash", edit: func(v *ServerAttestation) { v.ConfigSHA256 = strings.Repeat("b", 64) }, want: "config"},
		{name: "listener hash", edit: func(v *ServerAttestation) { v.ListenerImageSHA256 = strings.Repeat("c", 64) }, want: "listener"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := attestation
			test.edit(&changed)
			if err := changed.ValidateAt(manifest, "172.20.9.15:18443", strings.Repeat("a", 64), fingerprint, "20260831T090000Z-4d41c0de", now); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("Validate()=%v want %s", err, test.want)
			}
		})
	}
}

func TestActionConfigIsStrictAndBoundToManifestEndpoints(t *testing.T) {
	manifest := validWindowsManifest()
	config := ActionConfig{SchemaVersion: 1, PowerShellPath: manifest.Artifacts["powershell"].Path, InstallerScriptPath: manifest.Artifacts["installer"].Path, BundlePath: `C:\fixture`, PayloadManifestPath: `C:\fixture\payload-manifest.json`, GeneratedConfigPath: `C:\fixture\client.json`, ServerConfigPath: `C:\fixture\server.json`, ServerConfigSHA256: strings.Repeat("a", 64), ServerListenerEndpoint: "172.20.9.15:18443", ServerAttestationPath: `C:\fixture\server-attestation.json`, ServerAttestationSHA256: strings.Repeat("b", 64), ServerHostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), ServerAttestationRunNonce: "20260831T090000Z-4d41c0de", CredentialSourcePath: `C:\fixture\credential-source.exe`, CredentialSourceSHA256: strings.Repeat("c", 64), FixtureManifestPath: `C:\fixture\fixture-manifest.json`, SentinelPath: manifest.Artifacts["sentinel"].Path, ActionHelperPath: manifest.Artifacts["action-helper"].Path, FakeDataEndpoint: "172.20.9.15:18083", FakeControlEndpoint: "172.20.9.15:18082", PublicDataEndpoint: "198.18.0.2:18080", FakeIdentity: "fake-upstream/1", CredentialExpiresAt: "2099-01-01T00:00:00Z"}
	if err := config.Validate(manifest, "172.20.9.15:18083", "172.20.9.15:18082", "198.18.0.2:18080", "fake-upstream/1", config.PayloadManifestPath); err != nil {
		t.Fatalf("Validate()=%v", err)
	}
	tests := []struct {
		name string
		edit func(*ActionConfig)
		want string
	}{
		{name: "sentinel swap", edit: func(v *ActionConfig) { v.SentinelPath = `C:\fixture\other.exe` }, want: "sentinel"},
		{name: "helper swap", edit: func(v *ActionConfig) { v.ActionHelperPath = `C:\fixture\other.exe` }, want: "action-helper"},
		{name: "data endpoint", edit: func(v *ActionConfig) { v.FakeDataEndpoint = "172.20.9.15:8080" }, want: "endpoint"},
		{name: "identity", edit: func(v *ActionConfig) { v.FakeIdentity = "other" }, want: "identity"},
		{name: "payload manifest", edit: func(v *ActionConfig) { v.PayloadManifestPath = `C:\fixture\other.json` }, want: "payload manifest"},
		{name: "bundle", edit: func(v *ActionConfig) { v.BundlePath = `C:\other` }, want: "bundle"},
		{name: "credential source", edit: func(v *ActionConfig) { v.CredentialSourcePath = `credential-source.exe` }, want: "credential source"},
		{name: "server attestation", edit: func(v *ActionConfig) { v.ServerAttestationSHA256 = "bad" }, want: "attestation"},
		{name: "server attestation run nonce", edit: func(v *ActionConfig) { v.ServerAttestationRunNonce = "" }, want: "run nonce"},
		{name: "server host key grammar", edit: func(v *ActionConfig) { v.ServerHostKeyFingerprint = "SHA256:short" }, want: "host key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := config
			test.edit(&changed)
			if err := changed.Validate(manifest, "172.20.9.15:18083", "172.20.9.15:18082", "198.18.0.2:18080", "fake-upstream/1", config.PayloadManifestPath); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate()=%v want %s", err, test.want)
			}
		})
	}
}

func validWindowsManifest() Manifest {
	artifacts := make(map[string]Artifact)
	for index, role := range RequiredArtifactRoles() {
		artifact := Artifact{Path: `C:\fixture\` + role + `.exe`, SHA256: strings.Repeat(string("0123456789abcdef"[index]), 64)}
		if role == "agent" || role == "core" || role == "ui" || role == "server-service" {
			artifact.InstalledPath = `C:\Program Files\RegenBio\` + role + `.exe`
		}
		artifacts[role] = artifact
	}
	return Manifest{SchemaVersion: 1, CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1", "172.20.9.2"}, InternalSuffixes: []string{"intra.regen-bio.com"}, Artifacts: artifacts}
}
