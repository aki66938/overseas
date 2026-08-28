package fixtureconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManifestRequiresExactReviewedRoleSet(t *testing.T) {
	manifest := validManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	for _, role := range RequiredArtifactRoles() {
		t.Run(role, func(t *testing.T) {
			changed := manifest
			changed.Artifacts = cloneArtifacts(manifest.Artifacts)
			delete(changed.Artifacts, role)
			if err := changed.Validate(); err == nil || !strings.Contains(err.Error(), role) {
				t.Fatalf("Validate() = %v, want missing %s", err, role)
			}
		})
	}
	changed := manifest
	changed.Artifacts = cloneArtifacts(manifest.Artifacts)
	changed.Artifacts["unreviewed"] = Artifact{Path: `C:\fixture\extra.exe`, SHA256: strings.Repeat("a", 64)}
	if err := changed.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("Validate() = %v, want extra role refusal", err)
	}
}

func TestValidateGeneratedConfigsRequiresOnlyFakeCONNECTUpstream(t *testing.T) {
	client := []byte(`{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"shadowsocks","tag":"tunnel","server":"172.20.9.15","server_port":18443}],"route":{"rules":[{"ip_cidr":["172.20.9.15/32"],"action":"route","outbound":"direct"},{"ip_cidr":["172.20.8.0/22"],"action":"route","outbound":"direct"},{"port":[53],"action":"hijack-dns"},{"network":["udp"],"action":"reject"},{"network":["tcp"],"action":"route","outbound":"tunnel"}],"final":"tunnel"},"dns":{"servers":[{"type":"udp","tag":"corp-dns","server":"172.20.9.1","detour":"direct"},{"type":"https","tag":"public-dns","server":"1.1.1.1","detour":"tunnel"}],"final":"public-dns","reverse_mapping":true}}`)
	server := []byte(`{"inbounds":[{"type":"shadowsocks","tag":"server-in","listen":"172.20.9.15","listen_port":18443}],"outbounds":[{"type":"http","tag":"fake-connect","server":"172.20.9.15","server_port":18083}],"route":{"final":"fake-connect"}}`)
	if err := ValidateGeneratedConfigs(client, server, "172.20.9.15:18083"); err != nil {
		t.Fatalf("ValidateGeneratedConfigs() = %v", err)
	}
	tests := []struct {
		name           string
		client, server []byte
		endpoint, want string
	}{
		{name: "production telecom", client: client, server: []byte(strings.ReplaceAll(string(server), `"172.20.9.15","server_port":18083`, `"127.0.0.1","server_port":8080`)), endpoint: "172.20.9.15:18083", want: "prohibited"},
		{name: "wrong bound endpoint", client: client, server: server, endpoint: "172.20.9.16:18083", want: "bound fake"},
		{name: "client misses server inbound", client: []byte(strings.Replace(string(client), `"server_port":18443`, `"server_port":18444`, 1)), server: server, endpoint: "172.20.9.15:18083", want: "server inbound"},
		{name: "fallback outbound", client: client, server: []byte(strings.Replace(string(server), `"outbounds":[{"type":"http","tag":"fake-connect","server":"172.20.9.15","server_port":18083}]`, `"outbounds":[{"type":"http","tag":"fake-connect","server":"172.20.9.15","server_port":18083},{"type":"direct","tag":"fallback"}]`, 1)), endpoint: "172.20.9.15:18083", want: "exactly one"},
		{name: "client extra remote", client: []byte(strings.Replace(string(client), `]`, `,{"type":"http","tag":"telecom","server":"127.0.0.1","server_port":8080}]`, 1)), server: server, endpoint: "172.20.9.15:18083", want: "client"},
		{name: "client direct public rule", client: []byte(strings.Replace(string(client), `"172.20.8.0/22"`, `"0.0.0.0/0"`, 1)), server: server, endpoint: "172.20.9.15:18083", want: "non-corporate"},
		{name: "client remote dns", client: []byte(strings.Replace(string(client), `"server":"172.20.9.1","detour":"direct"`, `"server":"8.8.8.8","detour":"direct"`, 1)), server: server, endpoint: "172.20.9.15:18083", want: "corporate resolver"},
		{name: "server remote rule set", client: client, server: []byte(strings.Replace(string(server), `"route":{"final":"fake-connect"}`, `"route":{"rule_set":[{"type":"remote","url":"https://example.test/rules.srs"}],"final":"fake-connect"}`, 1)), endpoint: "172.20.9.15:18083", want: "rule-set"},
		{name: "trailing server json", client: client, server: append(server, []byte(` {}`)...), endpoint: "172.20.9.15:18083", want: "trailing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateGeneratedConfigs(test.client, test.server, test.endpoint); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("ValidateGeneratedConfigs() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestManifestBindingComesFromManifestNotCallerHashes(t *testing.T) {
	manifest := validManifest()
	binding, err := manifest.ArtifactBinding(strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	if binding.ManifestSHA256 != strings.Repeat("f", 64) || binding.AgentSHA256 != manifest.Artifacts["agent"].SHA256 || binding.ActionHelperSHA256 != manifest.Artifacts["action-helper"].SHA256 {
		t.Fatalf("binding = %#v", binding)
	}
}

func validManifest() Manifest {
	artifacts := make(map[string]Artifact)
	for index, role := range RequiredArtifactRoles() {
		artifact := Artifact{Path: `C:\fixture\` + role + `.exe`, SHA256: strings.Repeat(string("0123456789abcdef"[index]), 64)}
		if role == "agent" || role == "core" || role == "ui" || role == "server-service" {
			artifact.InstalledPath = `C:\Program Files\RegenBio\` + role + `.exe`
		}
		artifacts[role] = artifact
	}
	return Manifest{SchemaVersion: 1, Artifacts: artifacts}
}

func cloneArtifacts(input map[string]Artifact) map[string]Artifact {
	output := make(map[string]Artifact, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func TestManifestStrictJSON(t *testing.T) {
	data, _ := json.Marshal(validManifest())
	data = append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
	if _, err := ParseManifest(data); err == nil {
		t.Fatal("ParseManifest accepted unknown field")
	}
}

func TestActionConfigIsStrictAndBoundToManifestEndpoints(t *testing.T) {
	manifest := validManifest()
	config := ActionConfig{SchemaVersion: 1, PowerShellPath: manifest.Artifacts["powershell"].Path, InstallerScriptPath: manifest.Artifacts["installer"].Path, BundlePath: `C:\fixture`, PayloadManifestPath: `C:\fixture\payload-manifest.json`, FixtureManifestPath: `C:\fixture\fixture-manifest.json`, SentinelPath: manifest.Artifacts["sentinel"].Path, ActionHelperPath: manifest.Artifacts["action-helper"].Path, FakeDataEndpoint: "172.20.9.15:18083", FakeControlEndpoint: "172.20.9.15:18082", PublicDataEndpoint: "198.18.0.2:18080", FakeIdentity: "fake-upstream/1"}
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
