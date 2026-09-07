package fixtureconfig

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestRequiresExactReviewedRoleSet(t *testing.T) {
	manifest := validManifest(t)
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
	client := []byte(`{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"shadowsocks","tag":"tunnel","server":"172.20.9.15","server_port":18443}],"route":{"rules":[{"ip_cidr":["172.20.9.15/32"],"action":"route","outbound":"direct"},{"ip_cidr":["172.20.8.0/22"],"action":"route","outbound":"direct"},{"domain_suffix":["intra.regen-bio.com"],"action":"route","outbound":"direct"},{"port":[53],"action":"hijack-dns"},{"network":["udp"],"action":"reject"},{"network":["tcp"],"action":"route","outbound":"tunnel"}],"final":"tunnel"},"dns":{"servers":[{"type":"udp","tag":"corp-dns","server":"172.20.9.1","detour":"direct"},{"type":"https","tag":"public-dns","server":"1.1.1.1","detour":"tunnel"}],"rules":[{"domain_suffix":["intra.regen-bio.com"],"action":"route","server":"corp-dns"}],"final":"public-dns","reverse_mapping":true}}`)
	server := []byte(`{"inbounds":[{"type":"shadowsocks","tag":"server-in","listen":"172.20.9.15","listen_port":18443}],"outbounds":[{"type":"http","tag":"fake-connect","server":"172.20.9.15","server_port":18083}],"route":{"final":"fake-connect"}}`)
	policy := NetworkPolicy{CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"}, InternalSuffixes: []string{"intra.regen-bio.com"}}
	if err := ValidateGeneratedConfigs(client, server, "172.20.9.15:18083", policy); err != nil {
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
			if err := ValidateGeneratedConfigs(test.client, test.server, test.endpoint, policy); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("ValidateGeneratedConfigs() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGeneratedConfigUsesOnlyExactSignedCorporatePolicyWithLabelBoundaries(t *testing.T) {
	policy := NetworkPolicy{CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"}, InternalSuffixes: []string{"intra.regen-bio.com"}}
	baseClient := `{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"shadowsocks","tag":"tunnel","server":"172.20.9.15","server_port":18443,"method":"2022-blake3-aes-128-gcm"}],"route":{"rules":[{"ip_cidr":["172.20.9.15/32"],"action":"route","outbound":"direct"},{"ip_cidr":["172.20.8.0/22"],"action":"route","outbound":"direct"},{"domain_suffix":["ad.intra.regen-bio.com"],"action":"route","outbound":"direct"},{"port":[53],"action":"hijack-dns"},{"network":["udp"],"action":"reject"},{"network":["tcp"],"action":"route","outbound":"tunnel"}],"final":"tunnel"},"dns":{"servers":[{"type":"udp","tag":"corp-dns","server":"172.20.9.1","detour":"direct"},{"type":"https","tag":"public-dns","server":"1.1.1.1","detour":"tunnel"}],"rules":[{"domain_suffix":["ad.intra.regen-bio.com"],"action":"route","server":"corp-dns"}],"final":"public-dns","reverse_mapping":true}}`
	server := []byte(`{"inbounds":[{"type":"shadowsocks","tag":"server-in","listen":"172.20.9.15","listen_port":18443}],"outbounds":[{"type":"http","tag":"fake-connect","server":"172.20.9.15","server_port":18083}],"route":{"final":"fake-connect"}}`)
	if err := ValidateGeneratedConfigs([]byte(baseClient), server, "172.20.9.15:18083", policy); err != nil {
		t.Fatalf("exact signed policy rejected: %v", err)
	}
	for _, test := range []struct{ name, from, to, want string }{
		{name: "other private cidr", from: `172.20.8.0/22`, to: `10.0.0.0/8`, want: "corporate"},
		{name: "other private dns", from: `"server":"172.20.9.1","detour":"direct"`, to: `"server":"10.0.0.53","detour":"direct"`, want: "resolver"},
		{name: "suffix text collision", from: `ad.intra.regen-bio.com`, to: `evilintra.regen-bio.com`, want: "suffix"},
		{name: "unbounded direct route", from: `{"ip_cidr":["172.20.8.0/22"],"action":"route","outbound":"direct"}`, to: `{"action":"route","outbound":"direct"}`, want: "direct"},
		{name: "direct port escape", from: `{"ip_cidr":["172.20.8.0/22"],"action":"route","outbound":"direct"}`, to: `{"ip_cidr":["172.20.8.0/22"],"port":[443],"action":"route","outbound":"direct"}`, want: "direct"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := []byte(strings.ReplaceAll(baseClient, test.from, test.to))
			if err := ValidateGeneratedConfigs(changed, server, "172.20.9.15:18083", policy); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("ValidateGeneratedConfigs()=%v, want %q", err, test.want)
			}
		})
	}
}

func TestPayloadManifestDrivesEveryInstalledClientFile(t *testing.T) {
	manifest := validPayloadManifest()
	bindings, err := manifest.InstalledFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != len(manifest.Files) {
		t.Fatalf("installed bindings=%d, want %d", len(bindings), len(manifest.Files))
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		seen[binding.Name] = true
		if binding.Path == "" || binding.SHA256 == "" {
			t.Fatalf("incomplete binding %#v", binding)
		}
	}
	for _, name := range requiredPayloadNames {
		if !seen[name] {
			t.Errorf("payload %s omitted", name)
		}
	}
	if !seen["client-sbom.json"] || !seen["SHA256SUMS"] {
		t.Fatal("signed metadata entries were omitted")
	}
	changed := manifest
	changed.Files = append([]PayloadFile(nil), manifest.Files...)
	changed.Files = changed.Files[1:]
	if _, err := changed.InstalledFiles(); err == nil || !strings.Contains(err.Error(), "complete") {
		t.Fatalf("InstalledFiles()=%v, want incomplete-manifest refusal", err)
	}
}

func TestPayloadManifestAcceptsReleaseSchemaAndRefusesUnsafeDestinations(t *testing.T) {
	manifest := validPayloadManifest()
	manifest.SourceCommit = strings.Repeat("a", 40)
	manifest.Mode = "release"
	manifest.Files[0].AuthenticodeRequired = true
	manifest.Files[0].AuthenticodeThumbprints = []string{strings.Repeat("a", 40)}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePayloadManifest(data); err != nil {
		t.Fatalf("ParsePayloadManifest(release schema)=%v", err)
	}
	for _, edit := range []func(*PayloadManifest){
		func(v *PayloadManifest) { v.Files[0].Name = `..\escape.exe` },
		func(v *PayloadManifest) { v.Files[0].Destination = "other-root" },
		func(v *PayloadManifest) { v.Files[0].AuthenticodeThumbprints = []string{"not-a-thumbprint"} },
		func(v *PayloadManifest) {
			v.Files = append(v.Files, PayloadFile{Name: "credential.bin", Destination: "program-data", SHA256: strings.Repeat("c", 64)})
		},
	} {
		changed := validPayloadManifest()
		edit(&changed)
		if _, err := changed.InstalledFiles(); err == nil {
			t.Fatal("InstalledFiles accepted an unsafe manifest entry")
		}
	}
}

func TestValidateGeneratedConfigsRejectsPlaintextTunnelCredential(t *testing.T) {
	client := []byte(`{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"shadowsocks","tag":"tunnel","server":"172.20.9.15","server_port":18443,"method":"2022-blake3-aes-128-gcm","password":"plaintext-secret"}],"route":{"rules":[{"ip_cidr":["172.20.9.15/32"],"action":"route","outbound":"direct"},{"ip_cidr":["172.20.8.0/22"],"action":"route","outbound":"direct"},{"domain_suffix":["intra.regen-bio.com"],"action":"route","outbound":"direct"},{"port":[53],"action":"hijack-dns"},{"network":["udp"],"action":"reject"},{"network":["tcp"],"action":"route","outbound":"tunnel"}],"final":"tunnel"},"dns":{"servers":[{"type":"udp","tag":"corp-dns","server":"172.20.9.1","detour":"direct"},{"type":"https","tag":"public-dns","server":"1.1.1.1","detour":"tunnel"}],"rules":[{"domain_suffix":["intra.regen-bio.com"],"action":"route","server":"corp-dns"}],"final":"public-dns","reverse_mapping":true}}`)
	server := []byte(`{"inbounds":[{"type":"shadowsocks","tag":"server-in","listen":"172.20.9.15","listen_port":18443}],"outbounds":[{"type":"http","tag":"fake-connect","server":"172.20.9.15","server_port":18083}],"route":{"final":"fake-connect"}}`)
	policy := NetworkPolicy{CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"}, InternalSuffixes: []string{"intra.regen-bio.com"}}
	if err := ValidateGeneratedConfigs(client, server, "172.20.9.15:18083", policy); err == nil || !strings.Contains(strings.ToLower(err.Error()), "plaintext") {
		t.Fatalf("ValidateGeneratedConfigs()=%v, want plaintext-credential refusal", err)
	}
}

func TestProvisioningMetadataRequiresCredentiallessLockedClientConfig(t *testing.T) {
	client := []byte(`{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"shadowsocks","tag":"tunnel","server":"172.20.9.15","server_port":18443,"method":"2022-blake3-aes-128-gcm"}],"route":{"final":"tunnel"}}`)
	metadata, err := ProvisioningMetadata(client)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Method != "2022-blake3-aes-128-gcm" || metadata.Endpoint != "172.20.9.15:18443" {
		t.Fatalf("metadata=%#v", metadata)
	}
	for _, changed := range [][]byte{
		[]byte(strings.Replace(string(client), `"tag":"tunnel"`, `"tag":"other"`, 1)),
		[]byte(strings.Replace(string(client), `"method":"2022-blake3-aes-128-gcm"`, `"method":""`, 1)),
		[]byte(strings.Replace(string(client), `"method":"2022-blake3-aes-128-gcm"`, `"method":"2022-blake3-aes-128-gcm","password":"plaintext"`, 1)),
		append(client, []byte(` {}`)...),
	} {
		if _, err := ProvisioningMetadata(changed); err == nil {
			t.Fatal("ProvisioningMetadata accepted an invalid or secret-bearing client config")
		}
	}
}

func TestManifestBindingComesFromManifestNotCallerHashes(t *testing.T) {
	manifest := validManifest(t)
	binding, err := manifest.ArtifactBinding(strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	if binding.ManifestSHA256 != strings.Repeat("f", 64) || binding.AgentSHA256 != manifest.Artifacts["agent"].SHA256 || binding.ActionHelperSHA256 != manifest.Artifacts["action-helper"].SHA256 {
		t.Fatalf("binding = %#v", binding)
	}
}

func validManifest(t *testing.T) Manifest {
	t.Helper()
	root := t.TempDir()
	artifacts := make(map[string]Artifact)
	for index, role := range RequiredArtifactRoles() {
		artifact := Artifact{Path: filepath.Join(root, "fixture", role+".exe"), SHA256: strings.Repeat(string("0123456789abcdef"[index]), 64)}
		if role == "agent" || role == "core" || role == "ui" || role == "server-service" {
			artifact.InstalledPath = filepath.Join(root, "installed", role+".exe")
		}
		artifacts[role] = artifact
	}
	return Manifest{SchemaVersion: 1, CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1", "172.20.9.2"}, InternalSuffixes: []string{"intra.regen-bio.com"}, Artifacts: artifacts}
}

func validPayloadManifest() PayloadManifest {
	files := make([]PayloadFile, 0, len(requiredPayloadNames))
	for index, name := range requiredPayloadNames {
		destination := "program-files"
		if name == "agent.yaml" || name == "agent.yaml.p7s" || name == "client-sbom.json" || name == "SHA256SUMS" {
			destination = "program-data"
		}
		files = append(files, PayloadFile{Name: name, Destination: destination, SHA256: strings.Repeat(string("0123456789abcdef"[index]), 64)})
	}
	return PayloadManifest{SchemaVersion: 1, ProductVersion: "0.1.0", SourceCommit: strings.Repeat("a", 40), Mode: "release", SignerThumbprints: []string{strings.Repeat("a", 40)}, Files: files}
}

func cloneArtifacts(input map[string]Artifact) map[string]Artifact {
	output := make(map[string]Artifact, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func TestManifestStrictJSON(t *testing.T) {
	data, _ := json.Marshal(validManifest(t))
	data = append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
	if _, err := ParseManifest(data); err == nil {
		t.Fatal("ParseManifest accepted unknown field")
	}
}

func TestActionConfigStrictJSON(t *testing.T) {
	if _, err := ParseActionConfig([]byte(`{"schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		`{"schema_version":1,"unknown":true}`,
		`{"schema_version":1} {}`,
		`{"schema_version":`,
	} {
		if _, err := ParseActionConfig([]byte(data)); err == nil {
			t.Errorf("accepted invalid action config %s", data)
		}
	}
}
