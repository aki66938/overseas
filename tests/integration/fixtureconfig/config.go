package fixtureconfig

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"corp.example/overseas-access-gateway/tests/integration/fixtureproto"
)

var requiredArtifactRoles = []string{"action-helper", "agent", "capture-script", "core", "driver", "installer", "powershell", "sentinel", "server-service", "ui"}

var requiredPayloadNames = []string{
	"overseas-agent.exe", "overseas-client.exe", "credential-provisioner.exe", "installer-verifier.exe",
	"install-client.ps1", "PROVISIONING.md", "sing-box.exe", "sing-box.manifest.json", "libcronet.dll",
	"wintun.dll", "agent.yaml", "agent.yaml.p7s", "sing-box-LICENSE.txt", "wintun-LICENSE.txt",
	"client-sbom.json", "SHA256SUMS",
}

const (
	clientInstallRoot = `C:\Program Files\RegenBio\OverseasAccess`
	clientDataRoot    = `C:\ProgramData\RegenBio\OverseasAccess`
)

type Artifact struct {
	Path          string `json:"path"`
	InstalledPath string `json:"installed_path,omitempty"`
	SHA256        string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion    int                 `json:"schema_version"`
	CorporateCIDRs   []string            `json:"corporate_cidrs"`
	CorporateDNS     []string            `json:"corporate_dns"`
	InternalSuffixes []string            `json:"internal_suffixes"`
	Artifacts        map[string]Artifact `json:"artifacts"`
}

type NetworkPolicy struct {
	CorporateCIDRs   []string `json:"corporate_cidrs"`
	CorporateDNS     []string `json:"corporate_dns"`
	InternalSuffixes []string `json:"internal_suffixes"`
}

type PayloadFile struct {
	Name                    string   `json:"name"`
	Destination             string   `json:"destination"`
	SHA256                  string   `json:"sha256"`
	AuthenticodeRequired    bool     `json:"authenticode_required"`
	AuthenticodeThumbprints []string `json:"authenticode_thumbprints"`
}

type PayloadManifest struct {
	SchemaVersion     int           `json:"schema_version"`
	ProductVersion    string        `json:"product_version"`
	SourceCommit      string        `json:"source_commit"`
	Mode              string        `json:"mode"`
	SignerThumbprints []string      `json:"signer_thumbprints"`
	Files             []PayloadFile `json:"files"`
}

type InstalledPayload struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ActionConfig struct {
	SchemaVersion          int    `json:"schema_version"`
	PowerShellPath         string `json:"powershell_path"`
	InstallerScriptPath    string `json:"installer_script_path"`
	BundlePath             string `json:"bundle_path"`
	PayloadManifestPath    string `json:"payload_manifest_path"`
	GeneratedConfigPath    string `json:"generated_config_path"`
	ServerConfigPath       string `json:"server_config_path"`
	ServerConfigSHA256     string `json:"server_config_sha256"`
	ServerListenerEndpoint string `json:"server_listener_endpoint"`
	FixtureManifestPath    string `json:"fixture_manifest_path"`
	SentinelPath           string `json:"sentinel_path"`
	ActionHelperPath       string `json:"action_helper_path"`
	FakeDataEndpoint       string `json:"fake_data_endpoint"`
	FakeControlEndpoint    string `json:"fake_control_endpoint"`
	PublicDataEndpoint     string `json:"public_data_endpoint"`
	FakeIdentity           string `json:"fake_identity"`
	CredentialExpiresAt    string `json:"credential_expires_at"`
}

func ParseActionConfig(data []byte) (ActionConfig, error) {
	var value ActionConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := requireEOF(decoder); err != nil {
		return value, err
	}
	return value, nil
}

func (c ActionConfig) Validate(manifest Manifest, fakeData, fakeControl, publicData, fakeIdentity, payloadManifestPath string) error {
	if c.SchemaVersion != 1 {
		return errors.New("action config schema mismatch")
	}
	for name, path := range map[string]string{"powershell": c.PowerShellPath, "installer": c.InstallerScriptPath, "bundle": c.BundlePath, "payload manifest": c.PayloadManifestPath, "generated config": c.GeneratedConfigPath, "server config": c.ServerConfigPath, "fixture manifest": c.FixtureManifestPath, "sentinel": c.SentinelPath, "action-helper": c.ActionHelperPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("action config %s path is invalid", name)
		}
	}
	for role, path := range map[string]string{"powershell": c.PowerShellPath, "installer": c.InstallerScriptPath, "sentinel": c.SentinelPath, "action-helper": c.ActionHelperPath} {
		if manifest.Artifacts[role].Path != path {
			return fmt.Errorf("action config %s path differs from manifest", role)
		}
	}
	if c.PayloadManifestPath != payloadManifestPath {
		return errors.New("action config payload manifest differs from pinned payload")
	}
	for _, role := range []string{"agent", "core", "ui"} {
		relative, err := filepath.Rel(c.BundlePath, manifest.Artifacts[role].Path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return fmt.Errorf("action config bundle does not contain manifest artifact %s", role)
		}
	}
	if c.FakeDataEndpoint != fakeData || c.FakeControlEndpoint != fakeControl || c.PublicDataEndpoint != publicData {
		return errors.New("action config endpoint binding mismatch")
	}
	if c.FakeIdentity != fakeIdentity || strings.TrimSpace(c.FakeIdentity) == "" {
		return errors.New("action config identity binding mismatch")
	}
	if !validSHA256(c.ServerConfigSHA256) {
		return errors.New("action config server config hash is invalid")
	}
	if _, _, err := parseSafeEndpoint(c.ServerListenerEndpoint); err != nil {
		return errors.New("action config server listener endpoint is invalid")
	}
	expires, err := time.Parse(time.RFC3339, c.CredentialExpiresAt)
	if err != nil || !expires.After(time.Now().UTC()) {
		return errors.New("action config credential expiration is invalid")
	}
	return nil
}

func RequiredArtifactRoles() []string { return append([]string(nil), requiredArtifactRoles...) }

func ParseManifest(data []byte) (Manifest, error) {
	var value Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Manifest{}, fmt.Errorf("decode fixture manifest: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return Manifest{}, err
	}
	if err := value.Validate(); err != nil {
		return Manifest{}, err
	}
	return value, nil
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != 1 {
		return errors.New("fixture manifest schema version must be 1")
	}
	if err := m.NetworkPolicy().Validate(); err != nil {
		return err
	}
	wanted := make(map[string]struct{}, len(requiredArtifactRoles))
	for _, role := range requiredArtifactRoles {
		wanted[role] = struct{}{}
	}
	for role := range m.Artifacts {
		if _, ok := wanted[role]; !ok {
			return fmt.Errorf("unsupported artifact role %q", role)
		}
	}
	for _, role := range requiredArtifactRoles {
		artifact, ok := m.Artifacts[role]
		if !ok {
			return fmt.Errorf("artifact role %s is required", role)
		}
		if !filepath.IsAbs(artifact.Path) || filepath.Clean(artifact.Path) != artifact.Path {
			return fmt.Errorf("artifact role %s path must be absolute and clean", role)
		}
		if role == "agent" || role == "core" || role == "ui" || role == "server-service" {
			if !filepath.IsAbs(artifact.InstalledPath) || filepath.Clean(artifact.InstalledPath) != artifact.InstalledPath {
				return fmt.Errorf("artifact role %s installed path must be absolute and clean", role)
			}
		}
		if !validSHA256(artifact.SHA256) {
			return fmt.Errorf("artifact role %s hash is invalid", role)
		}
	}
	return nil
}

func (m Manifest) NetworkPolicy() NetworkPolicy {
	return NetworkPolicy{CorporateCIDRs: append([]string(nil), m.CorporateCIDRs...), CorporateDNS: append([]string(nil), m.CorporateDNS...), InternalSuffixes: append([]string(nil), m.InternalSuffixes...)}
}

func (p NetworkPolicy) Validate() error {
	if len(p.CorporateCIDRs) == 0 || len(p.CorporateDNS) == 0 || len(p.InternalSuffixes) == 0 {
		return errors.New("signed corporate CIDR, DNS, and suffix allowlists are required")
	}
	seen := map[string]bool{}
	for _, text := range p.CorporateCIDRs {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.String() != text || prefix.Bits() == 0 || seen["c:"+text] {
			return errors.New("signed corporate CIDR allowlist is invalid")
		}
		seen["c:"+text] = true
	}
	for _, text := range p.CorporateDNS {
		addr, err := netip.ParseAddr(text)
		if err != nil || !addr.Is4() || !addr.IsPrivate() || addr.String() != text || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || seen["d:"+text] {
			return errors.New("signed corporate DNS allowlist is invalid")
		}
		seen["d:"+text] = true
	}
	for _, text := range p.InternalSuffixes {
		if text == "" || text != strings.ToLower(text) || strings.Trim(text, ".") != text || strings.Contains(text, "..") || !strings.Contains(text, ".") || seen["s:"+text] {
			return errors.New("signed internal suffix allowlist is invalid")
		}
		seen["s:"+text] = true
	}
	return nil
}

func ParsePayloadManifest(data []byte) (PayloadManifest, error) {
	var value PayloadManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("decode payload manifest: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return value, err
	}
	if _, err := value.InstalledFiles(); err != nil {
		return value, err
	}
	return value, nil
}

func (m PayloadManifest) InstalledFiles() ([]InstalledPayload, error) {
	if m.SchemaVersion != 1 || m.ProductVersion != "0.1.0" || m.Mode != "release" || !validHex(m.SourceCommit, 40) || len(m.SignerThumbprints) == 0 {
		return nil, errors.New("payload manifest schema, version, or signer allowlist is invalid")
	}
	signers := make(map[string]bool, len(m.SignerThumbprints))
	for _, thumbprint := range m.SignerThumbprints {
		thumbprint = strings.ToLower(thumbprint)
		if !validHex(thumbprint, 40) || signers[thumbprint] {
			return nil, errors.New("payload manifest signer allowlist is invalid")
		}
		signers[thumbprint] = true
	}
	wanted := make(map[string]bool, len(requiredPayloadNames))
	for _, name := range requiredPayloadNames {
		wanted[name] = true
	}
	if len(m.Files) < len(wanted) {
		return nil, errors.New("payload manifest must contain the complete required payload allowlist")
	}
	seen := map[string]bool{}
	requiredSeen := map[string]bool{}
	reservedRuntimeNames := map[string]bool{
		".regenbio-overseas-access.owner.json": true,
		"credential.bin":                       true,
		"network-state.json":                   true,
		"runtime-owned.json":                   true,
		"sing-box.json":                        true,
	}
	result := make([]InstalledPayload, 0, len(m.Files))
	for _, file := range m.Files {
		if file.Name == "" || file.Name == "." || filepath.Base(file.Name) != file.Name || strings.ContainsAny(file.Name, `\/:`) || seen[strings.ToLower(file.Name)] || reservedRuntimeNames[strings.ToLower(file.Name)] || !validSHA256(file.SHA256) {
			return nil, errors.New("payload manifest contains an unsafe, duplicate, or unhashed file")
		}
		seen[strings.ToLower(file.Name)] = true
		root := ""
		switch file.Destination {
		case "program-files":
			root = clientInstallRoot
		case "program-data":
			root = clientDataRoot
		default:
			return nil, errors.New("payload manifest contains an unreviewed destination")
		}
		if wanted[file.Name] {
			requiredSeen[file.Name] = true
			expectedDestination := "program-files"
			if file.Name == "agent.yaml" || file.Name == "agent.yaml.p7s" || file.Name == "client-sbom.json" || file.Name == "SHA256SUMS" {
				expectedDestination = "program-data"
			}
			if file.Destination != expectedDestination {
				return nil, errors.New("required payload destination is invalid")
			}
		}
		if file.AuthenticodeRequired && len(file.AuthenticodeThumbprints) == 0 {
			return nil, errors.New("required payload Authenticode allowlist is absent")
		}
		for _, thumbprint := range file.AuthenticodeThumbprints {
			thumbprint = strings.ToLower(thumbprint)
			if !validHex(thumbprint, 40) || !signers[thumbprint] {
				return nil, errors.New("payload Authenticode signer is outside the manifest allowlist")
			}
		}
		result = append(result, InstalledPayload{Name: file.Name, Path: filepath.Join(root, file.Name), SHA256: file.SHA256})
	}
	for name := range wanted {
		if !requiredSeen[name] {
			return nil, errors.New("payload manifest must contain the complete required payload allowlist")
		}
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i].Path) < strings.ToLower(result[j].Path) })
	return result, nil
}

func validHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func PayloadBindings(manifest PayloadManifest) ([]fixtureproto.PayloadFileBinding, error) {
	installed, err := manifest.InstalledFiles()
	if err != nil {
		return nil, err
	}
	result := make([]fixtureproto.PayloadFileBinding, len(installed))
	for index, file := range installed {
		result[index] = fixtureproto.PayloadFileBinding{Name: file.Name, Path: file.Path, SHA256: file.SHA256}
	}
	return result, nil
}

func (p NetworkPolicy) Binding() fixtureproto.NetworkBinding {
	return fixtureproto.NetworkBinding{CorporateCIDRs: append([]string(nil), p.CorporateCIDRs...), CorporateDNS: append([]string(nil), p.CorporateDNS...), InternalSuffixes: append([]string(nil), p.InternalSuffixes...)}
}

func (m Manifest) ArtifactBinding(manifestSHA256 string) (fixtureproto.ArtifactBinding, error) {
	if err := m.Validate(); err != nil {
		return fixtureproto.ArtifactBinding{}, err
	}
	if !validSHA256(manifestSHA256) {
		return fixtureproto.ArtifactBinding{}, errors.New("manifest hash is invalid")
	}
	return fixtureproto.ArtifactBinding{
		ManifestSHA256: manifestSHA256,
		AgentSHA256:    m.Artifacts["agent"].SHA256, CoreSHA256: m.Artifacts["core"].SHA256,
		UISHA256: m.Artifacts["ui"].SHA256, ServerServiceSHA256: m.Artifacts["server-service"].SHA256,
		DriverSHA256: m.Artifacts["driver"].SHA256, SentinelSHA256: m.Artifacts["sentinel"].SHA256,
		ActionHelperSHA256: m.Artifacts["action-helper"].SHA256, PowerShellSHA256: m.Artifacts["powershell"].SHA256,
		InstallerSHA256: m.Artifacts["installer"].SHA256, CaptureScriptSHA256: m.Artifacts["capture-script"].SHA256,
	}, nil
}

type singBoxConfig struct {
	Inbounds  []singEndpoint `json:"inbounds"`
	Outbounds []singEndpoint `json:"outbounds"`
	Route     singRoute      `json:"route"`
	DNS       *singDNS       `json:"dns,omitempty"`
}

type singEndpoint struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen,omitempty"`
	ListenPort uint16 `json:"listen_port,omitempty"`
	Server     string `json:"server,omitempty"`
	ServerPort uint16 `json:"server_port,omitempty"`
	Method     string `json:"method,omitempty"`
	Password   string `json:"password,omitempty"`
}

type singRoute struct {
	Final   string          `json:"final"`
	Rules   []singRouteRule `json:"rules,omitempty"`
	RuleSet json.RawMessage `json:"rule_set,omitempty"`
}

type singRouteRule struct {
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Network      []string `json:"network,omitempty"`
	Port         []int    `json:"port,omitempty"`
	Action       string   `json:"action"`
	Outbound     string   `json:"outbound,omitempty"`
}

type singDNS struct {
	Servers        []singDNSServer `json:"servers"`
	Rules          []singDNSRule   `json:"rules,omitempty"`
	Final          string          `json:"final"`
	ReverseMapping bool            `json:"reverse_mapping"`
}

type singDNSServer struct {
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	Server string `json:"server"`
	Detour string `json:"detour"`
}

type singDNSRule struct {
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Action       string   `json:"action"`
	Server       string   `json:"server,omitempty"`
}

func ValidateGeneratedConfigs(clientData, serverData []byte, fakeDataEndpoint string, policy NetworkPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	fakeHost, fakePort, err := parseSafeEndpoint(fakeDataEndpoint)
	if err != nil {
		return fmt.Errorf("bound fake CONNECT endpoint: %w", err)
	}
	client, err := decodeSingConfig(clientData)
	if err != nil {
		return fmt.Errorf("client config: %w", err)
	}
	server, err := decodeSingConfig(serverData)
	if err != nil {
		return fmt.Errorf("server config: %w", err)
	}
	if prohibitedConfig(clientData) {
		return errors.New("client config contains prohibited telecom/loopback upstream")
	}
	if prohibitedConfig(serverData) {
		return errors.New("server config contains prohibited telecom/loopback upstream")
	}
	if len(client.Outbounds) != 2 {
		return errors.New("client config must contain exactly direct and tunnel outbounds")
	}
	clientTypes := map[string]int{}
	var clientTunnel singEndpoint
	for _, outbound := range client.Outbounds {
		clientTypes[outbound.Type]++
		if outbound.Type != "direct" && outbound.Type != "shadowsocks" {
			return fmt.Errorf("client config contains unsupported outbound %q", outbound.Type)
		}
		if outbound.Type == "shadowsocks" {
			if _, _, err := parseSafeEndpoint(net.JoinHostPort(outbound.Server, fmt.Sprint(outbound.ServerPort))); err != nil {
				return fmt.Errorf("client tunnel endpoint: %w", err)
			}
			clientTunnel = outbound
		}
	}
	if clientTypes["direct"] != 1 || clientTypes["shadowsocks"] != 1 || client.Route.Final != "tunnel" {
		return errors.New("client config does not have one fixed tunnel and direct outbound")
	}
	if err := validateClientPolicy(client, clientTunnel, policy); err != nil {
		return err
	}
	if len(server.Inbounds) != 1 || server.Inbounds[0].Type != "shadowsocks" {
		return errors.New("server config must contain exactly one shadowsocks inbound")
	}
	serverInbound := server.Inbounds[0]
	if _, _, err := parseSafeEndpoint(net.JoinHostPort(serverInbound.Listen, fmt.Sprint(serverInbound.ListenPort))); err != nil {
		return fmt.Errorf("server inbound: %w", err)
	}
	if clientTunnel.Server != serverInbound.Listen || clientTunnel.ServerPort != serverInbound.ListenPort {
		return errors.New("client tunnel does not match the server inbound")
	}
	if len(server.Outbounds) != 1 {
		return errors.New("server config must contain exactly one outbound")
	}
	outbound := server.Outbounds[0]
	if outbound.Type != "http" || outbound.Tag != "fake-connect" || server.Route.Final != outbound.Tag {
		return errors.New("server config outbound is not the fixed fake CONNECT route")
	}
	if outbound.Server != fakeHost || outbound.ServerPort != fakePort {
		return errors.New("server config does not use the bound fake CONNECT endpoint")
	}
	return nil
}

func decodeSingConfig(data []byte) (singBoxConfig, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return singBoxConfig{}, fmt.Errorf("trailing or invalid JSON: %w", err)
	}
	for name := range top {
		switch name {
		case "log", "inbounds", "outbounds", "route", "dns":
		default:
			return singBoxConfig{}, fmt.Errorf("unsupported top-level network surface %q", name)
		}
	}
	var value singBoxConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := requireEOF(decoder); err != nil {
		return value, err
	}
	if len(value.Inbounds) == 0 || len(value.Outbounds) == 0 || value.Route.Final == "" {
		return value, errors.New("required sing-box surfaces are absent")
	}
	if rawJSONPresent(value.Route.RuleSet) {
		return value, errors.New("remote or local rule-set surfaces are not allowed in the isolated fixture config")
	}
	return value, nil
}

func validateClientPolicy(client singBoxConfig, tunnel singEndpoint, policy NetworkPolicy) error {
	if client.DNS == nil || len(client.DNS.Servers) == 0 || client.DNS.Final != "public-dns" || !client.DNS.ReverseMapping {
		return errors.New("client DNS policy is absent or incomplete")
	}
	hasNodeDirect, hasDNSHijack, hasUDPReject, hasTCPTunnel := false, false, false, false
	seenCIDR, seenDNS, seenSuffix := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, rule := range client.Route.Rules {
		switch rule.Action {
		case "route":
			if rule.Outbound == "direct" {
				if (len(rule.IPCIDR) == 0 && len(rule.DomainSuffix) == 0) || len(rule.Network) != 0 || len(rule.Port) != 0 {
					return errors.New("direct route rule has fields outside constrained corporate targets")
				}
				for _, text := range rule.IPCIDR {
					prefix, err := netip.ParsePrefix(text)
					if err != nil || prefix.String() != text || prefix.Bits() == 0 {
						return errors.New("route rules contain a non-corporate direct IP target")
					}
					if prefix.Bits() == 32 && prefix.Addr().String() == tunnel.Server {
						hasNodeDirect = true
						continue
					}
					if !containsExact(policy.CorporateCIDRs, text) {
						return errors.New("route rules contain a non-corporate direct IP target")
					}
					seenCIDR[text] = true
				}
				for _, suffix := range rule.DomainSuffix {
					matched := matchingSuffix(policy.InternalSuffixes, suffix)
					if matched == "" {
						return errors.New("route rules contain an unreviewed direct domain suffix")
					}
					seenSuffix[matched] = true
				}
			} else if rule.Outbound == "tunnel" && equalStrings(rule.Network, []string{"tcp"}) && len(rule.IPCIDR) == 0 && len(rule.DomainSuffix) == 0 && len(rule.Port) == 0 {
				hasTCPTunnel = true
			} else {
				return errors.New("route rules contain an unreviewed route outbound")
			}
		case "hijack-dns":
			hasDNSHijack = equalInts(rule.Port, []int{53}) && len(rule.IPCIDR) == 0 && len(rule.DomainSuffix) == 0
		case "reject":
			if equalStrings(rule.Network, []string{"udp"}) {
				hasUDPReject = true
			} else {
				return errors.New("route rules contain an unreviewed reject action")
			}
		default:
			return errors.New("route rules contain an unreviewed action")
		}
	}
	if !hasNodeDirect || !hasDNSHijack || !hasUDPReject || !hasTCPTunnel {
		return errors.New("client route rules lack the reviewed node/corporate/DNS/UDP/TCP policy")
	}
	for _, cidr := range policy.CorporateCIDRs {
		if !seenCIDR[cidr] {
			return errors.New("client route omits a signed corporate CIDR")
		}
	}
	for _, server := range client.DNS.Servers {
		addr, err := netip.ParseAddr(server.Server)
		if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
			return errors.New("client DNS contains an invalid server")
		}
		switch server.Detour {
		case "direct":
			if !containsExact(policy.CorporateDNS, addr.String()) || server.Type != "udp" || server.Tag != "corp-dns" {
				return errors.New("client DNS direct server is not the reviewed corporate resolver")
			}
			seenDNS[addr.String()] = true
		case "tunnel":
			if server.Type != "https" || server.Tag != "public-dns" {
				return errors.New("client DNS tunneled server is not the reviewed public resolver")
			}
		default:
			return errors.New("client DNS server lacks an explicit reviewed detour")
		}
	}
	for _, address := range policy.CorporateDNS {
		if !seenDNS[address] {
			return errors.New("client DNS omits a signed corporate resolver")
		}
	}
	for _, rule := range client.DNS.Rules {
		if rule.Action != "route" || rule.Server != "corp-dns" || len(rule.DomainSuffix) == 0 {
			return errors.New("client DNS contains an unreviewed rule")
		}
		for _, suffix := range rule.DomainSuffix {
			matched := matchingSuffix(policy.InternalSuffixes, suffix)
			if matched == "" {
				return errors.New("client DNS contains an unreviewed corporate suffix")
			}
			seenSuffix[matched] = true
		}
	}
	for _, suffix := range policy.InternalSuffixes {
		if !seenSuffix[suffix] {
			return errors.New("client config omits a signed internal suffix")
		}
	}
	return nil
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func matchingSuffix(allowlist []string, candidate string) string {
	candidate = strings.ToLower(candidate)
	for _, allowed := range allowlist {
		if candidate == allowed || strings.HasSuffix(candidate, "."+allowed) {
			return allowed
		}
	}
	return ""
}

func CredentialDocument(clientData []byte, expiresAt string) ([]byte, error) {
	client, err := decodeSingConfig(clientData)
	if err != nil {
		return nil, fmt.Errorf("client config: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
		return nil, errors.New("credential expiration is invalid")
	}
	var tunnel *singEndpoint
	for index := range client.Outbounds {
		if client.Outbounds[index].Tag == "tunnel" && client.Outbounds[index].Type == "shadowsocks" {
			if tunnel != nil {
				return nil, errors.New("client config has ambiguous tunnel credentials")
			}
			tunnel = &client.Outbounds[index]
		}
	}
	if tunnel == nil || strings.TrimSpace(tunnel.Method) == "" || strings.TrimSpace(tunnel.Password) == "" {
		return nil, errors.New("client config lacks the locked tunnel credential")
	}
	return json.Marshal(struct {
		Method    string `json:"method"`
		Password  string `json:"password"`
		ExpiresAt string `json:"expires_at"`
	}{tunnel.Method, tunnel.Password, expiresAt})
}

func ClientTunnelEndpoint(clientData []byte) (string, error) {
	client, err := decodeSingConfig(clientData)
	if err != nil {
		return "", err
	}
	var endpoint string
	for _, outbound := range client.Outbounds {
		if outbound.Type == "shadowsocks" && outbound.Tag == "tunnel" {
			if endpoint != "" {
				return "", errors.New("client config has multiple tunnel endpoints")
			}
			if _, _, err := parseSafeEndpoint(net.JoinHostPort(outbound.Server, fmt.Sprint(outbound.ServerPort))); err != nil {
				return "", err
			}
			endpoint = net.JoinHostPort(outbound.Server, fmt.Sprint(outbound.ServerPort))
		}
	}
	if endpoint == "" {
		return "", errors.New("client config lacks the tunnel endpoint")
	}
	return endpoint, nil
}

func equalStrings(got, want []string) bool {
	return len(got) == len(want) && (len(got) == 0 || got[0] == want[0])
}

func equalInts(got, want []int) bool {
	return len(got) == len(want) && (len(got) == 0 || got[0] == want[0])
}

func rawJSONPresent(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte("[]"))
}

func prohibitedConfig(data []byte) bool {
	normalized := strings.ToLower(strings.ReplaceAll(string(data), " ", ""))
	return strings.Contains(normalized, "127.0.0.1:8080") || strings.Contains(normalized, `"server":"127.0.0.1","server_port":8080`) || strings.Contains(normalized, `"tag":"telecom"`)
}

func parseSafeEndpoint(value string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, errors.New("must be host:port")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
		return "", 0, errors.New("must use a non-loopback canonical IPv4 address")
	}
	if addr.String() != host {
		return "", 0, errors.New("address must be canonical")
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil || port < 1024 || port > 65535 {
		return "", 0, errors.New("port must be an unprivileged numeric TCP port")
	}
	if fmt.Sprint(port) != portText {
		return "", 0, errors.New("port must be canonical numeric text")
	}
	return host, uint16(port), nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data is forbidden")
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func SortedRoles() []string { values := RequiredArtifactRoles(); sort.Strings(values); return values }
