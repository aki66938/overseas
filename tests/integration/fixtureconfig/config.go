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

	"corp.example/overseas-access-gateway/tests/integration/fixtureproto"
)

var requiredArtifactRoles = []string{"action-helper", "agent", "capture-script", "core", "driver", "installer", "powershell", "sentinel", "server-service", "ui"}

type Artifact struct {
	Path          string `json:"path"`
	InstalledPath string `json:"installed_path,omitempty"`
	SHA256        string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion int                 `json:"schema_version"`
	Artifacts     map[string]Artifact `json:"artifacts"`
}

type ActionConfig struct {
	SchemaVersion       int    `json:"schema_version"`
	PowerShellPath      string `json:"powershell_path"`
	InstallerScriptPath string `json:"installer_script_path"`
	BundlePath          string `json:"bundle_path"`
	PayloadManifestPath string `json:"payload_manifest_path"`
	FixtureManifestPath string `json:"fixture_manifest_path"`
	SentinelPath        string `json:"sentinel_path"`
	ActionHelperPath    string `json:"action_helper_path"`
	FakeDataEndpoint    string `json:"fake_data_endpoint"`
	FakeControlEndpoint string `json:"fake_control_endpoint"`
	PublicDataEndpoint  string `json:"public_data_endpoint"`
	FakeIdentity        string `json:"fake_identity"`
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
	for name, path := range map[string]string{"powershell": c.PowerShellPath, "installer": c.InstallerScriptPath, "bundle": c.BundlePath, "payload manifest": c.PayloadManifestPath, "fixture manifest": c.FixtureManifestPath, "sentinel": c.SentinelPath, "action-helper": c.ActionHelperPath} {
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

func ValidateGeneratedConfigs(clientData, serverData []byte, fakeDataEndpoint string) error {
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
	if err := validateClientPolicy(client, clientTunnel); err != nil {
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

func validateClientPolicy(client singBoxConfig, tunnel singEndpoint) error {
	if client.DNS == nil || len(client.DNS.Servers) == 0 || client.DNS.Final != "public-dns" || !client.DNS.ReverseMapping {
		return errors.New("client DNS policy is absent or incomplete")
	}
	hasNodeDirect, hasDNSHijack, hasUDPReject, hasTCPTunnel := false, false, false, false
	for _, rule := range client.Route.Rules {
		switch rule.Action {
		case "route":
			if rule.Outbound == "direct" {
				if len(rule.IPCIDR) == 0 && len(rule.DomainSuffix) == 0 {
					return errors.New("direct route rule has no constrained corporate target")
				}
				for _, text := range rule.IPCIDR {
					prefix, err := netip.ParsePrefix(text)
					if err != nil || prefix.String() != text || prefix.Bits() == 0 || !prefix.Addr().IsPrivate() {
						return errors.New("route rules contain a non-corporate direct IP target")
					}
					if prefix.Bits() == 32 && prefix.Addr().String() == tunnel.Server {
						hasNodeDirect = true
					}
				}
				for _, suffix := range rule.DomainSuffix {
					if !strings.HasSuffix(strings.ToLower(suffix), "intra.regen-bio.com") {
						return errors.New("route rules contain an unreviewed direct domain suffix")
					}
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
	for _, server := range client.DNS.Servers {
		addr, err := netip.ParseAddr(server.Server)
		if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
			return errors.New("client DNS contains an invalid server")
		}
		switch server.Detour {
		case "direct":
			if !addr.IsPrivate() || server.Type != "udp" || server.Tag != "corp-dns" {
				return errors.New("client DNS direct server is not the reviewed corporate resolver")
			}
		case "tunnel":
			if server.Type != "https" || server.Tag != "public-dns" {
				return errors.New("client DNS tunneled server is not the reviewed public resolver")
			}
		default:
			return errors.New("client DNS server lacks an explicit reviewed detour")
		}
	}
	for _, rule := range client.DNS.Rules {
		if rule.Action != "route" || rule.Server != "corp-dns" || len(rule.DomainSuffix) == 0 {
			return errors.New("client DNS contains an unreviewed rule")
		}
		for _, suffix := range rule.DomainSuffix {
			if !strings.HasSuffix(strings.ToLower(suffix), "intra.regen-bio.com") {
				return errors.New("client DNS contains an unreviewed corporate suffix")
			}
		}
	}
	return nil
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
