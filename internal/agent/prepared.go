package agent

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const windowsPreparedStateVersion = 1

var lowercaseSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Typed boundary errors let the controller report tun_not_found only when the
// deadline truly expired without the adapter, tun_identity_mismatch when a
// candidate adapter exists but fails ownership validation, and distinguish
// runtime monitor causes without recasting them as TUN errors.
var (
	errTUNNotFound         = errors.New("fixed TUN adapter did not appear before the deadline")
	errTUNIdentityMismatch = errors.New("fixed TUN adapter identity does not match the owned definition")
	errNetworkChanged      = errors.New("network fingerprint changed while connected")
	errVPNConflict         = errors.New("a foreign VPN tunnel adapter is active")
	errFirewallAudit       = errors.New("prepared firewall audit failed")
)

type PreparedNetwork struct {
	Generation   uint64 `json:"generation"`
	Fingerprint  string `json:"fingerprint"`
	AdapterCount int    `json:"adapter_count"`
	RuleCount    int    `json:"rule_count"`
}

type WindowsNativeAdapter struct {
	InterfaceIndex int      `json:"InterfaceIndex"`
	Description    string   `json:"Description,omitempty"`
	InterfaceLUID  uint64   `json:"InterfaceLUID"`
	InterfaceGuid  string   `json:"InterfaceGuid"`
	InterfaceAlias string   `json:"InterfaceAlias"`
	Status         string   `json:"Status"`
	DNSServers     []string `json:"DNSServers,omitempty"`
	DNSAutomatic   bool     `json:"DNSAutomatic"`
}

type WindowsNativeInterface struct {
	InterfaceIndex      int    `json:"InterfaceIndex"`
	InterfaceLUID       uint64 `json:"InterfaceLUID"`
	AutomaticMetric     bool   `json:"AutomaticMetric"`
	InterfaceMetric     int    `json:"InterfaceMetric"`
	DisableDefaultRoute bool   `json:"DisableDefaultRoute"`
}

type WindowsNativeRoute struct {
	DestinationPrefix string `json:"DestinationPrefix"`
	InterfaceIndex    int    `json:"InterfaceIndex"`
	InterfaceLUID     uint64 `json:"InterfaceLUID"`
	NextHop           string `json:"NextHop"`
	RouteMetric       int    `json:"RouteMetric"`
	Protocol          int    `json:"Protocol"`
}

type WindowsNetworkBaseline struct {
	Adapters   []WindowsNativeAdapter     `json:"Adapters"`
	Interfaces []WindowsNativeInterface   `json:"Interfaces"`
	Routes     []WindowsNativeRoute       `json:"Routes"`
	NodeRoutes []WindowsNodeRouteSnapshot `json:"NodeRoutes"`
}

type WindowsPreparedRule struct {
	Name               string   `json:"Name"`
	InterfaceGuid      string   `json:"InterfaceGuid,omitempty"`
	InterfaceAlias     string   `json:"InterfaceAlias,omitempty"`
	InterfaceAliases   []string `json:"InterfaceAliases,omitempty"`
	Protocol           string   `json:"Protocol"`
	RemotePorts        []string `json:"RemotePorts,omitempty"`
	RemoteAddressesSHA string   `json:"RemoteAddressesSHA"`
	Emergency          bool     `json:"Emergency"`
	ExpectedEnabled    bool     `json:"ExpectedEnabled"`
}

type WindowsPreparedState struct {
	Version                   int                    `json:"Version"`
	Generation                uint64                 `json:"Generation"`
	AdapterCount              int                    `json:"AdapterCount,omitempty"`
	PolicySHA256              string                 `json:"PolicySHA256"`
	RuleDefinitionVersion     int                    `json:"RuleDefinitionVersion"`
	FingerprintSHA256         string                 `json:"FingerprintSHA256"`
	Baseline                  WindowsNetworkBaseline `json:"Baseline"`
	BlockedRemoteAddresses    []string               `json:"BlockedRemoteAddresses"`
	DNSBlockedRemoteAddresses []string               `json:"DNSBlockedRemoteAddresses"`
	Rules                     []WindowsPreparedRule  `json:"Rules"`
	IntegritySHA256           string                 `json:"IntegritySHA256"`
}

// foreignTunnelAdapter reports whether an adapter belongs to a third-party
// tunnel (Clash-family TUN, iKuuu/Sakura VPN, wintun/tap users). Only the
// product's own tun and physical adapters take part in the rule pool.
func foreignTunnelAdapter(adapter WindowsNativeAdapter) bool {
	if strings.EqualFold(adapter.InterfaceAlias, windowsTUNInterface) {
		return false
	}
	description := strings.ToLower(adapter.Description)
	for _, marker := range []string{"wintun", "tap-", "tun2socks", "sing-box", "clash", "meta", "ikuuu", "sakura", "vpn"} {
		if strings.Contains(description, marker) {
			return true
		}
	}
	return false
}

func validatePreparedNetwork(prepared PreparedNetwork) error {
	if prepared.Generation == 0 {
		return errors.New("prepared generation is required")
	}
	if !lowercaseSHA256Pattern.MatchString(prepared.Fingerprint) {
		return errors.New("prepared fingerprint must be lowercase SHA-256")
	}
	if prepared.AdapterCount <= 0 {
		return errors.New("prepared adapter count must be positive")
	}
	// RuleCount may be zero in the PoC fast path: no firewall pool.
	return nil
}

func sealWindowsPreparedState(state *WindowsPreparedState) error {
	if state == nil {
		return errors.New("prepared state is required")
	}
	canonicalizeWindowsPreparedState(state)
	state.IntegritySHA256 = ""
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal prepared state: %w", err)
	}
	state.IntegritySHA256 = fmt.Sprintf("%x", sha256.Sum256(payload))
	return nil
}

func validateWindowsPreparedState(state WindowsPreparedState) error {
	want := state.IntegritySHA256
	if !lowercaseSHA256Pattern.MatchString(want) {
		return errors.New("prepared state integrity is invalid")
	}
	copyState := state
	if err := sealWindowsPreparedState(&copyState); err != nil {
		return err
	}
	if copyState.IntegritySHA256 != want {
		return errors.New("prepared state integrity mismatch")
	}
	if state.Version != windowsPreparedStateVersion || state.Generation == 0 || state.RuleDefinitionVersion <= 0 {
		return errors.New("prepared state version or generation is invalid")
	}
	if !lowercaseSHA256Pattern.MatchString(state.PolicySHA256) || !lowercaseSHA256Pattern.MatchString(state.FingerprintSHA256) {
		return errors.New("prepared state hashes are invalid")
	}
	if len(state.Baseline.Adapters) == 0 || len(state.Rules) == 0 || len(state.BlockedRemoteAddresses) == 0 || len(state.DNSBlockedRemoteAddresses) == 0 {
		return errors.New("prepared baseline and rules are required")
	}
	blockedHash, err := hashCanonicalPrefixes(state.BlockedRemoteAddresses)
	if err != nil {
		return errors.New("prepared blocked prefix set is invalid")
	}
	dnsHash, err := hashCanonicalPrefixes(state.DNSBlockedRemoteAddresses)
	if err != nil {
		return errors.New("prepared DNS prefix set is invalid")
	}
	seen := make(map[string]bool, len(state.Rules))
	for _, rule := range state.Rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" || seen[name] {
			return errors.New("prepared rule names must be unique")
		}
		seen[name] = true
		if strings.TrimSpace(rule.Protocol) == "" || !lowercaseSHA256Pattern.MatchString(rule.RemoteAddressesSHA) {
			return errors.New("prepared rule definition is invalid")
		}
		expectedHash := dnsHash
		if rule.Emergency || rule.Protocol == "Any" {
			expectedHash = blockedHash
		}
		if rule.RemoteAddressesSHA != expectedHash {
			return errors.New("prepared rule address hash does not match its sealed prefix set")
		}
	}
	return nil
}

func canonicalizeWindowsPreparedState(state *WindowsPreparedState) {
	state.BlockedRemoteAddresses = append([]string(nil), state.BlockedRemoteAddresses...)
	sort.Strings(state.BlockedRemoteAddresses)
	state.DNSBlockedRemoteAddresses = append([]string(nil), state.DNSBlockedRemoteAddresses...)
	sort.Strings(state.DNSBlockedRemoteAddresses)
	state.Baseline.Adapters = append([]WindowsNativeAdapter(nil), state.Baseline.Adapters...)
	for index := range state.Baseline.Adapters {
		state.Baseline.Adapters[index].DNSServers = append([]string(nil), state.Baseline.Adapters[index].DNSServers...)
		sort.Strings(state.Baseline.Adapters[index].DNSServers)
	}
	sort.Slice(state.Baseline.Adapters, func(i, j int) bool {
		return state.Baseline.Adapters[i].InterfaceGuid < state.Baseline.Adapters[j].InterfaceGuid
	})
	state.Baseline.Interfaces = append([]WindowsNativeInterface(nil), state.Baseline.Interfaces...)
	sort.Slice(state.Baseline.Interfaces, func(i, j int) bool {
		return state.Baseline.Interfaces[i].InterfaceIndex < state.Baseline.Interfaces[j].InterfaceIndex
	})
	state.Baseline.Routes = append([]WindowsNativeRoute(nil), state.Baseline.Routes...)
	sort.Slice(state.Baseline.Routes, func(i, j int) bool {
		left, right := state.Baseline.Routes[i], state.Baseline.Routes[j]
		if left.DestinationPrefix != right.DestinationPrefix {
			return left.DestinationPrefix < right.DestinationPrefix
		}
		if left.InterfaceIndex != right.InterfaceIndex {
			return left.InterfaceIndex < right.InterfaceIndex
		}
		return left.NextHop < right.NextHop
	})
	state.Baseline.NodeRoutes = append([]WindowsNodeRouteSnapshot(nil), state.Baseline.NodeRoutes...)
	sort.Slice(state.Baseline.NodeRoutes, func(i, j int) bool {
		return state.Baseline.NodeRoutes[i].NodeAddress < state.Baseline.NodeRoutes[j].NodeAddress
	})
	state.Rules = append([]WindowsPreparedRule(nil), state.Rules...)
	for index := range state.Rules {
		state.Rules[index].RemotePorts = append([]string(nil), state.Rules[index].RemotePorts...)
		sort.Strings(state.Rules[index].RemotePorts)
		state.Rules[index].InterfaceAliases = append([]string(nil), state.Rules[index].InterfaceAliases...)
		sort.Strings(state.Rules[index].InterfaceAliases)
	}
	sort.Slice(state.Rules, func(i, j int) bool { return state.Rules[i].Name < state.Rules[j].Name })
}
