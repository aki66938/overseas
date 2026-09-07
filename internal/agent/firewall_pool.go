//go:build windows

package agent

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const (
	windowsFirewallRuleDefinitionVersion = 2
	windowsPublicAnyRulePrefix           = "RegenBioOverseasAccess.BlockPublicAny."
)

var firewallAdapterGUIDPattern = regexp.MustCompile(`(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$`)

func buildPreparedFirewallRules(adapters []WindowsNativeAdapter, blockedPrefixes, dnsBlockedPrefixes []string) ([]WindowsPreparedRule, error) {
	blockedHash, err := hashCanonicalPrefixes(blockedPrefixes)
	if err != nil {
		return nil, fmt.Errorf("hash blocked prefixes: %w", err)
	}
	dnsHash, err := hashCanonicalPrefixes(dnsBlockedPrefixes)
	if err != nil {
		return nil, fmt.Errorf("hash DNS blocked prefixes: %w", err)
	}
	protected := make([]WindowsNativeAdapter, 0, len(adapters))
	seenGUID := make(map[string]bool, len(adapters))
	seenIndex := make(map[int]bool, len(adapters))
	for _, adapter := range adapters {
		if adapter.InterfaceIndex <= 0 || strings.TrimSpace(adapter.InterfaceAlias) == "" || !firewallAdapterGUIDPattern.MatchString(adapter.InterfaceGuid) {
			return nil, errors.New("prepared firewall adapter identity is invalid")
		}
		if adapter.InterfaceIndex == 1 || strings.EqualFold(adapter.InterfaceAlias, windowsTUNInterface) || strings.EqualFold(adapter.Status, "NotPresent") {
			continue
		}
		guid := strings.ToUpper(strings.Trim(strings.TrimSpace(adapter.InterfaceGuid), "{}"))
		if seenGUID[guid] || seenIndex[adapter.InterfaceIndex] {
			return nil, errors.New("prepared firewall adapter identity is duplicated")
		}
		seenGUID[guid] = true
		seenIndex[adapter.InterfaceIndex] = true
		adapter.InterfaceGuid = "{" + guid + "}"
		protected = append(protected, adapter)
	}
	if len(protected) == 0 {
		return nil, errors.New("prepared firewall has no protectable adapters")
	}
	sort.Slice(protected, func(i, j int) bool { return protected[i].InterfaceGuid < protected[j].InterfaceGuid })
	aliases := make([]string, 0, len(protected))
	rules := make([]WindowsPreparedRule, 0, len(protected)+3)
	for _, adapter := range protected {
		aliases = append(aliases, adapter.InterfaceAlias)
		guid := strings.Trim(adapter.InterfaceGuid, "{}")
		rules = append(rules, WindowsPreparedRule{
			Name: windowsPublicAnyRulePrefix + guid, InterfaceGuid: adapter.InterfaceGuid,
			InterfaceAlias: adapter.InterfaceAlias, Protocol: "Any", RemoteAddressesSHA: blockedHash,
		})
	}
	sort.Strings(aliases)
	rules = append(rules,
		WindowsPreparedRule{Name: windowsDNSUDPBlockRule, InterfaceAliases: append([]string(nil), aliases...), Protocol: "UDP", RemotePorts: []string{"53"}, RemoteAddressesSHA: dnsHash},
		WindowsPreparedRule{Name: windowsDNSTCPBlockRule, InterfaceAliases: append([]string(nil), aliases...), Protocol: "TCP", RemotePorts: []string{"53"}, RemoteAddressesSHA: dnsHash},
		WindowsPreparedRule{Name: windowsEmergencyBlockRule, InterfaceAliases: append([]string(nil), aliases...), Protocol: "Any", RemoteAddressesSHA: blockedHash, Emergency: true},
	)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules, nil
}

func hashCanonicalPrefixes(values []string) (string, error) {
	if len(values) == 0 {
		return "", errors.New("prefix collection is empty")
	}
	set := make(map[string]bool, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix != prefix.Masked() {
			return "", errors.New("prefix collection contains an invalid prefix")
		}
		set[prefix.String()] = true
	}
	canonical := make([]string, 0, len(set))
	for value := range set {
		canonical = append(canonical, value)
	}
	sort.Strings(canonical)
	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(payload)), nil
}

func validatePreparedFirewallOwnership(expected, actual []WindowsPreparedRule) error {
	if len(expected) == 0 || len(expected) != len(actual) {
		return errors.New("prepared firewall rule count does not match ownership ledger")
	}
	want := canonicalPreparedRules(expected)
	got := canonicalPreparedRules(actual)
	seen := make(map[string]bool, len(want))
	for _, rule := range want {
		if rule.Name == "" || seen[rule.Name] || rule.ExpectedEnabled {
			return errors.New("prepared firewall ledger is invalid")
		}
		seen[rule.Name] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errors.New("prepared firewall rule definition drifted")
	}
	return nil
}

func canonicalPreparedRules(values []WindowsPreparedRule) []WindowsPreparedRule {
	result := append([]WindowsPreparedRule(nil), values...)
	for index := range result {
		result[index].RemotePorts = append([]string(nil), result[index].RemotePorts...)
		sort.Strings(result[index].RemotePorts)
		result[index].InterfaceAliases = append([]string(nil), result[index].InterfaceAliases...)
		sort.Strings(result[index].InterfaceAliases)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
