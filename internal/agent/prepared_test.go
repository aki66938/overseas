//go:build windows

package agent

import (
	"strings"
	"testing"
)

func TestPreparedNetworkJSONContract(t *testing.T) {
	prepared := PreparedNetwork{Generation: 4, Fingerprint: strings.Repeat("a", 64), AdapterCount: 7, RuleCount: 10}
	if err := validatePreparedNetwork(prepared); err != nil {
		t.Fatalf("validatePreparedNetwork() error = %v", err)
	}
	for _, invalid := range []PreparedNetwork{
		{},
		{Generation: 1, Fingerprint: "ABC", AdapterCount: 1, RuleCount: 4},
		{Generation: 1, Fingerprint: strings.Repeat("a", 64), AdapterCount: 0, RuleCount: 3},
		{Generation: 1, Fingerprint: strings.Repeat("a", 64), AdapterCount: 1, RuleCount: 0},
	} {
		if err := validatePreparedNetwork(invalid); err == nil {
			t.Fatalf("validatePreparedNetwork(%+v) succeeded", invalid)
		}
	}
}

func TestPreparedStateSealRejectsTampering(t *testing.T) {
	blocked := []string{"1.0.0.0/8"}
	blockedHash, err := hashCanonicalPrefixes(blocked)
	if err != nil {
		t.Fatal(err)
	}
	state := WindowsPreparedState{
		Version:               1,
		Generation:            2,
		PolicySHA256:          strings.Repeat("b", 64),
		RuleDefinitionVersion: 2,
		FingerprintSHA256:     strings.Repeat("c", 64),
		Baseline: WindowsNetworkBaseline{
			Adapters: []WindowsNativeAdapter{{InterfaceIndex: 4, InterfaceGuid: "{11111111-1111-1111-1111-111111111111}", InterfaceAlias: "Ethernet", Status: "Up"}},
		},
		BlockedRemoteAddresses: blocked, DNSBlockedRemoteAddresses: []string{"0.0.0.0/0"},
		Rules: []WindowsPreparedRule{{Name: "RegenBioOverseasAccess.BlockPublicAny.11111111-1111-1111-1111-111111111111", InterfaceGuid: "{11111111-1111-1111-1111-111111111111}", InterfaceAlias: "Ethernet", Protocol: "Any", RemoteAddressesSHA: blockedHash}},
	}
	if err := sealWindowsPreparedState(&state); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsPreparedState(state); err != nil {
		t.Fatalf("validateWindowsPreparedState() error = %v", err)
	}
	state.Rules[0].Protocol = "TCP"
	if err := validateWindowsPreparedState(state); err == nil {
		t.Fatal("tampered prepared state was accepted")
	}
}

func TestPreparedStateRejectsDuplicateRulesAndInvalidGeneration(t *testing.T) {
	blocked := []string{"1.0.0.0/8"}
	blockedHash, err := hashCanonicalPrefixes(blocked)
	if err != nil {
		t.Fatal(err)
	}
	rule := WindowsPreparedRule{Name: "owned", Protocol: "Any", RemoteAddressesSHA: blockedHash}
	state := WindowsPreparedState{
		Version: 1, Generation: 1, PolicySHA256: strings.Repeat("a", 64), RuleDefinitionVersion: 2,
		FingerprintSHA256: strings.Repeat("b", 64), Baseline: WindowsNetworkBaseline{Adapters: []WindowsNativeAdapter{{InterfaceIndex: 4, InterfaceGuid: "g", InterfaceAlias: "Ethernet", Status: "Up"}}},
		BlockedRemoteAddresses: blocked, DNSBlockedRemoteAddresses: []string{"0.0.0.0/0"},
		Rules: []WindowsPreparedRule{rule, rule},
	}
	if err := sealWindowsPreparedState(&state); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsPreparedState(state); err == nil {
		t.Fatal("duplicate prepared rule names were accepted")
	}
	state.Generation = 0
	if err := sealWindowsPreparedState(&state); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsPreparedState(state); err == nil {
		t.Fatal("zero prepared generation was accepted")
	}
}
