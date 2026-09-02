package agent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestPreparedFirewallPowerShellScriptsParse(t *testing.T) {
	for operation, script := range map[string]string{
		networkOperationEmergency:       emergencyNetworkPowerShell,
		networkOperationFirewallPrepare: preparedFirewallPreparePowerShell,
		networkOperationFirewallEnable:  preparedFirewallEnablePowerShell,
		networkOperationFirewallVerify:  preparedFirewallVerifyPowerShell,
		networkOperationFirewallDisable: preparedFirewallDisablePowerShell,
		networkOperationFirewallAudit:   preparedFirewallAuditPowerShell,
	} {
		t.Run(operation, func(t *testing.T) {
			command := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", "$null=[ScriptBlock]::Create([Console]::In.ReadToEnd())")
			command.Stdin = strings.NewReader(networkPowerShellTransportPrologue + "\n" + script)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("PowerShell parse failed: %v: %s", err, output)
			}
		})
	}
}

func TestPreparedFirewallRulePlanUsesOneAnyRulePerAdapter(t *testing.T) {
	adapters := make([]WindowsNativeAdapter, 0, 7)
	for index := 0; index < 7; index++ {
		adapters = append(adapters, WindowsNativeAdapter{
			InterfaceIndex: index + 2,
			InterfaceGuid:  fmt.Sprintf("{%08X-1111-2222-3333-444444444444}", index+1),
			InterfaceAlias: fmt.Sprintf("adapter-%d", index+1),
			Status:         "Up",
		})
	}
	rules, err := buildPreparedFirewallRules(adapters, []string{"1.0.0.0/8", "2000::/3"}, []string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 10 {
		t.Fatalf("rule count=%d, want 10", len(rules))
	}
	anyCount, dnsCount, emergencyCount := 0, 0, 0
	for _, rule := range rules {
		if rule.ExpectedEnabled {
			t.Fatalf("prepared rule is enabled: %+v", rule)
		}
		switch {
		case rule.Emergency:
			emergencyCount++
		case rule.Protocol == "Any" && rule.InterfaceGuid != "":
			anyCount++
			if !strings.HasPrefix(rule.Name, windowsPublicAnyRulePrefix) {
				t.Fatalf("adapter rule name=%q", rule.Name)
			}
		case rule.Protocol == "UDP" || rule.Protocol == "TCP":
			dnsCount++
			if len(rule.RemotePorts) != 1 || rule.RemotePorts[0] != "53" {
				t.Fatalf("DNS rule=%+v", rule)
			}
		}
		if strings.Contains(rule.Name, "QUIC") || strings.Contains(rule.Name, "PublicTCP") || strings.Contains(rule.Name, "PublicUDP") {
			t.Fatalf("legacy rule survived: %q", rule.Name)
		}
	}
	if anyCount != 7 || dnsCount != 2 || emergencyCount != 1 {
		t.Fatalf("any/dns/emergency=%d/%d/%d", anyCount, dnsCount, emergencyCount)
	}
}

func TestPreparedFirewallRulePlanIsOrderIndependent(t *testing.T) {
	adapters := []WindowsNativeAdapter{
		{InterfaceIndex: 4, InterfaceGuid: "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}", InterfaceAlias: "B", Status: "Down"},
		{InterfaceIndex: 3, InterfaceGuid: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", InterfaceAlias: "A", Status: "Up"},
	}
	first, err := buildPreparedFirewallRules(adapters, []string{"2000::/3", "1.0.0.0/8"}, []string{"0.0.0.0/0", "0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	adapters[0], adapters[1] = adapters[1], adapters[0]
	second, err := buildPreparedFirewallRules(adapters, []string{"1.0.0.0/8", "2000::/3"}, []string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%#v", first) != fmt.Sprintf("%#v", second) {
		t.Fatalf("plans differ:\n%#v\n%#v", first, second)
	}
}

func TestPreparedFirewallOwnershipRejectsUnknownOrDriftedRules(t *testing.T) {
	adapters := []WindowsNativeAdapter{{InterfaceIndex: 4, InterfaceGuid: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", InterfaceAlias: "Ethernet", Status: "Up"}}
	want, err := buildPreparedFirewallRules(adapters, []string{"1.0.0.0/8"}, []string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePreparedFirewallOwnership(want, append([]WindowsPreparedRule(nil), want...)); err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]WindowsPreparedRule(nil), want...), WindowsPreparedRule{Name: "foreign", Protocol: "Any", RemoteAddressesSHA: strings.Repeat("a", 64)})
	if err := validatePreparedFirewallOwnership(want, unknown); err == nil {
		t.Fatal("unknown rule was accepted")
	}
	drifted := append([]WindowsPreparedRule(nil), want...)
	drifted[0].InterfaceAlias = "changed"
	if err := validatePreparedFirewallOwnership(want, drifted); err == nil {
		t.Fatal("drifted rule was accepted")
	}
	enabled := append([]WindowsPreparedRule(nil), want...)
	enabled[0].ExpectedEnabled = true
	if err := validatePreparedFirewallOwnership(want, enabled); err == nil {
		t.Fatal("enabled prepared rule was accepted")
	}
}

func TestPreparedFirewallRulePlanRejectsDuplicateIdentityAndOwnedTUN(t *testing.T) {
	duplicate := WindowsNativeAdapter{InterfaceIndex: 4, InterfaceGuid: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", InterfaceAlias: "Ethernet", Status: "Up"}
	if _, err := buildPreparedFirewallRules([]WindowsNativeAdapter{duplicate, duplicate}, []string{"1.0.0.0/8"}, []string{"0.0.0.0/0"}); err == nil {
		t.Fatal("duplicate adapter was accepted")
	}
	tun := duplicate
	tun.InterfaceAlias = windowsTUNInterface
	if _, err := buildPreparedFirewallRules([]WindowsNativeAdapter{tun}, []string{"1.0.0.0/8"}, []string{"0.0.0.0/0"}); err == nil {
		t.Fatal("a plan containing only the owned TUN was accepted")
	}
}

func TestWindowsNetworkPreparedFirewallOperationsUseExactRuleSets(t *testing.T) {
	runner := &fakeNetworkRunner{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	state := validPreparedFirewallState(t, manager)
	if err := manager.prepareFirewallPool(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := manager.enablePreparedFirewall(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := manager.verifyPreparedFirewall(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := manager.disablePreparedFirewall(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := manager.auditPreparedFirewall(context.Background(), state, false); err != nil {
		t.Fatal(err)
	}
	prepare := runner.inputFor(t, networkOperationFirewallPrepare)
	if prepare.PreparedGeneration != state.Generation || prepare.RuleDefinitionVersion != windowsFirewallRuleDefinitionVersion || len(prepare.PreparedRules) != len(state.Rules) {
		t.Fatalf("prepare input = %+v", prepare)
	}
	enable := runner.inputFor(t, networkOperationFirewallEnable)
	if len(enable.FirewallRuleNames) != len(state.Rules)-1 || containsString(enable.FirewallRuleNames, windowsEmergencyBlockRule) {
		t.Fatalf("enable names = %v", enable.FirewallRuleNames)
	}
	disable := runner.inputFor(t, networkOperationFirewallDisable)
	if len(disable.FirewallRuleNames) != len(state.Rules) || !containsString(disable.FirewallRuleNames, windowsEmergencyBlockRule) {
		t.Fatalf("disable names = %v", disable.FirewallRuleNames)
	}
}

func TestWindowsNetworkPreparedFirewallFailureArmsEmergency(t *testing.T) {
	runner := &fakeNetworkRunner{runErrors: map[string][]error{networkOperationFirewallPrepare: {errors.New("collision")}}}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	state := validPreparedFirewallState(t, manager)
	if err := manager.prepareFirewallPool(context.Background(), state); err == nil {
		t.Fatal("prepare succeeded")
	}
	if runner.count(networkOperationEmergency) != 1 {
		t.Fatalf("emergency calls = %d", runner.count(networkOperationEmergency))
	}
	emergency := runner.inputFor(t, networkOperationEmergency)
	if emergency.PreparedGeneration != state.Generation || emergency.RuleDefinitionVersion != state.RuleDefinitionVersion {
		t.Fatalf("emergency generation = %d/%d, want %d/%d", emergency.PreparedGeneration, emergency.RuleDefinitionVersion, state.Generation, state.RuleDefinitionVersion)
	}
	if len(emergency.PreparedRules) != len(state.Rules) {
		t.Fatalf("emergency prepared rules = %d, want %d", len(emergency.PreparedRules), len(state.Rules))
	}
}

func TestPreparedEmergencyOperationEnablesExistingDisabledRule(t *testing.T) {
	if !strings.Contains(emergencyNetworkPowerShell, "Enable-NetFirewallRule") || !strings.Contains(emergencyNetworkPowerShell, "PolicyStore PersistentStore") {
		t.Fatal("emergency operation does not enable an existing Disabled persistent rule")
	}
	for _, fragment := range []string{"$i.PreparedRules", "Get-PreparedDescription", "Assert-PreparedRule", "PreparedGeneration"} {
		if !strings.Contains(emergencyNetworkPowerShell, fragment) {
			t.Fatalf("prepared emergency operation is missing %q", fragment)
		}
	}
}

func validPreparedFirewallState(t *testing.T, manager *WindowsNetworkManager) WindowsPreparedState {
	t.Helper()
	rules, err := buildPreparedFirewallRules([]WindowsNativeAdapter{{InterfaceIndex: 4, InterfaceGuid: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", InterfaceAlias: "Ethernet", Status: "Up"}}, manager.blockedPrefixes, manager.dnsBlockedPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	return WindowsPreparedState{Generation: 2, RuleDefinitionVersion: windowsFirewallRuleDefinitionVersion, Rules: rules}
}
