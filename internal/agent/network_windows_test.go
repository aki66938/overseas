//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
)

func TestWindowsNetworkCapturePersistsExactStateBeforeMutation(t *testing.T) {
	trace := &callTrace{}
	runner := &fakeNetworkRunner{trace: trace, capture: validWindowsSnapshot()}
	store := &fakeSnapshotStore{trace: trace}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := manager.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.InstallPublicTCPBlock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Restore(context.Background(), snapshot) })

	if snapshot == nil || !store.exists {
		t.Fatal("captured network state was not persisted")
	}
	if got, want := trace.calls(), []string{"capture", "save", "guard", "scan", "block"}; !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}
	block := runner.inputFor(t, networkOperationBlock)
	if len(block.Interfaces) != 1 || block.Interfaces[0].Index != 7 {
		t.Fatalf("block interfaces = %#v", block.Interfaces)
	}
	assertAddressCovered(t, block.BlockedRemoteAddresses, netip.MustParseAddr("8.8.8.8"), true)
	assertAddressCovered(t, block.BlockedRemoteAddresses, netip.MustParseAddr("172.20.9.15"), false)
	assertAddressCovered(t, block.BlockedRemoteAddresses, netip.MustParseAddr("192.168.1.1"), false)
}

func TestWindowsNetworkActivateUsesFixedTUNRoutesAndDNS(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}

	input := runner.inputFor(t, networkOperationActivate)
	if input.TUNInterface != windowsTUNInterface || input.TUNDNS != windowsTUNDNS {
		t.Fatalf("TUN input = interface %q DNS %q", input.TUNInterface, input.TUNDNS)
	}
	if input.OwnedTUN == nil || input.OwnedTUN.InterfaceGuid != "new-tun-guid" || len(input.OwnedRoutes) == 0 {
		t.Fatalf("owned TUN activation input = %#v", input)
	}
	assertOwnedRouteCovers(t, input.OwnedRoutes, netip.MustParseAddr("8.8.8.8"), windowsOwnedRouteMetric, validTUNIdentity().InterfaceIndex)
}

func TestWindowsNetworkRestoreDeletesSnapshotOnlyAfterSuccess(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), restoreErrors: []error{errors.New("restore failed"), nil}}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.Restore(context.Background(), snapshot); err == nil {
		t.Fatal("first Restore() succeeded")
	}
	if !store.exists {
		t.Fatal("failed restore deleted the persisted snapshot")
	}
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatalf("second Restore() = %v", err)
	}
	if store.exists {
		t.Fatal("successful restore retained the persisted snapshot")
	}
}

func TestWindowsNetworkReconcileIsIdempotentAcrossServiceRestart(t *testing.T) {
	snapshot := validWindowsSnapshot()
	runner := &fakeNetworkRunner{}
	store := &fakeSnapshotStore{exists: true, snapshot: snapshot}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := runner.count(networkOperationRestore); got != 1 {
		t.Fatalf("restore operations = %d, want 1", got)
	}
}

func TestWindowsNetworkRejectsExistingOwnedFirewallRulesBeforeCapture(t *testing.T) {
	snapshot := validWindowsSnapshot()
	snapshot.OwnedFirewallRulesPresent = []string{windowsTCPBlockRule}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{capture: snapshot}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Capture(context.Background()); err == nil {
		t.Fatal("Capture() accepted a colliding firewall rule")
	}
}

func TestWindowsNetworkPublicBlockExemptsCorporateDNSAddresses(t *testing.T) {
	policy := validPolicy()
	policy.CorporateDNS = []string{"8.8.8.8"}
	manager, err := newWindowsNetworkManager(policy, `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}

	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("8.8.8.8"), false)
}

func TestWindowsNetworkBlocksPublicIPv6AndRetainsLocalIPv6(t *testing.T) {
	policy := validPolicy()
	policy.CorporateCIDRs = append(policy.CorporateCIDRs, "2606:4700:4700::/48")
	manager, err := newWindowsNetworkManager(policy, `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}

	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("2001:4860:4860::8888"), true)
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("2606:4700:4700::1111"), false)
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("::1"), false)
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("fe80::1"), false)
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("fd00::1"), false)
}

func TestWindowsNetworkInstallsPersistentGuardBeforeAdapterFirewall(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.InstallPublicTCPBlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Restore(context.Background(), store.snapshot) })

	guard := runner.inputFor(t, networkOperationGuard)
	if len(guard.GuardRoutes) == 0 {
		t.Fatal("persistent public route guard was not installed")
	}
	assertOwnedRouteCovers(t, guard.GuardRoutes, netip.MustParseAddr("8.8.8.8"), windowsGuardRouteMetric, 1)
	assertOwnedRouteCovers(t, guard.GuardRoutes, netip.MustParseAddr("2001:4860:4860::8888"), windowsGuardRouteMetric, 1)
	if firstIndex(runner.operations, networkOperationGuard) > firstIndex(runner.operations, networkOperationBlock) {
		t.Fatalf("guard was installed after adapter firewall: %v", runner.operations)
	}
	if len(store.snapshot.GuardRoutes) != len(guard.GuardRoutes) {
		t.Fatalf("guard routes were not persisted before mutation: snapshot=%d guard=%d", len(store.snapshot.GuardRoutes), len(guard.GuardRoutes))
	}
}

func TestWindowsNetworkGuardBeatsNewDefaultAndRASForUnconstrainedLookupWithoutReconciliation(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.InstallPublicTCPBlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Restore(context.Background(), validWindowsSnapshot()) })

	// No scan/reconciliation is performed after these ordinary new /0 paths
	// appear. For an unconstrained lookup, longest-prefix routing must select
	// the owned sink guard. This does not model Windows strong-host source-bound
	// lookup, which is an explicitly documented integration boundary.
	guard := runner.inputFor(t, networkOperationGuard).GuardRoutes
	for _, address := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		matched := mostSpecificOwnedRoute(guard, netip.MustParseAddr(address))
		if matched == nil || netip.MustParsePrefix(matched.DestinationPrefix).Bits() == 0 {
			t.Fatalf("new default/RAS route can beat guard for %s: %#v", address, matched)
		}
	}
	if got := runner.count(networkOperationScan); got != 1 {
		t.Fatalf("test unexpectedly relied on reconciliation: scans=%d", got)
	}
}

func TestWindowsNetworkHealthyTUNRoutesBeatGuardAtSamePrefixes(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), ready: validTUNIdentity()}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.InstallPublicTCPBlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Restore(context.Background(), validWindowsSnapshot()) })

	guard := runner.inputFor(t, networkOperationGuard).GuardRoutes
	active := runner.inputFor(t, networkOperationActivate).OwnedRoutes
	for _, sink := range guard {
		prefix := netip.MustParsePrefix(sink.DestinationPrefix)
		if !prefix.Addr().Is4() {
			continue
		}
		found := false
		for _, route := range active {
			if route.DestinationPrefix == sink.DestinationPrefix && route.InterfaceIndex == validTUNIdentity().InterfaceIndex && route.RouteMetric < sink.RouteMetric {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no strictly preferred TUN route for guard %#v", sink)
		}
	}
}

func TestWindowsNetworkRestoreFailureRearmsEmergencyAndMonitor(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), runErrors: map[string][]error{networkOperationRestore: {errors.New("partial firewall removal")}}}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	manager.protectionInterval = time.Millisecond
	snapshot, err := manager.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.InstallPublicTCPBlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), snapshot); err == nil {
		t.Fatal("Restore() succeeded after partial removal")
	}
	if !store.exists || runner.count(networkOperationEmergency) == 0 {
		t.Fatalf("failed restore did not retain snapshot/emergency: exists=%v emergency=%d", store.exists, runner.count(networkOperationEmergency))
	}
	if !strings.Contains(restoreNetworkPowerShell, "catch") || !strings.Contains(restoreNetworkPowerShell, "Install-Emergency") {
		t.Fatal("restore script cannot re-arm emergency protection inside a partial-removal failure")
	}
	want := runner.count(networkOperationEmergency) + 1
	waitForNetworkOperationCount(t, runner, networkOperationEmergency, want)
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatalf("retry Restore() = %v", err)
	}
}

func TestWindowsNetworkReconcileFailureRearmsEmergencyAndMonitor(t *testing.T) {
	runner := &fakeNetworkRunner{runErrors: map[string][]error{networkOperationRestore: {errors.New("restore failed")}}}
	store := &fakeSnapshotStore{exists: true, snapshot: validWindowsSnapshot()}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	manager.protectionInterval = time.Millisecond
	if err := manager.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile() succeeded after restore failure")
	}
	if !store.exists || runner.count(networkOperationEmergency) == 0 {
		t.Fatalf("failed reconcile did not retain snapshot/emergency: exists=%v emergency=%d", store.exists, runner.count(networkOperationEmergency))
	}
	want := runner.count(networkOperationEmergency) + 1
	waitForNetworkOperationCount(t, runner, networkOperationEmergency, want)
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("retry Reconcile() = %v", err)
	}
}

func TestWindowsNetworkReconcileValidationFailureRearmsEmergencyAndMonitor(t *testing.T) {
	corrupt := validWindowsSnapshot()
	corrupt.Version = 0
	runner := &fakeNetworkRunner{}
	store := &fakeSnapshotStore{exists: true, snapshot: corrupt}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	manager.protectionInterval = time.Millisecond
	if err := manager.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile() accepted corrupt persisted state")
	}
	if !store.exists || runner.count(networkOperationEmergency) == 0 {
		t.Fatalf("validation failure did not retain snapshot/emergency: exists=%v emergency=%d", store.exists, runner.count(networkOperationEmergency))
	}
	want := runner.count(networkOperationEmergency) + 1
	waitForNetworkOperationCount(t, runner, networkOperationEmergency, want)
	manager.stopProtection()
}

func TestWindowsNetworkProtectionCoversRASAndHotPluggedAdaptersByIdentity(t *testing.T) {
	runner := &fakeNetworkRunner{
		capture: validWindowsSnapshot(),
		scans: [][]WindowsAdapterIdentity{
			{{InterfaceIndex: 7, InterfaceGuid: "ethernet-guid", InterfaceAlias: "Ethernet", Status: "Up"}},
			{
				{InterfaceIndex: 7, InterfaceGuid: "ethernet-guid", InterfaceAlias: "Ethernet", Status: "Up"},
				{InterfaceIndex: 22, InterfaceGuid: "ras-guid", InterfaceAlias: "Company RAS", Status: "Up"},
			},
		},
	}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	manager.protectionInterval = time.Millisecond
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.InstallPublicTCPBlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Restore(context.Background(), validWindowsSnapshot()) })
	waitForNetworkOperationCount(t, runner, networkOperationBlock, 2)

	input := runner.lastInputFor(t, networkOperationBlock)
	if len(input.ProtectedAdapters) != 2 || input.ProtectedAdapters[1].InterfaceGuid != "ras-guid" {
		t.Fatalf("protected adapters = %#v", input.ProtectedAdapters)
	}
	if strings.Contains(blockNetworkPowerShell, "-InterfaceType") || !strings.Contains(blockNetworkPowerShell, "-InterfaceAlias") {
		t.Fatal("firewall script does not scope rules to reconciled adapter identities")
	}
	if !strings.Contains(blockNetworkPowerShell, "Firewall rule name collision") || !strings.Contains(blockNetworkPowerShell, "Get-NetFirewallInterfaceFilter") {
		t.Fatal("firewall reconciliation does not reject foreign names or refresh changed adapter aliases")
	}
	if !strings.Contains(scanNetworkPowerShell, "ConvertTo-Json -InputObject $adapters") {
		t.Fatal("single-adapter scans are not encoded as a JSON array")
	}
}

func TestWindowsNetworkProtectionExplicitlyExcludesOnlyOwnedTUNIdentity(t *testing.T) {
	runner := &fakeNetworkRunner{
		capture: validWindowsSnapshot(),
		ready:   validTUNIdentity(),
		scans: [][]WindowsAdapterIdentity{
			{{InterfaceIndex: 7, InterfaceGuid: "ethernet-guid", InterfaceAlias: "Ethernet", Status: "Up"}},
			{
				{InterfaceIndex: 7, InterfaceGuid: "ethernet-guid", InterfaceAlias: "Ethernet", Status: "Up"},
				{InterfaceIndex: 41, InterfaceGuid: "new-tun-guid", InterfaceAlias: windowsTUNInterface, Status: "Up"},
			},
		},
	}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.InstallPublicTCPBlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Restore(context.Background(), validWindowsSnapshot()) })

	input := runner.lastInputFor(t, networkOperationBlock)
	if len(input.ProtectedAdapters) != 1 || input.ProtectedAdapters[0].InterfaceGuid != "ethernet-guid" {
		t.Fatalf("owned TUN was not exactly excluded: %#v", input.ProtectedAdapters)
	}
}

func TestWindowsNetworkDNSProtectionBlocksSecondaryPrivateAndPublicResolvers(t *testing.T) {
	policy := validPolicy()
	policy.CorporateDNS = []string{"172.20.9.1", "172.20.9.2"}
	manager, err := newWindowsNetworkManager(policy, `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}

	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("192.168.50.53"), true)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("8.8.8.8"), true)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("fd00::53"), true)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("172.20.9.1"), false)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("172.19.0.2"), false)
	if !strings.Contains(blockNetworkPowerShell, "-RemotePort 53") || !strings.Contains(blockNetworkPowerShell, "$i.DNSBlockedRemoteAddresses") {
		t.Fatal("dedicated all-destination DNS egress rules are missing")
	}
}

func TestWindowsNetworkReconciliationFailureInstallsCatchAllEmergencyBlock(t *testing.T) {
	runner := &fakeNetworkRunner{
		capture:   validWindowsSnapshot(),
		runErrors: map[string][]error{networkOperationScan: {errors.New("adapter scan failed")}},
	}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.InstallPublicTCPBlock(context.Background()); err == nil {
		t.Fatal("InstallPublicTCPBlock() succeeded after adapter reconciliation failure")
	}
	if got := runner.count(networkOperationEmergency); got != 1 {
		t.Fatalf("emergency operations = %d, want 1", got)
	}
	input := runner.lastInputFor(t, networkOperationEmergency)
	assertAddressCovered(t, input.BlockedRemoteAddresses, netip.MustParseAddr("8.8.8.8"), true)
	if !strings.Contains(emergencyNetworkPowerShell, "Firewall rule name collision") {
		t.Fatal("emergency protection can adopt a foreign colliding rule")
	}
}

func TestWindowsNetworkRestoreCancellationDoesNotLeakStaleMonitorFailure(t *testing.T) {
	runner := &fakeNetworkRunner{
		capture:        validWindowsSnapshot(),
		blockScanAfter: 2,
		scanStarted:    make(chan struct{}),
	}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	manager.protectionInterval = time.Millisecond
	snapshot, err := manager.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	failures, err := manager.InstallPublicTCPBlock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.scanStarted:
	case <-time.After(time.Second):
		t.Fatal("protection monitor did not enter its scan")
	}
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failures:
		t.Fatalf("normal monitor cancellation leaked failure: %v", err)
	default:
	}
}

func TestWindowsNetworkNewProtectionGenerationDropsOldFailure(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	oldFailures, err := manager.InstallPublicTCPBlock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot, err = manager.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	failures, err := manager.InstallPublicTCPBlock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Restore(context.Background(), snapshot) })
	if oldFailures == failures {
		t.Fatal("protection generations reused one terminal channel")
	}
	select {
	case err := <-failures:
		t.Fatalf("new protection generation retained old failure: %v", err)
	default:
	}
}

func TestWindowsNetworkUsesCapturedBestRouteForEveryNodeBypass(t *testing.T) {
	policy := validPolicy()
	policy.Nodes = append(policy.Nodes, accessmodel.Node{ID: "second", Address: "8.8.4.4", Port: 8443, Priority: 2})
	snapshot := validWindowsSnapshot()
	snapshot.NodeRoutes = []WindowsNodeRouteSnapshot{
		{NodeAddress: "172.20.9.15", DestinationPrefix: "172.20.8.0/22", InterfaceIndex: 7, NextHop: "0.0.0.0", RouteMetric: 20, InterfaceMetric: 25, EffectiveMetric: 45, BypassRequired: false},
		{NodeAddress: "8.8.4.4", DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 12, NextHop: "192.0.2.1", RouteMetric: 7, InterfaceMetric: 11, EffectiveMetric: 18, BypassRequired: true},
	}
	runner := &fakeNetworkRunner{capture: snapshot, ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(policy, `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("8.8.4.4"), false)

	input := runner.inputFor(t, networkOperationActivate)
	var bypass *WindowsOwnedRoute
	for index := range input.OwnedRoutes {
		if input.OwnedRoutes[index].DestinationPrefix == "8.8.4.4/32" {
			bypass = &input.OwnedRoutes[index]
		}
		if input.OwnedRoutes[index].DestinationPrefix == "172.20.9.15/32" {
			t.Fatal("created unnecessary bypass despite more-specific on-link route")
		}
	}
	if bypass == nil || bypass.InterfaceIndex != 12 || bypass.NextHop != "192.0.2.1" || bypass.RouteMetric != 7 {
		t.Fatalf("captured best-route bypass = %#v", bypass)
	}
}

func TestWindowsNetworkRestoreCarriesFullOwnedRouteTuples(t *testing.T) {
	snapshot := validWindowsSnapshot()
	snapshot.NodeRoutes = []WindowsNodeRouteSnapshot{{
		NodeAddress: "172.20.9.15", DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7,
		NextHop: "172.20.10.1", RouteMetric: 13, InterfaceMetric: 25, EffectiveMetric: 38, BypassRequired: true,
	}}
	runner := &fakeNetworkRunner{capture: snapshot, ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := manager.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), captured); err != nil {
		t.Fatal(err)
	}

	input := runner.inputFor(t, networkOperationRestore)
	if len(input.OwnedRoutes) < 2 || len(input.GuardRoutes) == 0 {
		t.Fatalf("owned/guard routes were not carried: owned=%d guard=%d", len(input.OwnedRoutes), len(input.GuardRoutes))
	}
	for _, route := range input.OwnedRoutes {
		if route.DestinationPrefix == "" || route.InterfaceIndex <= 0 || route.NextHop == "" {
			t.Fatalf("incomplete owned route tuple: %#v", route)
		}
		if route.DestinationPrefix == "172.20.9.15/32" && route.RouteMetric != 13 {
			t.Fatalf("bypass did not preserve captured route metric: %#v", route)
		}
	}
	if !strings.Contains(restoreNetworkPowerShell, "$_.InterfaceIndex -eq") || !strings.Contains(restoreNetworkPowerShell, "$_.NextHop -eq") {
		t.Fatal("restore script does not match the full owned route tuple")
	}
}

func TestWindowsNetworkRejectsPreexistingTUNAlias(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*WindowsNetworkSnapshot)
	}{
		{name: "alias", mutate: func(snapshot *WindowsNetworkSnapshot) { snapshot.TUNAliasPresent = true }},
		{name: "address", mutate: func(snapshot *WindowsNetworkSnapshot) { snapshot.TUNAddressPresent = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := validWindowsSnapshot()
			test.mutate(&snapshot)
			manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{capture: snapshot}, &fakeSnapshotStore{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Capture(context.Background()); err == nil {
				t.Fatal("Capture() accepted a preexisting fixed TUN identity collision")
			}
		})
	}
}

func TestWindowsNetworkReadinessRejectsUnownedOrMalformedTUN(t *testing.T) {
	tests := []struct {
		name     string
		identity WindowsTUNIdentity
	}{
		{name: "preexisting guid", identity: func() WindowsTUNIdentity {
			value := validTUNIdentity()
			value.InterfaceGuid = "baseline-guid"
			return value
		}()},
		{name: "wrong description", identity: func() WindowsTUNIdentity {
			value := validTUNIdentity()
			value.InterfaceDescription = "Ethernet Adapter"
			return value
		}()},
		{name: "hardware adapter", identity: func() WindowsTUNIdentity { value := validTUNIdentity(); value.HardwareInterface = true; return value }()},
		{name: "wrong address", identity: func() WindowsTUNIdentity {
			value := validTUNIdentity()
			value.Addresses = []string{"172.19.0.5/30"}
			return value
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := validWindowsSnapshot()
			snapshot.BaselineAdapterGuids = []string{"baseline-guid"}
			manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{capture: snapshot, ready: test.identity}, &fakeSnapshotStore{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Capture(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := manager.WaitTUNReady(context.Background()); err == nil {
				t.Fatal("WaitTUNReady() accepted an unowned or malformed adapter")
			}
		})
	}
}

func validWindowsSnapshot() WindowsNetworkSnapshot {
	return WindowsNetworkSnapshot{
		Version: 1,
		Interfaces: []WindowsInterfaceSnapshot{{
			Index:           7,
			Alias:           "Ethernet",
			InterfaceMetric: 25,
			AutomaticMetric: true,
			DNSAutomatic:    true,
			DNSServers:      []string{"172.20.9.1", "172.20.9.2"},
		}},
		RouteMetric:          windowsOwnedRouteMetric,
		GuardInterfaceIndex:  1,
		BaselineAdapterGuids: []string{"baseline-guid"},
		NodeRoutes: []WindowsNodeRouteSnapshot{{
			NodeAddress: "172.20.9.15", DestinationPrefix: "172.20.8.0/22", InterfaceIndex: 7,
			NextHop: "0.0.0.0", RouteMetric: 20, InterfaceMetric: 25, EffectiveMetric: 45,
		}},
	}
}

func validTUNIdentity() WindowsTUNIdentity {
	return WindowsTUNIdentity{
		InterfaceIndex:       41,
		InterfaceGuid:        "new-tun-guid",
		InterfaceAlias:       windowsTUNInterface,
		InterfaceDescription: "Wintun Userspace Tunnel",
		HardwareInterface:    false,
		Virtual:              true,
		Addresses:            []string{"172.19.0.1/30"},
	}
}

func assertAddressCovered(t *testing.T, prefixes []string, address netip.Addr, want bool) {
	t.Helper()
	covered := false
	for _, value := range prefixes {
		if netip.MustParsePrefix(value).Contains(address) {
			covered = true
			break
		}
	}
	if covered != want {
		t.Fatalf("address %s covered = %v, want %v (prefixes=%v)", address, covered, want, prefixes)
	}
}

func assertOwnedRouteCovers(t *testing.T, routes []WindowsOwnedRoute, address netip.Addr, metric, interfaceIndex int) {
	t.Helper()
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.DestinationPrefix)
		if err == nil && prefix.Contains(address) && route.RouteMetric == metric && route.InterfaceIndex == interfaceIndex {
			return
		}
	}
	t.Fatalf("no owned route covers %s with metric=%d interface=%d: %#v", address, metric, interfaceIndex, routes)
}

func mostSpecificOwnedRoute(routes []WindowsOwnedRoute, address netip.Addr) *WindowsOwnedRoute {
	var best *WindowsOwnedRoute
	for index := range routes {
		prefix, err := netip.ParsePrefix(routes[index].DestinationPrefix)
		if err != nil || !prefix.Contains(address) {
			continue
		}
		if best == nil || prefix.Bits() > netip.MustParsePrefix(best.DestinationPrefix).Bits() {
			best = &routes[index]
		}
	}
	return best
}

func firstIndex(values []string, target string) int {
	for index, value := range values {
		if value == target {
			return index
		}
	}
	return len(values)
}

type fakeNetworkRunner struct {
	trace          *callTrace
	capture        WindowsNetworkSnapshot
	ready          WindowsTUNIdentity
	operations     []string
	inputs         map[string][]byte
	restoreErrors  []error
	scans          [][]WindowsAdapterIdentity
	inputHistory   map[string][][]byte
	mu             sync.Mutex
	runErrors      map[string][]error
	blockScanAfter int
	scanCalls      int
	scanStarted    chan struct{}
	scanStartOnce  sync.Once
}

func (f *fakeNetworkRunner) Run(ctx context.Context, operation string, input []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operations = append(f.operations, operation)
	if f.inputs == nil {
		f.inputs = make(map[string][]byte)
	}
	f.inputs[operation] = append([]byte(nil), input...)
	if f.inputHistory == nil {
		f.inputHistory = make(map[string][][]byte)
	}
	f.inputHistory[operation] = append(f.inputHistory[operation], append([]byte(nil), input...))
	if f.trace != nil {
		f.trace.record(operation)
	}
	if queued := f.runErrors[operation]; len(queued) != 0 {
		err := queued[0]
		f.runErrors[operation] = queued[1:]
		return nil, err
	}
	if operation == networkOperationCapture {
		return json.Marshal(f.capture)
	}
	if operation == networkOperationReady {
		return json.Marshal(f.ready)
	}
	if operation == networkOperationScan {
		f.scanCalls++
		if f.blockScanAfter > 0 && f.scanCalls >= f.blockScanAfter {
			f.scanStartOnce.Do(func() { close(f.scanStarted) })
			f.mu.Unlock()
			<-ctx.Done()
			f.mu.Lock()
			return nil, ctx.Err()
		}
		if len(f.scans) == 0 {
			return json.Marshal([]WindowsAdapterIdentity{{InterfaceIndex: 7, InterfaceGuid: "ethernet-guid", InterfaceAlias: "Ethernet", Status: "Up"}})
		}
		value := f.scans[0]
		if len(f.scans) > 1 {
			f.scans = f.scans[1:]
		}
		return json.Marshal(value)
	}
	if operation == networkOperationRestore && len(f.restoreErrors) != 0 {
		err := f.restoreErrors[0]
		f.restoreErrors = f.restoreErrors[1:]
		return nil, err
	}
	return nil, nil
}

func (f *fakeNetworkRunner) inputFor(t *testing.T, operation string) windowsNetworkInput {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var input windowsNetworkInput
	if err := json.Unmarshal(f.inputs[operation], &input); err != nil {
		t.Fatalf("decode %s input: %v", operation, err)
	}
	return input
}

func (f *fakeNetworkRunner) lastInputFor(t *testing.T, operation string) windowsNetworkInput {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	history := f.inputHistory[operation]
	if len(history) == 0 {
		t.Fatalf("no %s input", operation)
	}
	var input windowsNetworkInput
	if err := json.Unmarshal(history[len(history)-1], &input); err != nil {
		t.Fatalf("decode %s input: %v", operation, err)
	}
	return input
}

func (f *fakeNetworkRunner) count(operation string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, candidate := range f.operations {
		if candidate == operation {
			count++
		}
	}
	return count
}

func waitForNetworkOperationCount(t *testing.T, runner *fakeNetworkRunner, operation string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runner.count(operation) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s operation count = %d, want at least %d", operation, runner.count(operation), want)
}

type fakeSnapshotStore struct {
	trace    *callTrace
	exists   bool
	snapshot WindowsNetworkSnapshot
}

func (f *fakeSnapshotStore) Save(_ string, snapshot WindowsNetworkSnapshot) error {
	f.exists = true
	f.snapshot = snapshot
	if f.trace != nil {
		f.trace.record("save")
	}
	return nil
}

func (f *fakeSnapshotStore) Load(string) (WindowsNetworkSnapshot, error) {
	if !f.exists {
		return WindowsNetworkSnapshot{}, errSnapshotNotFound
	}
	return f.snapshot, nil
}

func (f *fakeSnapshotStore) Delete(string) error {
	f.exists = false
	return nil
}
