//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

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
	if err := manager.InstallPublicTCPBlock(context.Background()); err != nil {
		t.Fatal(err)
	}

	if snapshot == nil || !store.exists {
		t.Fatal("captured network state was not persisted")
	}
	if got, want := trace.calls(), []string{"capture", "save", "block"}; !equalStrings(got, want) {
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
	if !equalStrings(input.TUNRoutePrefixes, []string{"0.0.0.0/1", "128.0.0.0/1"}) {
		t.Fatalf("TUN routes = %v", input.TUNRoutePrefixes)
	}
	if input.OwnedTUN == nil || input.OwnedTUN.InterfaceGuid != "new-tun-guid" || len(input.OwnedRoutes) != 2 {
		t.Fatalf("owned TUN activation input = %#v", input)
	}
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

func TestWindowsNetworkFirewallScopeCoversNewEligibleInterfacesAndExcludesTUNByType(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.InstallPublicTCPBlock(context.Background()); err != nil {
		t.Fatal(err)
	}

	input := runner.inputFor(t, networkOperationBlock)
	if !equalStrings(input.FirewallInterfaceTypes, []string{"Wired", "Wireless"}) {
		t.Fatalf("firewall interface types = %v", input.FirewallInterfaceTypes)
	}
	if !strings.Contains(blockNetworkPowerShell, "-InterfaceType") || strings.Contains(blockNetworkPowerShell, "-InterfaceAlias") {
		t.Fatal("firewall script is not dynamically scoped by eligible interface type")
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
	if len(input.OwnedRoutes) != 3 {
		t.Fatalf("owned routes = %#v", input.OwnedRoutes)
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

type fakeNetworkRunner struct {
	trace         *callTrace
	capture       WindowsNetworkSnapshot
	ready         WindowsTUNIdentity
	operations    []string
	inputs        map[string][]byte
	restoreErrors []error
}

func (f *fakeNetworkRunner) Run(_ context.Context, operation string, input []byte) ([]byte, error) {
	f.operations = append(f.operations, operation)
	if f.inputs == nil {
		f.inputs = make(map[string][]byte)
	}
	f.inputs[operation] = append([]byte(nil), input...)
	if f.trace != nil {
		f.trace.record(operation)
	}
	if operation == networkOperationCapture {
		return json.Marshal(f.capture)
	}
	if operation == networkOperationReady {
		return json.Marshal(f.ready)
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
	var input windowsNetworkInput
	if err := json.Unmarshal(f.inputs[operation], &input); err != nil {
		t.Fatalf("decode %s input: %v", operation, err)
	}
	return input
}

func (f *fakeNetworkRunner) count(operation string) int {
	count := 0
	for _, candidate := range f.operations {
		if candidate == operation {
			count++
		}
	}
	return count
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
