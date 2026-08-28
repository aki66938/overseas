//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
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
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
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
	if input.NodeAddress != "172.20.9.15" || input.DefaultGateway != "172.20.10.1" || input.DefaultInterfaceIndex != 7 {
		t.Fatalf("node bypass input = %#v", input)
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
		DefaultInterfaceIndex: 7,
		DefaultGateway:        "172.20.10.1",
		NodeAddress:           "172.20.9.15",
		RouteMetric:           windowsOwnedRouteMetric,
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
