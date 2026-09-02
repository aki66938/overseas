//go:build windows

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

type fakePreparedStateStore struct {
	mu        sync.Mutex
	exists    bool
	state     WindowsPreparedState
	saves     int
	saveErr   error
	deleteErr error
}

func (s *fakePreparedStateStore) Save(_ string, state WindowsPreparedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.exists = true
	s.state = state
	s.saves++
	return nil
}

func (s *fakePreparedStateStore) Load(string) (WindowsPreparedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exists {
		return WindowsPreparedState{}, errPreparedStateNotFound
	}
	return s.state, nil
}

func (s *fakePreparedStateStore) Delete(string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.exists = false
	return nil
}

type scriptedNativeReader struct {
	mu        sync.Mutex
	baselines []WindowsNetworkBaseline
	calls     int
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (r *scriptedNativeReader) Baseline(ctx context.Context, _ []string) (WindowsNetworkBaseline, error) {
	if r.started != nil {
		r.once.Do(func() { close(r.started) })
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return WindowsNetworkBaseline{}, ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if len(r.baselines) == 0 {
		return WindowsNetworkBaseline{}, errors.New("no scripted baseline")
	}
	value := r.baselines[0]
	if len(r.baselines) > 1 {
		r.baselines = r.baselines[1:]
	}
	return value, nil
}

func (r *scriptedNativeReader) Fingerprint(ctx context.Context, nodes []string) (string, error) {
	baseline, err := r.Baseline(ctx, nodes)
	if err != nil {
		return "", err
	}
	return fingerprintNativeNetwork(baseline)
}

func TestWindowsNetworkPrepareFirstGenerationAndUnchangedReuse(t *testing.T) {
	baseline := validPreparedBaseline()
	runner := &fakeNetworkRunner{}
	preparedStore := &fakePreparedStateStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline, baseline}}),
		withWindowsPreparedStateStore(preparedStore))
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Generation != 1 || first.AdapterCount != 1 || first.RuleCount != 4 {
		t.Fatalf("prepared results = %+v / %+v", first, second)
	}
	if preparedStore.saves != 1 || runner.count(networkOperationFirewallPrepare) != 1 {
		t.Fatalf("saves/prepare = %d/%d, want 1/1", preparedStore.saves, runner.count(networkOperationFirewallPrepare))
	}
	if runner.count(networkOperationFirewallAudit) != 2 {
		t.Fatalf("audit calls = %d, want 2", runner.count(networkOperationFirewallAudit))
	}
}

func TestWindowsNetworkPrepareTopologyChangeCreatesNextGeneration(t *testing.T) {
	first := validPreparedBaseline()
	second := validPreparedBaseline()
	second.Interfaces[0].InterfaceMetric++
	runner := &fakeNetworkRunner{}
	store := &fakePreparedStateStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{first, second}}),
		withWindowsPreparedStateStore(store))
	if err != nil {
		t.Fatal(err)
	}
	prepared1, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prepared2, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prepared1.Generation != 1 || prepared2.Generation != 2 || prepared1.Fingerprint == prepared2.Fingerprint {
		t.Fatalf("generation/fingerprint did not change: %+v / %+v", prepared1, prepared2)
	}
	if store.saves != 2 || runner.count(networkOperationFirewallPrepare) != 2 {
		t.Fatalf("saves/prepare = %d/%d, want 2/2", store.saves, runner.count(networkOperationFirewallPrepare))
	}
	secondInput := runner.lastInputFor(t, networkOperationFirewallPrepare)
	if secondInput.PreviousPreparedGeneration != 1 || len(secondInput.PreviousPreparedRules) != prepared1.RuleCount {
		t.Fatalf("previous generation/rules = %d/%d, want 1/%d", secondInput.PreviousPreparedGeneration, len(secondInput.PreviousPreparedRules), prepared1.RuleCount)
	}
}

func TestWindowsNetworkPreparePolicyAndRuleVersionInvalidationUsesSealedPriorLedger(t *testing.T) {
	baseline := validPreparedBaseline()
	store := &fakePreparedStateStore{}
	runner1 := &fakeNetworkRunner{}
	manager1, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner1, &fakeSnapshotStore{}, withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline}}), withWindowsPreparedStateStore(store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager1.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.RuleDefinitionVersion = 1
	if err := sealWindowsPreparedState(&store.state); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	policy := validPolicy()
	policy.InternalSuffixes = append(policy.InternalSuffixes, "apps.intra.regen-bio.com")
	policy.CorporateCIDRs = append(policy.CorporateCIDRs, "8.8.8.0/24")
	runner2 := &fakeNetworkRunner{}
	manager2, err := newWindowsNetworkManager(policy, `C:\state.json`, runner2, &fakeSnapshotStore{}, withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline}}), withWindowsPreparedStateStore(store))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager2.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Generation != 2 {
		t.Fatalf("generation = %d, want 2", prepared.Generation)
	}
	input := runner2.inputFor(t, networkOperationFirewallPrepare)
	if input.PreviousPreparedGeneration != 1 || input.PreviousRuleDefinitionVersion != 1 || len(input.PreviousPreparedRules) == 0 {
		t.Fatalf("prior ledger was not supplied: %+v", input)
	}
	if len(input.PreviousBlockedRemoteAddresses) == 0 || slices.Equal(input.PreviousBlockedRemoteAddresses, input.BlockedRemoteAddresses) {
		t.Fatalf("previous blocked prefixes were not preserved independently")
	}
}

func TestWindowsNetworkPrepareConcurrentCallersCoalesceAndCanceledWaiterIsolated(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	reader := &scriptedNativeReader{baselines: []WindowsNetworkBaseline{validPreparedBaseline()}, started: started, release: release}
	runner := &fakeNetworkRunner{}
	store := &fakePreparedStateStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{}, withWindowsNativeNetworkReader(reader), withWindowsPreparedStateStore(store))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, prepareErr := manager.Prepare(context.Background()); result <- prepareErr }()
	<-started
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Prepare(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v", err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if reader.calls != 1 || store.saves != 1 || runner.count(networkOperationFirewallPrepare) != 1 {
		t.Fatalf("calls/saves/prepare = %d/%d/%d", reader.calls, store.saves, runner.count(networkOperationFirewallPrepare))
	}
}

func TestWindowsNetworkPrepareRejectsActiveTransactionAndPublishFailure(t *testing.T) {
	baseline := validPreparedBaseline()
	store := &fakePreparedStateStore{saveErr: errors.New("disk full")}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{}, withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline}}), withWindowsPreparedStateStore(store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Prepare(context.Background()); err == nil {
		t.Fatal("Prepare succeeded after atomic publication failure")
	}
	manager.mu.Lock()
	manager.current = &WindowsNetworkSnapshot{}
	manager.mu.Unlock()
	if _, err := manager.Prepare(context.Background()); err == nil {
		t.Fatal("Prepare accepted an active transaction")
	}
}

func TestWindowsNetworkPrepareReplacementPublishFailureRollsBackPriorGeneration(t *testing.T) {
	first := validPreparedBaseline()
	second := validPreparedBaseline()
	second.Interfaces[0].InterfaceMetric++
	runner := &fakeNetworkRunner{}
	store := &fakePreparedStateStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{}, withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{first, second}}), withWindowsPreparedStateStore(store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.saveErr = errors.New("disk full")
	store.mu.Unlock()
	if _, err := manager.Prepare(context.Background()); err == nil {
		t.Fatal("replacement succeeded after prepared-state publication failure")
	}
	if runner.count(networkOperationFirewallPrepare) != 3 {
		t.Fatalf("prepare operations = %d, want first + replacement + rollback", runner.count(networkOperationFirewallPrepare))
	}
	rollback := runner.lastInputFor(t, networkOperationFirewallPrepare)
	if rollback.PreparedGeneration != 1 || rollback.PreviousPreparedGeneration != 2 {
		t.Fatalf("rollback generation = %d from %d, want 1 from 2", rollback.PreparedGeneration, rollback.PreviousPreparedGeneration)
	}
}

func TestWindowsNetworkFastCaptureRejectsStaleGeneration(t *testing.T) {
	baseline := validPreparedBaseline()
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{}, withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline, baseline}}), withWindowsPreparedStateStore(&fakePreparedStateStore{}))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prepared.Generation++
	if _, err := manager.Capture(context.Background(), prepared); err == nil {
		t.Fatal("Capture accepted a stale prepared generation")
	}
}

func TestWindowsNetworkFastPathUsesNativeCaptureThenExactEnableAndVerify(t *testing.T) {
	baseline := validPreparedBaseline()
	runner := &fakeNetworkRunner{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{}, withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline, baseline}}), withWindowsPreparedStateStore(&fakePreparedStateStore{}))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	value, err := manager.Capture(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := value.(WindowsNetworkSnapshot)
	if snapshot.PreparedGeneration != prepared.Generation || snapshot.OwnershipPhase != windowsSnapshotPhaseCaptured {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if err := manager.EnableProtection(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if runner.count(networkOperationCapture) != 0 || runner.count(networkOperationScan) != 0 || runner.count(networkOperationBlock) != 0 || runner.count(networkOperationVerify) != 0 {
		t.Fatalf("legacy operations ran: %v", runner.operations)
	}
	want := []string{networkOperationFirewallPrepare, networkOperationFirewallAudit, networkOperationFirewallEnable, networkOperationFirewallVerify}
	if len(runner.operations) != len(want) {
		t.Fatalf("operations = %v, want %v", runner.operations, want)
	}
	for index := range want {
		if runner.operations[index] != want[index] {
			t.Fatalf("operations = %v, want %v", runner.operations, want)
		}
	}
}

func TestWindowsNetworkWaitTUNReadyDoesNotReconcileFirewall(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), ready: validTUNIdentity()}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{networkOperationScan, networkOperationBlock, networkOperationVerify} {
		if runner.count(operation) != 0 {
			t.Fatalf("WaitTUNReady performed %s", operation)
		}
	}
}

func TestFilePreparedStateStoreReplacesAtomicallyAndRejectsUnknownJSON(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, windowsPreparedStateFile)
	store := filePreparedStateStore{}
	first := WindowsPreparedState{Generation: 1}
	second := WindowsPreparedState{Generation: 2}
	if err := store.Save(path, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(path, second); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(path)
	if err != nil || loaded.Generation != 2 {
		t.Fatalf("loaded = %+v, err = %v", loaded, err)
	}
	if matches, err := filepath.Glob(filepath.Join(directory, ".prepared-network-*.tmp")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary residue = %v, err = %v", matches, err)
	}
	if err := os.WriteFile(path, []byte(`{"Generation":2,"Unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(path); err == nil {
		t.Fatal("prepared store accepted an unknown JSON field")
	}
}

func validPreparedBaseline() WindowsNetworkBaseline {
	return WindowsNetworkBaseline{
		Adapters:   []WindowsNativeAdapter{{InterfaceIndex: 4, InterfaceLUID: 44, InterfaceGuid: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", InterfaceAlias: "Ethernet", Status: "Up", DNSServers: []string{"172.20.9.1", "172.20.9.2"}, DNSAutomatic: true}},
		Interfaces: []WindowsNativeInterface{{InterfaceIndex: 4, InterfaceLUID: 44, AutomaticMetric: true, InterfaceMetric: 25}},
		Routes:     []WindowsNativeRoute{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, InterfaceLUID: 44, NextHop: "172.20.10.1", RouteMetric: 0, Protocol: 3}},
		NodeRoutes: []WindowsNodeRouteSnapshot{{NodeAddress: "172.20.9.15", DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, NextHop: "172.20.10.1", RouteMetric: 0, InterfaceMetric: 25, EffectiveMetric: 25, BypassRequired: true}},
	}
}
