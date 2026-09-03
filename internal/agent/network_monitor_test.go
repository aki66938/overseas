//go:build windows

package agent

import (
	"context"
	"errors"
	"testing"
	"time"
)

type scriptedMonitorTicker struct {
	channel chan time.Time
}

func (t *scriptedMonitorTicker) Tick() <-chan time.Time { return t.channel }
func (t *scriptedMonitorTicker) Stop()                  {}

type scriptedMonitorClock struct {
	fingerprint *scriptedMonitorTicker
	audit       *scriptedMonitorTicker
}

func (c *scriptedMonitorClock) NewTicker(duration time.Duration) monitorTicker {
	if duration >= networkMonitorAuditInterval {
		if c.audit == nil {
			c.audit = &scriptedMonitorTicker{channel: make(chan time.Time)}
		}
		return c.audit
	}
	if c.fingerprint == nil {
		c.fingerprint = &scriptedMonitorTicker{channel: make(chan time.Time)}
	}
	return c.fingerprint
}

func fireMonitorTick(channel chan time.Time) {
	select {
	case channel <- time.Now():
	case <-time.After(time.Second):
	}
}

// monitorFixture builds a manager whose prepared state matches one valid
// baseline and returns everything needed to drive its runtime monitor.
type monitorFixture struct {
	manager *WindowsNetworkManager
	runner  *fakeNetworkRunner
	reader  *scriptedNativeReader
	clock   *scriptedMonitorClock
}

func newMonitorFixture(t *testing.T, fingerprintDrift bool) monitorFixture {
	t.Helper()
	baseline := validPreparedBaseline()
	drifted := validPreparedBaseline()
	drifted.Adapters[0].InterfaceAlias = "Renamed Ethernet"
	// Sequence: prepare reads [0]; the monitor baseline reads [1]; the first
	// drift tick reads [2] when scripted.
	baselines := []WindowsNetworkBaseline{baseline, baseline}
	if fingerprintDrift {
		baselines = append(baselines, drifted)
	}
	runner := &fakeNetworkRunner{}
	reader := &scriptedNativeReader{baselines: baselines}
	clock := &scriptedMonitorClock{}
	preparedStore := &fakePreparedStateStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(reader),
		withWindowsPreparedStateStore(preparedStore),
		withWindowsMonitorClock(clock),
		withWindowsMonitorConfig(networkMonitorConfig{FingerprintInterval: 30 * time.Second, AuditInterval: 5 * time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Materialize both tickers before StartMonitor so the test can fire them
	// deterministically as soon as the monitor is running.
	clock.NewTicker(30 * time.Second)
	clock.NewTicker(5 * time.Minute)
	manager.mu.Lock()
	// Simulate the connected ownership of the prepared generation.
	manager.current = &WindowsNetworkSnapshot{Version: 1, RouteMetric: windowsOwnedRouteMetric, OwnershipPhase: windowsSnapshotPhaseProtected, PreparedGeneration: prepared.Generation}
	manager.mu.Unlock()
	return monitorFixture{manager: manager, runner: runner, reader: reader, clock: clock}
}

func TestNetworkMonitorUnchangedFingerprintNeverWritesFirewall(t *testing.T) {
	fixture := newMonitorFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	failures, err := fixture.manager.StartMonitor(ctx, fixture.manager.preparedNetwork())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	monitorWriteBaseline := monitorWriteCount(fixture.runner)
	for range 100 {
		fireMonitorTick(fixture.clock.fingerprint.channel)
	}
	for range 2 {
		fireMonitorTick(fixture.clock.audit.channel)
	}
	if got := monitorWriteCount(fixture.runner) - monitorWriteBaseline; got != 0 {
		t.Fatalf("monitor wrote firewall rules while unchanged: %d operations", got)
	}
	select {
	case err := <-failures:
		t.Fatalf("unchanged monitor reported failure: %v", err)
	default:
	}
}

func TestNetworkMonitorChangedFingerprintEnablesEmergencyBeforeReporting(t *testing.T) {
	fixture := newMonitorFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures, err := fixture.manager.StartMonitor(ctx, fixture.manager.preparedNetwork())
	if err != nil {
		t.Fatal(err)
	}
	fireMonitorTick(fixture.clock.fingerprint.channel)
	select {
	case err := <-failures:
		if !errors.Is(err, errNetworkChanged) {
			t.Fatalf("failure = %v, want network changed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("changed fingerprint was not reported")
	}
	if got := fixture.runner.count(networkOperationEmergency); got != 1 {
		t.Fatalf("emergency enable operations = %d, want 1 before reporting", got)
	}
}

func TestNetworkMonitorAuditFailureEnablesEmergencyAndReportsOnce(t *testing.T) {
	fixture := newMonitorFixture(t, false)
	fixture.runner.runErrors = map[string][]error{networkOperationFirewallAudit: {errors.New("definition drifted")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures, err := fixture.manager.StartMonitor(ctx, fixture.manager.preparedNetwork())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		fireMonitorTick(fixture.clock.audit.channel)
	}
	select {
	case err := <-failures:
		if !errors.Is(err, errFirewallAudit) {
			t.Fatalf("failure = %v, want firewall audit", err)
		}
	case <-time.After(time.Second):
		t.Fatal("audit failure was not reported")
	}
	if got := fixture.runner.count(networkOperationEmergency); got != 1 {
		t.Fatalf("emergency enable operations = %d, want 1", got)
	}
	select {
	case err, ok := <-failures:
		if ok {
			t.Fatalf("monitor reported a second terminal error: %v", err)
		}
	default:
	}
}

func TestNetworkMonitorCancellationStopsAllWrites(t *testing.T) {
	fixture := newMonitorFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	failures, err := fixture.manager.StartMonitor(ctx, fixture.manager.preparedNetwork())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		fixture.manager.mu.Lock()
		busy := fixture.manager.monitorFlights
		fixture.manager.mu.Unlock()
		if busy == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case fixture.clock.fingerprint.channel <- time.Now():
	default:
	}
	if got := fixture.runner.count(networkOperationEmergency); got != 0 {
		t.Fatalf("canceled monitor wrote emergency protection: %d", got)
	}
	select {
	case err, ok := <-failures:
		if ok {
			t.Fatalf("canceled monitor reported failure: %v", err)
		}
	default:
	}
}

func TestNetworkMonitorRefusesUnknownPreparedGeneration(t *testing.T) {
	fixture := newMonitorFixture(t, false)
	if _, err := fixture.manager.StartMonitor(context.Background(), PreparedNetwork{Generation: 99, Fingerprint: "fingerprint"}); err == nil {
		t.Fatal("StartMonitor accepted an unknown prepared generation")
	}
}

func TestNetworkMonitorFingerprintReadFailureIsRetriedNotReported(t *testing.T) {
	fixture := newMonitorFixture(t, false)
	fixture.reader.failFingerprints = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures, err := fixture.manager.StartMonitor(ctx, fixture.manager.preparedNetwork())
	if err != nil {
		t.Fatal(err)
	}
	fireMonitorTick(fixture.clock.fingerprint.channel)
	select {
	case err := <-failures:
		t.Fatalf("transient fingerprint failure reported: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	fireMonitorTick(fixture.clock.fingerprint.channel)
	select {
	case err := <-failures:
		t.Fatalf("recovered fingerprint reported failure: %v", err)
	default:
	}
}

func monitorWriteCount(runner *fakeNetworkRunner) int {
	return runner.count(networkOperationFirewallPrepare) +
		runner.count(networkOperationFirewallEnable) +
		runner.count(networkOperationFirewallDisable) +
		runner.count(networkOperationEmergency) +
		runner.count(networkOperationPreparedRestore)
}
