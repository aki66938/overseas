//go:build windows

package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// The PoC fast path: sing-box auto_route owns routes and tun DNS; the
// product prepares in-memory, arms nothing, flushes the resolver cache,
// and proves the tun gone on restore.

func TestPocPrepareReturnsInMemoryGeneration(t *testing.T) {
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{validPreparedBaseline()}}))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Generation != 1 || prepared.RuleCount != 0 {
		t.Fatalf("prepared = %+v", prepared)
	}
}

func TestPocPrepareRefusesForeignTunnel(t *testing.T) {
	baseline := validPreparedBaseline()
	baseline.Adapters = append(baseline.Adapters, WindowsNativeAdapter{
		InterfaceIndex: 9, InterfaceGuid: "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
		InterfaceAlias: "Clash", Description: "Wintun Userspace Tunnel",
	})
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Prepare(context.Background()); !errors.Is(err, errVPNConflict) {
		t.Fatalf("Prepare() error = %v, want vpn conflict", err)
	}
}

func TestPocCaptureMatchesFingerprintAndWaitsForTun(t *testing.T) {
	baseline := validPreparedBaseline()
	reader := &scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline}, tun: validTUNIdentity(), tunReady: true}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Capture(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	_ = snapshot
	if err := manager.EnableProtection(context.Background(), prepared); err != nil {
		t.Fatalf("EnableProtection() = %v, want no-op success", err)
	}
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	reader.mu.Lock()
	reader.tunReady = false
	reader.mu.Unlock()
	residue, err := manager.Residue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !residue.IsZero() {
		t.Fatalf("residue after restore = %#v, want zero", residue)
	}
}

func TestPocWaitTUNRejectsForeignIdentity(t *testing.T) {
	reader := &scriptedNativeReader{baselines: []WindowsNetworkBaseline{validPreparedBaseline()}, tunReady: true}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	prepared, _ := manager.Prepare(context.Background())
	if _, err := manager.Capture(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	reader.mu.Lock()
	foreign := validTUNIdentity()
	foreign.InterfaceAlias = "Ethernet"
	reader.tun = foreign
	reader.mu.Unlock()
	if err := manager.WaitTUNReady(context.Background()); !errors.Is(err, errTUNIdentityMismatch) {
		t.Fatalf("WaitTUNReady() = %v, want identity mismatch", err)
	}
}

type manualMonitorTicker struct {
	ticks chan time.Time
}

func (t *manualMonitorTicker) Tick() <-chan time.Time { return t.ticks }
func (t *manualMonitorTicker) Stop()                  {}

type manualMonitorClock struct {
	mu      sync.Mutex
	tickers []*manualMonitorTicker
	next    int
	created chan time.Duration
}

func newManualMonitorClock() *manualMonitorClock {
	return &manualMonitorClock{
		tickers: []*manualMonitorTicker{{ticks: make(chan time.Time, 1)}, {ticks: make(chan time.Time, 1)}},
		created: make(chan time.Duration, 2),
	}
}

func (c *manualMonitorClock) NewTicker(duration time.Duration) monitorTicker {
	c.mu.Lock()
	defer c.mu.Unlock()
	ticker := c.tickers[c.next]
	c.next++
	c.created <- duration
	return ticker
}

type recordingMonitorRunner struct {
	called         chan string
	errByOperation map[string]error
}

func (r *recordingMonitorRunner) Run(_ context.Context, operation string, _ []byte) ([]byte, error) {
	r.called <- operation
	return []byte(`{}`), r.errByOperation[operation]
}

func TestRuntimeMonitorSkipsPreparedFirewallAuditForZeroRulePoc(t *testing.T) {
	clock := newManualMonitorClock()
	runner := &recordingMonitorRunner{called: make(chan string, 4)}
	manager, err := newWindowsNetworkManager(
		validPolicy(),
		`C:\state.json`,
		runner,
		&fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{validPreparedBaseline()}}),
		withWindowsMonitorClock(clock),
	)
	if err != nil {
		t.Fatal(err)
	}
	prepared := PreparedNetwork{Generation: 1, Fingerprint: strings.Repeat("a", 64), AdapterCount: 1}
	manager.prepared = &WindowsPreparedState{Generation: prepared.Generation, Rules: nil}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures, err := manager.StartMonitor(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case duration := <-clock.created:
		if duration != networkMonitorFingerprintInterval {
			t.Fatalf("first ticker = %s, want fingerprint ticker", duration)
		}
	case <-time.After(time.Second):
		t.Fatal("fingerprint ticker was not created")
	}
	select {
	case duration := <-clock.created:
		t.Fatalf("zero-rule PoC created legacy audit ticker %s", duration)
	case operation := <-runner.called:
		t.Fatalf("zero-rule PoC invoked legacy operation %q", operation)
	case failure := <-failures:
		t.Fatalf("zero-rule PoC monitor failed: %v", failure)
	case <-time.After(50 * time.Millisecond):
	}
}

func clockTickerAt(clock *manualMonitorClock, index int) *manualMonitorTicker {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.tickers[index]
}

func TestRuntimeMonitorRetainsFailClosedAuditForOwnedPreparedRules(t *testing.T) {
	clock := newManualMonitorClock()
	runner := &recordingMonitorRunner{
		called:         make(chan string, 4),
		errByOperation: map[string]error{networkOperationFirewallAudit: errors.New("membership drift")},
	}
	manager, err := newWindowsNetworkManager(
		validPolicy(),
		`C:\state.json`,
		runner,
		&fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{validPreparedBaseline()}}),
		withWindowsMonitorClock(clock),
	)
	if err != nil {
		t.Fatal(err)
	}
	prepared := PreparedNetwork{Generation: 1, Fingerprint: strings.Repeat("a", 64), AdapterCount: 1}
	manager.prepared = &WindowsPreparedState{
		Generation: prepared.Generation,
		Rules: []WindowsPreparedRule{
			{Name: "RegenBioOverseasAccess.Managed.Normal"},
			{Name: "RegenBioOverseasAccess.Managed.Emergency", Emergency: true},
		},
	}
	failures, err := manager.StartMonitor(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	for index, want := range []time.Duration{networkMonitorFingerprintInterval, networkMonitorAuditInterval} {
		select {
		case got := <-clock.created:
			if got != want {
				t.Fatalf("ticker %d = %s, want %s", index, got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("ticker %d was not created", index)
		}
	}
	clockTickerAt(clock, 1).ticks <- time.Now()

	failure := <-failures
	if !errors.Is(failure, errFirewallAudit) {
		t.Fatalf("monitor failure = %v, want firewall audit", failure)
	}
	for index, want := range []string{networkOperationFirewallAudit, networkOperationEmergency} {
		select {
		case got := <-runner.called:
			if got != want {
				t.Fatalf("operation %d = %q, want %q", index, got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("operation %d = absent, want %q", index, want)
		}
	}
}

func TestTunRecoveryScriptIsRestrictedToOneOwnedPhantom(t *testing.T) {
	script, ok := networkPowerShellScripts["tun_recover"]
	if !ok {
		t.Fatal("tun_recover fixed operation is absent")
	}
	for _, required := range []string{
		"Get-PnpDevice -PresentOnly:$false",
		`SWD\WINTUN\`,
		"CM_PROB_PHANTOM",
		"CoreExecutable",
		`Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}`,
		"TUNInterface",
		"ownership is ambiguous",
		"pnputil.exe",
		"/remove-device",
		"removal was not proven",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("tun_recover script is missing %q", required)
		}
	}
	if strings.Contains(script, "pnputil.exe /remove-device *") {
		t.Fatal("tun_recover must never use wildcard device removal")
	}
}

func TestPocPrepareRunsOwnedPhantomRecoveryBeforeBaseline(t *testing.T) {
	runner := &fakeNetworkRunner{}
	manager, err := newWindowsNetworkManager(
		validPolicy(),
		`C:\state.json`,
		runner,
		&fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{
			validPreparedBaseline(), validPreparedBaseline(),
		}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.ops) == 0 || runner.ops[0] != "tun_recover" {
		t.Fatalf("prepare operations = %v, want tun_recover first", runner.ops)
	}
}
