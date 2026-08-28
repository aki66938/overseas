package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
)

func TestControllerConnectFailureRemainsFailClosed(t *testing.T) {
	trace := &callTrace{}
	network := newFakeNetwork()
	network.trace = trace
	process := newFakeProcess()
	process.trace = trace
	process.startErr = errors.New("upstream unavailable")
	controller := newTestController(network, process, testDependencies(trace))

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StateFailed || !network.isBlocked() {
		t.Fatalf("Connect() = %#v, blocked = %v", got, network.isBlocked())
	}
	if network.restoreCalls != 0 {
		t.Fatalf("failed connect restored the network %d times", network.restoreCalls)
	}
	want := []string{"validate", "verify", "credential", "capture", "block", "render", "write", "start"}
	if calls := trace.calls(); !equalStrings(calls, want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
}

func TestControllerDisconnectRestoresCapturedState(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))

	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}
	got := controller.Disconnect(context.Background())

	if got.State != accessmodel.StateDisconnected || network.isBlocked() || network.isActive() {
		t.Fatalf("Disconnect() = %#v, blocked = %v, active = %v", got, network.isBlocked(), network.isActive())
	}
	if network.restoreCalls != 1 {
		t.Fatalf("Restore() calls = %d, want 1", network.restoreCalls)
	}
}

func TestControllerConcurrentConnectsCoalesce(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	process.readyGate = make(chan struct{})
	controller := newTestController(network, process, testDependencies(nil))

	results := make(chan Status, 2)
	go func() { results <- controller.Connect(context.Background()) }()
	process.waitForStart(t)
	go func() { results <- controller.Connect(context.Background()) }()
	close(process.readyGate)

	for range 2 {
		if got := <-results; got.State != accessmodel.StateConnected {
			t.Fatalf("Connect() = %#v", got)
		}
	}
	if process.startCalls != 1 {
		t.Fatalf("Start() calls = %d, want 1", process.startCalls)
	}
	controller.Disconnect(context.Background())
}

func TestControllerDisconnectCancelsConnectAndRestores(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	process.readyGate = make(chan struct{})
	controller := newTestController(network, process, testDependencies(nil))

	connectDone := make(chan Status, 1)
	go func() { connectDone <- controller.Connect(context.Background()) }()
	process.waitForStart(t)

	got := controller.Disconnect(context.Background())
	connectStatus := <-connectDone

	if got.State != accessmodel.StateDisconnected {
		t.Fatalf("Disconnect() = %#v", got)
	}
	if connectStatus.State == accessmodel.StateConnected {
		t.Fatalf("canceled Connect() = %#v", connectStatus)
	}
	if network.isBlocked() || network.isActive() {
		t.Fatalf("network was not restored: blocked=%v active=%v", network.isBlocked(), network.isActive())
	}
}

func TestControllerRecoveryReconcilesServiceRestartOnce(t *testing.T) {
	network := newFakeNetwork()
	network.blocked = true
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))

	if got := controller.Recover(context.Background()); got.State != accessmodel.StateDisconnected {
		t.Fatalf("Recover() = %#v", got)
	}
	if got := controller.Recover(context.Background()); got.State != accessmodel.StateDisconnected {
		t.Fatalf("second Recover() = %#v", got)
	}
	if network.reconcileCalls != 1 || network.isBlocked() {
		t.Fatalf("Reconcile() calls = %d, blocked = %v", network.reconcileCalls, network.isBlocked())
	}
}

func TestControllerInvalidPolicyFailsBeforeNetworkMutation(t *testing.T) {
	network := newFakeNetwork()
	deps := testDependencies(nil)
	deps.ValidatePolicy = func(accessmodel.Policy) error { return errors.New("invalid policy") }
	controller := newTestController(network, newFakeProcess(), deps)

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StateFailed || got.ErrorCode != ErrorInvalidPolicy {
		t.Fatalf("Connect() = %#v", got)
	}
	if network.captureCalls != 0 || network.blockCalls != 0 {
		t.Fatalf("network mutated after invalid policy: capture=%d block=%d", network.captureCalls, network.blockCalls)
	}
}

func TestControllerBadBinaryFailsBeforeNetworkMutation(t *testing.T) {
	network := newFakeNetwork()
	deps := testDependencies(nil)
	deps.VerifyExecutable = func(string) error { return errors.New("hash mismatch") }
	controller := newTestController(network, newFakeProcess(), deps)

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StateFailed || got.ErrorCode != ErrorInvalidBinary {
		t.Fatalf("Connect() = %#v", got)
	}
	if network.captureCalls != 0 || network.blockCalls != 0 {
		t.Fatalf("network mutated after invalid binary: capture=%d block=%d", network.captureCalls, network.blockCalls)
	}
}

func TestControllerExpiredCredentialFailsBeforeNetworkMutation(t *testing.T) {
	network := newFakeNetwork()
	deps := testDependencies(nil)
	deps.LoadCredential = func(context.Context, accessmodel.CredentialRef) (Credential, error) {
		return Credential{Method: "2022-blake3-aes-128-gcm", Password: []byte("secret"), ExpiresAt: time.Now().Add(-time.Minute)}, nil
	}
	controller := newTestController(network, newFakeProcess(), deps)

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StateFailed || got.ErrorCode != ErrorExpiredCredential {
		t.Fatalf("Connect() = %#v", got)
	}
	if network.captureCalls != 0 || network.blockCalls != 0 {
		t.Fatalf("network mutated after expired credential: capture=%d block=%d", network.captureCalls, network.blockCalls)
	}
}

func TestControllerReadinessLossTransitionsToFailedAndKeepsBlock(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}

	process.exit(errors.New("core exited"))
	waitForState(t, controller, accessmodel.StateFailed)

	if !network.isBlocked() {
		t.Fatal("public TCP block was removed after readiness loss")
	}
	if got := controller.Status(); got.ErrorCode != ErrorReadinessLost {
		t.Fatalf("Status() = %#v", got)
	}
}

func TestControllerConnectedProcessContextOutlivesConnectTransition(t *testing.T) {
	process := newFakeProcess()
	controller := newTestController(newFakeNetwork(), process, testDependencies(nil))

	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}
	process.mu.Lock()
	startContext := process.startContext
	process.mu.Unlock()
	if startContext == nil || startContext.Err() != nil {
		t.Fatalf("process Start context was canceled after Connect: %v", startContext)
	}
	controller.Disconnect(context.Background())
}

func TestControllerRecoveryRetriesRestorationIdempotently(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}
	network.restoreErrors = []error{errors.New("temporary restore failure"), nil}

	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StateFailed || got.ErrorCode != ErrorRestoreFailed {
		t.Fatalf("first Disconnect() = %#v", got)
	}
	if !network.isBlocked() {
		t.Fatal("failed restore unexpectedly removed the public TCP block")
	}
	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StateDisconnected {
		t.Fatalf("second Disconnect() = %#v", got)
	}
	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StateDisconnected {
		t.Fatalf("third Disconnect() = %#v", got)
	}
	if network.restoreCalls != 2 {
		t.Fatalf("Restore() calls = %d, want 2", network.restoreCalls)
	}
}

func TestControllerRouteActivationFailureRemainsFailClosed(t *testing.T) {
	network := newFakeNetwork()
	network.activateErr = errors.New("route failed")
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StateFailed || got.ErrorCode != ErrorRouteActivationFailed || !network.isBlocked() {
		t.Fatalf("Connect() = %#v, blocked = %v", got, network.isBlocked())
	}
}

func TestControllerClearsCredentialAndRenderedConfigOnWriteFailure(t *testing.T) {
	credentialBytes := []byte("topsecret")
	renderedBytes := []byte(`{"password":"topsecret"}`)
	deps := testDependencies(nil)
	deps.LoadCredential = func(context.Context, accessmodel.CredentialRef) (Credential, error) {
		return Credential{Method: "2022-blake3-aes-128-gcm", Password: credentialBytes, ExpiresAt: time.Now().Add(time.Hour)}, nil
	}
	deps.RenderConfig = func(accessmodel.Policy, Credential) ([]byte, error) { return renderedBytes, nil }
	deps.WriteConfigAtomic = func(string, []byte) error { return errors.New("disk full") }
	controller := newTestController(newFakeNetwork(), newFakeProcess(), deps)

	if got := controller.Connect(context.Background()); got.ErrorCode != ErrorRender {
		t.Fatalf("Connect() = %#v", got)
	}
	if !allZero(credentialBytes) {
		t.Fatalf("credential buffer was not cleared: %v", credentialBytes)
	}
	if !allZero(renderedBytes) {
		t.Fatalf("rendered config buffer was not cleared: %v", renderedBytes)
	}
}

func newTestController(network *fakeNetwork, process *fakeProcess, deps Dependencies) *Controller {
	return NewController(validPolicy(), network, process, WithDependencies(deps))
}

func validPolicy() accessmodel.Policy {
	return accessmodel.Policy{
		SchemaVersion:    1,
		Mode:             "poc",
		Nodes:            []accessmodel.Node{{ID: "vm101", Address: "172.20.9.15", Port: 8443}},
		CorporateCIDRs:   []string{"172.20.8.0/22"},
		CorporateDNS:     []string{"172.20.9.1"},
		InternalSuffixes: []string{"ad.intra.regen-bio.com"},
		BlockUDP:         true,
		BlockQUIC:        true,
		Credential:       accessmodel.CredentialRef{Kind: "dpapi-file", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`},
	}
}

func testDependencies(trace *callTrace) Dependencies {
	record := func(name string) {
		if trace != nil {
			trace.record(name)
		}
	}
	return Dependencies{
		ExecutablePath: `C:\Program Files\RegenBio\OverseasAccess\sing-box.exe`,
		ConfigPath:     `C:\ProgramData\RegenBio\OverseasAccess\sing-box.json`,
		ValidatePolicy: func(policy accessmodel.Policy) error {
			record("validate")
			return accessmodel.Validate(policy)
		},
		VerifyExecutable: func(string) error {
			record("verify")
			return nil
		},
		LoadCredential: func(context.Context, accessmodel.CredentialRef) (Credential, error) {
			record("credential")
			return Credential{Method: "2022-blake3-aes-128-gcm", Password: []byte("secret"), ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		RenderConfig: func(accessmodel.Policy, Credential) ([]byte, error) {
			record("render")
			return []byte(`{"route":{"final":"tunnel"}}`), nil
		},
		WriteConfigAtomic: func(string, []byte) error {
			record("write")
			return nil
		},
		Now: time.Now,
	}
}

type fakeNetwork struct {
	mu             sync.Mutex
	blocked        bool
	active         bool
	captureCalls   int
	blockCalls     int
	activateCalls  int
	restoreCalls   int
	reconcileCalls int
	restoreErrors  []error
	activateErr    error
	log            []string
	trace          *callTrace
}

func newFakeNetwork() *fakeNetwork { return &fakeNetwork{} }

func (f *fakeNetwork) Capture(context.Context) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captureCalls++
	f.log = append(f.log, "capture")
	if f.trace != nil {
		f.trace.record("capture")
	}
	return "original", nil
}

func (f *fakeNetwork) InstallPublicTCPBlock(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockCalls++
	f.blocked = true
	f.log = append(f.log, "block")
	if f.trace != nil {
		f.trace.record("block")
	}
	return nil
}

func (f *fakeNetwork) ActivateTUNRoutes(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activateCalls++
	f.log = append(f.log, "activate")
	if f.trace != nil {
		f.trace.record("activate")
	}
	if f.activateErr == nil {
		f.active = true
	}
	return f.activateErr
}

func (f *fakeNetwork) Restore(_ context.Context, _ any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restoreCalls++
	f.log = append(f.log, "restore")
	if f.trace != nil {
		f.trace.record("restore")
	}
	var err error
	if len(f.restoreErrors) != 0 {
		err = f.restoreErrors[0]
		f.restoreErrors = f.restoreErrors[1:]
	}
	if err == nil {
		f.blocked = false
		f.active = false
	}
	return err
}

func (f *fakeNetwork) Reconcile(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconcileCalls++
	f.blocked = false
	f.active = false
	return nil
}

func (f *fakeNetwork) isBlocked() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.blocked }
func (f *fakeNetwork) isActive() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.active }

type fakeProcess struct {
	mu           sync.Mutex
	startErr     error
	readyErr     error
	stopErr      error
	readyGate    chan struct{}
	started      chan struct{}
	startOnce    sync.Once
	waitDone     chan struct{}
	waitErr      error
	exitOnce     sync.Once
	startCalls   int
	log          []string
	trace        *callTrace
	startContext context.Context
}

func newFakeProcess() *fakeProcess {
	return &fakeProcess{started: make(chan struct{}), waitDone: make(chan struct{})}
}

func (f *fakeProcess) Start(ctx context.Context, _ string, _ string) error {
	f.mu.Lock()
	f.startCalls++
	f.startContext = ctx
	f.log = append(f.log, "start")
	if f.trace != nil {
		f.trace.record("start")
	}
	err := f.startErr
	f.mu.Unlock()
	f.startOnce.Do(func() { close(f.started) })
	return err
}

func (f *fakeProcess) Ready(ctx context.Context) error {
	f.mu.Lock()
	f.log = append(f.log, "ready")
	if f.trace != nil {
		f.trace.record("ready")
	}
	gate, err := f.readyGate, f.readyErr
	f.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (f *fakeProcess) Stop(context.Context) error {
	f.mu.Lock()
	f.log = append(f.log, "stop")
	if f.trace != nil {
		f.trace.record("stop")
	}
	err := f.stopErr
	f.mu.Unlock()
	f.exit(nil)
	return err
}

func (f *fakeProcess) Wait() error {
	<-f.waitDone
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.waitErr
}

func (f *fakeProcess) exit(err error) {
	f.exitOnce.Do(func() {
		f.mu.Lock()
		f.waitErr = err
		f.mu.Unlock()
		close(f.waitDone)
	})
}

func (f *fakeProcess) waitForStart(t *testing.T) {
	t.Helper()
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("process did not start")
	}
}

type callTrace struct {
	mu    sync.Mutex
	items []string
}

func (c *callTrace) record(item string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, item)
}

func (c *callTrace) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.items...)
}

func waitForState(t *testing.T, controller *Controller, want accessmodel.ConnectionState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if controller.Status().State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state = %s, want %s", controller.Status().State, want)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
