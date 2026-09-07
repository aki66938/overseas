package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/traceevent"
)

func TestErrorCodePreparedContracts(t *testing.T) {
	got := []string{
		ErrorPreparedUnavailable,
		ErrorNetworkChanged,
		ErrorFirewallEnable,
		ErrorFirewallVerify,
		ErrorTUNNotFound,
		ErrorTUNIdentityMismatch,
		ErrorAutomaticRestore,
	}
	want := []string{
		"prepared_state_unavailable",
		"network_changed",
		"firewall_enable_failed",
		"firewall_verify_failed",
		"tun_not_found",
		"tun_identity_mismatch",
		"automatic_restore_failed",
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("error code %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestControllerSuccessfulConnectEmitsOrderedStagePairs(t *testing.T) {
	sink := &recordingTraceSink{}
	deps := testDependencies(nil)
	deps.Trace = sink
	policy := accessmodel.Policy{
		SchemaVersion: 2, Mode: "poc",
		Nodes:          []accessmodel.Node{{ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 8080}},
		CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"},
		BlockUDP: true, BlockQUIC: true,
	}
	controller := NewController(policy, newFakeNetwork(), newFakeProcess(), WithDependencies(deps))
	if status := controller.Connect(context.Background()); status.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", status)
	}
	events := sink.eventsCopy()
	want := []string{
		"request_received:state",
		"policy_validation:started", "policy_validation:succeeded",
		"binary_verification:started", "binary_verification:succeeded",
		"network_prepare:started", "network_prepare:succeeded",
		"network_capture:started", "network_capture:succeeded",
		"firewall_enable:started", "firewall_enable:succeeded",
		"config_render:started", "config_render:succeeded",
		"core_start:started", "core_start:succeeded",
		"core_ready:started", "core_ready:succeeded",
		"tun_ready:started", "tun_ready:succeeded",
		"route_activation:started", "route_activation:succeeded",
		"connected:state",
		"monitor_start:started", "monitor_start:succeeded",
	}
	if got := traceKeys(events); !equalStrings(got, want) {
		t.Fatalf("trace order = %v, want %v", got, want)
	}
	for _, event := range events {
		if event.Generation != 1 {
			t.Fatalf("event generation = %d: %#v", event.Generation, event)
		}
		if event.Event != traceevent.EventStarted && event.Event != traceevent.EventState && event.ElapsedMS == nil {
			t.Fatalf("terminal event has no elapsed time: %#v", event)
		}
	}
	controller.Disconnect(context.Background())
}

func TestControllerConnectRunsStepsInFailClosedOrder(t *testing.T) {
	trace := &callTrace{}
	network := newFakeNetwork()
	network.trace = trace
	process := newFakeProcess()
	process.trace = trace
	controller := newTestController(network, process, testDependencies(trace))

	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}
	want := []string{"validate", "verify", "credential", "prepare", "capture", "enable", "render", "write", "start", "ready", "tun", "activate", "monitor"}
	if calls := trace.calls(); !equalStrings(calls, want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
	controller.Disconnect(context.Background())
}

func TestControllerConnectedStatusCarriesPhaseStepsAndElapsed(t *testing.T) {
	network := newFakeNetwork()
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StateConnected || got.Phase != PhaseConnected || got.Step != 6 || got.TotalSteps != connectionTotalSteps {
		t.Fatalf("connected status = %#v", got)
	}
	if got.ElapsedMS < 0 {
		t.Fatalf("negative elapsed time: %#v", got)
	}
	controller.Disconnect(context.Background())
}

func TestControllerLifecycleSnapshotTracksConnectedTimeAndQualityByGeneration(t *testing.T) {
	now := time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)
	deps := testDependencies(nil)
	deps.Now = func() time.Time { return now }
	deps.LoadCredential = func(context.Context, accessmodel.CredentialRef) (Credential, error) {
		return Credential{Method: "2022-blake3-aes-128-gcm", Password: []byte("secret"), ExpiresAt: now.Add(24 * time.Hour)}, nil
	}
	controller := newTestController(newFakeNetwork(), newFakeProcess(), deps)

	if status := controller.Connect(context.Background()); status.State != accessmodel.StateConnected {
		t.Fatalf("connect = %#v", status)
	}
	first := controller.LocalStatusSnapshot()
	if first.Generation != 1 || first.ConnectedAt != now || first.Quality != LineQualityUnknown {
		t.Fatalf("first snapshot = %#v", first)
	}
	now = now.Add(time.Minute)
	controller.Connect(context.Background())
	if repeated := controller.LocalStatusSnapshot(); repeated.ConnectedAt != first.ConnectedAt || repeated.Generation != first.Generation {
		t.Fatalf("repeated connect reset lifecycle: %#v", repeated)
	}
	if !controller.UpdateLineQuality(first.Generation, LineQualitySlow) {
		t.Fatal("current connected quality rejected")
	}
	if got := controller.LocalStatusSnapshot(); got.Status.State != accessmodel.StateConnected || got.Quality != LineQualitySlow || got.ConnectedAt != first.ConnectedAt {
		t.Fatalf("quality changed lifecycle fields: %#v", got)
	}
	if controller.UpdateLineQuality(first.Generation-1, LineQualityGood) {
		t.Fatal("stale quality accepted")
	}
	if controller.UpdateLineQuality(first.Generation, "excellent") {
		t.Fatal("invalid quality accepted")
	}

	now = now.Add(time.Hour)
	controller.Disconnect(context.Background())
	disconnected := controller.LocalStatusSnapshot()
	if disconnected.ConnectedAt != (time.Time{}) || disconnected.Quality != LineQualityUnknown {
		t.Fatalf("disconnect snapshot = %#v", disconnected)
	}
	if controller.UpdateLineQuality(disconnected.Generation, LineQualityGood) {
		t.Fatal("disconnected quality accepted")
	}

	now = now.Add(time.Hour)
	controller.Connect(context.Background())
	reconnected := controller.LocalStatusSnapshot()
	if reconnected.Generation != 3 || reconnected.ConnectedAt != now || reconnected.Quality != LineQualityUnknown {
		t.Fatalf("reconnect snapshot = %#v", reconnected)
	}
	controller.Disconnect(context.Background())
}

func TestControllerEmptyNetworkDetailStillEmitsDiagnosticFailure(t *testing.T) {
	sink := &recordingTraceSink{}
	network := newFakeNetwork()
	network.enableErr = testDiagnosticError{stage: traceevent.StageFirewallEnable}
	deps := testDependencies(nil)
	deps.Trace = sink
	controller := newTestController(network, newFakeProcess(), deps)

	status := controller.Connect(context.Background())
	diagnostics := controller.Diagnostics()
	if status.ErrorCode != ErrorFirewallEnable || diagnostics.Stage != traceevent.StageFirewallEnable || diagnostics.Detail == "" {
		t.Fatalf("status=%#v diagnostics=%#v", status, diagnostics)
	}
	last := sink.eventsCopy()[len(sink.eventsCopy())-1]
	if last.Stage != traceevent.StageAutomaticRestore || last.Event != traceevent.EventSucceeded {
		t.Fatalf("last trace = %#v, want automatic restore success", last)
	}
}

func TestControllerDisconnectRequiresZeroResidue(t *testing.T) {
	sink := &recordingTraceSink{}
	deps := testDependencies(nil)
	deps.Trace = sink
	network := newFakeNetwork()
	controller := newTestController(network, newFakeProcess(), deps)
	if status := controller.Connect(context.Background()); status.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", status)
	}
	network.mu.Lock()
	network.residue = traceevent.Residue{ManagedRules: 1}
	network.mu.Unlock()
	if status := controller.Disconnect(context.Background()); status.ErrorCode != ErrorAutomaticRestore || status.State != accessmodel.StateFailedSafe {
		t.Fatalf("Disconnect() = %#v", status)
	}
	events := sink.eventsCopy()
	last := events[len(events)-1]
	if last.Stage != traceevent.StageResidueVerify || last.Event != traceevent.EventFailed || last.Residue == nil || last.Residue.ManagedRules != 1 {
		t.Fatalf("last trace = %#v", last)
	}
}

func TestControllerRecoveryEmitsRecoveryAndZeroResidue(t *testing.T) {
	sink := &recordingTraceSink{}
	deps := testDependencies(nil)
	deps.Trace = sink
	network := newFakeNetwork()
	network.blocked = true
	controller := newTestController(network, newFakeProcess(), deps)
	if status := controller.Recover(context.Background()); status.State != accessmodel.StatePrepared {
		t.Fatalf("Recover() = %#v", status)
	}
	keys := traceKeys(sink.eventsCopy())
	for _, want := range []string{"service_recovery:started", "network_restore:started", "network_restore:succeeded", "residue_verify:started", "residue_verify:succeeded", "service_recovery:succeeded"} {
		if !containsString(keys, want) {
			t.Fatalf("trace %q missing from %v", want, keys)
		}
	}
}

func TestControllerTraceGenerationsAreIsolatedAndPaired(t *testing.T) {
	sink := &recordingTraceSink{}
	deps := testDependencies(nil)
	deps.Trace = sink
	controller := newTestController(newFakeNetwork(), newFakeProcess(), deps)
	if status := controller.Connect(context.Background()); status.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", status)
	}
	if status := controller.Disconnect(context.Background()); status.State != accessmodel.StatePrepared {
		t.Fatalf("Disconnect() = %#v", status)
	}
	events := sink.eventsCopy()
	seenSecond := false
	for _, event := range events {
		if event.Generation == 2 {
			seenSecond = true
		}
		if event.Generation == 0 || event.Generation > 2 || (seenSecond && event.Generation == 1) {
			t.Fatalf("generation order is invalid: %#v", events)
		}
	}
	assertTracePairs(t, events)
}

func TestControllerCanceledBeforeWorkHasOnlyStateEvent(t *testing.T) {
	sink := &recordingTraceSink{}
	deps := testDependencies(nil)
	deps.Trace = sink
	controller := newTestController(newFakeNetwork(), newFakeProcess(), deps)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if status := controller.Connect(ctx); status.ErrorCode != ErrorCanceled {
		t.Fatalf("Connect() = %#v", status)
	}
	assertTracePairs(t, sink.eventsCopy())
}

func TestControllerSuccessfulRestoreClearsPreviousDiagnostic(t *testing.T) {
	network := newFakeNetwork()
	network.enableErr = testDiagnosticError{stage: traceevent.StageFirewallEnable, detail: "enable failed"}
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))
	if status := controller.Connect(context.Background()); status.ErrorCode != ErrorFirewallEnable {
		t.Fatalf("Connect() = %#v", status)
	}
	network.mu.Lock()
	network.enableErr = nil
	network.mu.Unlock()
	if status := controller.Disconnect(context.Background()); status.State != accessmodel.StatePrepared {
		t.Fatalf("Disconnect() = %#v", status)
	}
	if diagnostics := controller.Diagnostics(); diagnostics.Stage != "" || diagnostics.Detail != "" {
		t.Fatalf("stale diagnostics = %#v", diagnostics)
	}
}

func TestControllerConnectFailureRunsAutomaticRestore(t *testing.T) {
	trace := &callTrace{}
	network := newFakeNetwork()
	network.trace = trace
	process := newFakeProcess()
	process.trace = trace
	process.startErr = errors.New("upstream unavailable")
	controller := newTestController(network, process, testDependencies(trace))

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StatePrepared || got.ErrorCode != ErrorCoreStart {
		t.Fatalf("Connect() = %#v", got)
	}
	if network.isBlocked() || network.isActive() {
		t.Fatalf("failed connect left network mutated: blocked = %v", network.isBlocked())
	}
	if network.restoreCalls != 1 {
		t.Fatalf("failed connect restored the network %d times", network.restoreCalls)
	}
	want := []string{"validate", "verify", "credential", "prepare", "capture", "enable", "render", "write", "start", "restore"}
	if calls := trace.calls(); !equalStrings(calls, want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
}

func TestControllerConnectFailureMatrixReturnsPreparedWithOriginalCode(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*fakeNetwork, *fakeProcess, *Dependencies)
		code string
	}{
		{
			name: "prepare failure",
			mut: func(n *fakeNetwork, _ *fakeProcess, _ *Dependencies) {
				n.prepareErr = errors.New("baseline unreadable")
			},
			code: ErrorPreparedUnavailable,
		},
		{
			name: "capture failure",
			mut: func(n *fakeNetwork, _ *fakeProcess, _ *Dependencies) {
				n.captureErr = errors.New("fingerprint drifted")
			},
			code: ErrorNetworkCapture,
		},
		{
			name: "firewall enable failure",
			mut:  func(n *fakeNetwork, _ *fakeProcess, _ *Dependencies) { n.enableErr = errors.New("enable rejected") },
			code: ErrorFirewallEnable,
		},
		{
			name: "firewall verify failure",
			mut: func(n *fakeNetwork, _ *fakeProcess, _ *Dependencies) {
				n.enableErr = testDiagnosticError{stage: traceevent.StageFirewallVerify, detail: "definition drifted"}
			},
			code: ErrorFirewallVerify,
		},
		{
			name: "config render failure",
			mut: func(_ *fakeNetwork, _ *fakeProcess, d *Dependencies) {
				d.RenderConfig = func(accessmodel.Policy, Credential) ([]byte, error) { return nil, errors.New("render failed") }
			},
			code: ErrorRender,
		},
		{
			name: "core start failure",
			mut:  func(_ *fakeNetwork, p *fakeProcess, _ *Dependencies) { p.startErr = errors.New("launch failed") },
			code: ErrorCoreStart,
		},
		{
			name: "core ready failure",
			mut:  func(_ *fakeNetwork, p *fakeProcess, _ *Dependencies) { p.readyErr = errors.New("core never ready") },
			code: ErrorCoreNotReady,
		},
		{
			name: "tun not found",
			mut: func(n *fakeNetwork, _ *fakeProcess, _ *Dependencies) {
				n.readyErr = fmt.Errorf("%w: deadline", errTUNNotFound)
			},
			code: ErrorTUNNotFound,
		},
		{
			name: "tun identity mismatch",
			mut: func(n *fakeNetwork, _ *fakeProcess, _ *Dependencies) {
				n.readyErr = fmt.Errorf("%w: wrong guid", errTUNIdentityMismatch)
			},
			code: ErrorTUNIdentityMismatch,
		},
		{
			name: "route activation failure",
			mut:  func(n *fakeNetwork, _ *fakeProcess, _ *Dependencies) { n.activateErr = errors.New("route failed") },
			code: ErrorRouteActivationFailed,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := newFakeNetwork()
			process := newFakeProcess()
			deps := testDependencies(nil)
			testCase.mut(network, process, &deps)
			controller := newTestController(network, process, deps)

			got := controller.Connect(context.Background())

			if got.State != accessmodel.StatePrepared || got.ErrorCode != testCase.code {
				t.Fatalf("Connect() = %#v, want prepared/%s", got, testCase.code)
			}
			if network.isBlocked() || network.isActive() {
				t.Fatalf("network left mutated: blocked=%v active=%v", network.isBlocked(), network.isActive())
			}
			if !network.lastResidue().IsZero() {
				t.Fatalf("active residue was not proven zero: %#v", network.lastResidue())
			}
			if testCase.code == ErrorPreparedUnavailable || testCase.code == ErrorNetworkCapture {
				if network.restoreCalls != 0 {
					t.Fatalf("pre-mutation failure ran Restore() %d times", network.restoreCalls)
				}
				if network.reconcileCalls != 1 {
					t.Fatalf("pre-mutation failure must reconcile once, got %d", network.reconcileCalls)
				}
			} else if network.restoreCalls != 1 {
				t.Fatalf("Restore() calls = %d, want 1", network.restoreCalls)
			}
			// A failed attempt returns to the connectable prepared state; a
			// fresh controller must connect without a preliminary Disconnect.
			fixed := newFakeNetwork()
			fixedController := newTestController(fixed, newFakeProcess(), testDependencies(nil))
			if retry := fixedController.Connect(context.Background()); retry.State != accessmodel.StateConnected {
				t.Fatalf("retry after prepared failure = %#v", retry)
			}
			fixedController.Disconnect(context.Background())
		})
	}
}

func TestControllerPublishesTypedNetworkDiagnosticWithoutChangingStatus(t *testing.T) {
	network := newFakeNetwork()
	network.enableErr = testDiagnosticError{stage: "firewall_enable", detail: "The specified interface was not found."}
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))

	status := controller.Connect(context.Background())
	diagnostics := controller.Diagnostics()

	if status.ErrorCode != ErrorFirewallEnable || status.Message != "无法启用防泄漏保护" {
		t.Fatalf("status = %#v", status)
	}
	if diagnostics.Stage != "firewall_enable" || diagnostics.Detail != "The specified interface was not found." {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestControllerSynthesizesIncompleteNetworkDiagnostic(t *testing.T) {
	network := newFakeNetwork()
	network.enableErr = testDiagnosticError{detail: "unclassified native failure"}
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))

	_ = controller.Connect(context.Background())
	diagnostics := controller.Diagnostics()

	if diagnostics.Stage != traceevent.StageFirewallEnable || diagnostics.Detail == "" {
		t.Fatalf("incomplete diagnostics were not synthesized: %#v", diagnostics)
	}
}

type testDiagnosticError struct{ stage, detail string }

func (e testDiagnosticError) Error() string            { return "fixed network operation failed" }
func (e testDiagnosticError) DiagnosticStage() string  { return e.stage }
func (e testDiagnosticError) DiagnosticDetail() string { return e.detail }

func TestControllerDisconnectRestoresCapturedState(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))

	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}
	got := controller.Disconnect(context.Background())

	if got.State != accessmodel.StatePrepared || network.isBlocked() || network.isActive() {
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

	if got.State != accessmodel.StatePrepared {
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

	if got := controller.Recover(context.Background()); got.State != accessmodel.StatePrepared {
		t.Fatalf("Recover() = %#v", got)
	}
	if got := controller.Recover(context.Background()); got.State != accessmodel.StatePrepared {
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

	if got.State != accessmodel.StatePrepared || got.ErrorCode != ErrorInvalidPolicy {
		t.Fatalf("Connect() = %#v", got)
	}
	if network.captureCalls != 0 || network.enableCalls != 0 {
		t.Fatalf("network mutated after invalid policy: capture=%d enable=%d", network.captureCalls, network.enableCalls)
	}
}

func TestControllerBadBinaryFailsBeforeNetworkMutation(t *testing.T) {
	network := newFakeNetwork()
	deps := testDependencies(nil)
	deps.VerifyExecutable = func(string) error { return errors.New("hash mismatch") }
	controller := newTestController(network, newFakeProcess(), deps)

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StatePrepared || got.ErrorCode != ErrorInvalidBinary {
		t.Fatalf("Connect() = %#v", got)
	}
	if network.captureCalls != 0 || network.enableCalls != 0 {
		t.Fatalf("network mutated after invalid binary: capture=%d enable=%d", network.captureCalls, network.enableCalls)
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

	if got.State != accessmodel.StatePrepared || got.ErrorCode != ErrorExpiredCredential {
		t.Fatalf("Connect() = %#v", got)
	}
	if network.captureCalls != 0 || network.enableCalls != 0 {
		t.Fatalf("network mutated after expired credential: capture=%d enable=%d", network.captureCalls, network.enableCalls)
	}
}

func TestControllerSchemaTwoConnectDoesNotLoadCredential(t *testing.T) {
	loads := 0
	deps := testDependencies(nil)
	deps.LoadCredential = func(context.Context, accessmodel.CredentialRef) (Credential, error) {
		loads++
		return Credential{}, errors.New("credential must not be requested")
	}
	policy := accessmodel.Policy{
		SchemaVersion: 2, Mode: "poc",
		Nodes:          []accessmodel.Node{{ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 8080}},
		CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"},
		BlockUDP: true, BlockQUIC: true,
	}
	controller := NewController(policy, newFakeNetwork(), newFakeProcess(), WithDependencies(deps))

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v, want connected", got)
	}
	if loads != 0 {
		t.Fatalf("LoadCredential calls = %d, want 0", loads)
	}
	controller.Disconnect(context.Background())
}

func TestControllerReadinessLossAutoRestoresToPrepared(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}

	process.exit(errors.New("core exited"))
	waitForState(t, controller, accessmodel.StatePrepared)

	if network.isBlocked() || network.isActive() {
		t.Fatalf("readiness loss left network mutated: blocked=%v active=%v", network.isBlocked(), network.isActive())
	}
	if got := controller.Status(); got.ErrorCode != ErrorReadinessLost {
		t.Fatalf("Status() = %#v", got)
	}
	if network.restoreCalls != 1 {
		t.Fatalf("Restore() calls = %d, want 1", network.restoreCalls)
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

	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StateFailedSafe || got.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("first Disconnect() = %#v", got)
	}
	if !network.isBlocked() {
		t.Fatal("failed restore unexpectedly removed the public TCP block")
	}
	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StatePrepared {
		t.Fatalf("second Disconnect() = %#v", got)
	}
	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StatePrepared {
		t.Fatalf("third Disconnect() = %#v", got)
	}
	if network.restoreCalls != 2 {
		t.Fatalf("Restore() calls = %d, want 2", network.restoreCalls)
	}
}

func TestControllerStopFailureRetainsLeakBlockAndSkipsRestore(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}
	process.stopErr = errors.New("could not prove process tree termination")
	process.stopProven = false

	got := controller.Disconnect(context.Background())

	if got.State != accessmodel.StateFailedSafe || got.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("Disconnect() = %#v", got)
	}
	if network.restoreCalls != 0 {
		t.Fatalf("Restore() calls = %d, want 0", network.restoreCalls)
	}
	if !network.isBlocked() {
		t.Fatal("process stop failure removed the public leak block")
	}
	if retry := controller.Connect(context.Background()); retry.State != accessmodel.StateFailedSafe || retry.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("Connect() after unproven stop = %#v", retry)
	}
	if process.startCalls != 1 {
		t.Fatalf("Start() calls after unproven stop = %d, want 1", process.startCalls)
	}
}

func TestControllerStartupFailureWithUnprovenStopRetainsLeakBlock(t *testing.T) {
	network := newFakeNetwork()
	network.activateErr = errors.New("route activation failed")
	process := newFakeProcess()
	process.stopErr = errors.New("could not prove process tree termination")
	process.stopProven = false
	controller := newTestController(network, process, testDependencies(nil))

	if got := controller.Connect(context.Background()); got.State != accessmodel.StateFailedSafe || got.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("Connect() = %#v", got)
	}
	got := controller.Disconnect(context.Background())

	if got.State != accessmodel.StateFailedSafe || got.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("Disconnect() = %#v", got)
	}
	if network.restoreCalls != 0 || !network.isBlocked() {
		t.Fatalf("startup stop failure restored network: restore calls=%d blocked=%v", network.restoreCalls, network.isBlocked())
	}
	if process.stopCalls != 2 {
		t.Fatalf("Stop() calls = %d, want initial attempt plus disconnect retry", process.stopCalls)
	}
}

func TestControllerStartCleanupFailureRetainsProtectionAndDeniesRelaunch(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	process.startErr = errors.New("native launch cleanup failed")
	process.startProven = false
	process.stopErr = errors.New("native process termination remains unproven")
	process.stopProven = false
	controller := newTestController(network, process, testDependencies(nil))

	if got := controller.Connect(context.Background()); got.State != accessmodel.StateFailedSafe || got.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("Connect() = %#v", got)
	}
	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StateFailedSafe || got.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("Disconnect() = %#v", got)
	}
	if network.restoreCalls != 0 || !network.isBlocked() {
		t.Fatalf("start cleanup failure restored protection: restore=%d blocked=%v", network.restoreCalls, network.isBlocked())
	}
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateFailedSafe {
		t.Fatalf("relaunch after unproven start = %#v", got)
	}
	if process.startCalls != 1 {
		t.Fatalf("Start() calls = %d, want 1", process.startCalls)
	}
}

func TestControllerRestoresAfterExitErrorWhenTreeTerminationIsProven(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}
	process.exit(errors.New("unexpected exit"))
	waitForState(t, controller, accessmodel.StatePrepared)

	got := controller.Disconnect(context.Background())

	if got.State != accessmodel.StatePrepared || network.isBlocked() {
		t.Fatalf("Disconnect() = %#v blocked=%v", got, network.isBlocked())
	}
	if network.restoreCalls != 1 {
		t.Fatalf("Restore() calls = %d, want exactly the automatic restore", network.restoreCalls)
	}
}

func TestControllerUnexpectedExitCleanupFailureDeniesReconnectAndRestore(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	process.waitProven = false
	process.stopProven = false
	process.stopErr = errors.New("job tree confirmation failed")
	controller := newTestController(network, process, testDependencies(nil))
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}
	process.exit(errors.New("unexpected exit with cleanup failure"))
	waitForState(t, controller, accessmodel.StateFailedSafe)

	if got := controller.Connect(context.Background()); got.State != accessmodel.StateFailedSafe || got.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("reconnect after unproven unexpected exit = %#v", got)
	}
	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StateFailedSafe || got.ErrorCode != ErrorAutomaticRestore {
		t.Fatalf("Disconnect() = %#v", got)
	}
	if network.restoreCalls != 0 || !network.isBlocked() || process.startCalls != 1 {
		t.Fatalf("cleanup failure state: restore=%d blocked=%v starts=%d", network.restoreCalls, network.isBlocked(), process.startCalls)
	}
}

func TestControllerDisconnectRaceWithUnexpectedExitHasOneTerminalOwner(t *testing.T) {
	for range 25 {
		network := newFakeNetwork()
		process := newFakeProcess()
		controller := newTestController(network, process, testDependencies(nil))
		if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
			t.Fatalf("Connect() = %#v", got)
		}
		start := make(chan struct{})
		result := make(chan Status, 1)
		go func() {
			<-start
			result <- controller.Disconnect(context.Background())
		}()
		close(start)
		process.exit(errors.New("unexpected exit during disconnect"))
		if got := <-result; got.State != accessmodel.StatePrepared {
			t.Fatalf("Disconnect() = %#v", got)
		}
		waitForState(t, controller, accessmodel.StatePrepared)
		if network.restoreCalls != 1 || network.isBlocked() {
			t.Fatalf("terminal race restore=%d blocked=%v", network.restoreCalls, network.isBlocked())
		}
	}
}

func TestControllerDelayedGenerationACannotConsumeGenerationBTermination(t *testing.T) {
	network := newFakeNetwork()
	a := newFakeProcess()
	a.stopSignalsDone = false
	b := newFakeProcess()
	factory := &queuedProcessSupervisor{instances: []*fakeProcess{a, b}}
	controller := NewController(validPolicy(), network, factory, WithDependencies(testDependencies(nil)))

	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect(A) = %#v", got)
	}
	oldFailures := network.failures
	if got := controller.Disconnect(context.Background()); got.State != accessmodel.StatePrepared {
		t.Fatalf("Disconnect(A) = %#v", got)
	}
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect(B) = %#v", got)
	}

	// A's terminal channel is generation-owned. A delayed duplicate event may
	// never be observed by B's monitor, nor may A's canceled monitor observe B.
	oldFailures <- errors.New("delayed generation A protection event")
	a.tryExit(errors.New("delayed generation A process event"))
	time.Sleep(10 * time.Millisecond)
	if got := controller.Status(); got.State != accessmodel.StateConnected {
		t.Fatalf("delayed generation A event changed B: %#v", got)
	}
	b.mu.Lock()
	bStops := b.stopCalls
	b.mu.Unlock()
	if bStops != 0 {
		t.Fatalf("delayed generation A event stopped B %d times", bStops)
	}
	b.exit(errors.New("generation B exited"))
	waitForState(t, controller, accessmodel.StatePrepared)
	if got := controller.Status(); got.ErrorCode != ErrorReadinessLost {
		t.Fatalf("Status(B) = %#v", got)
	}
}

func TestControllerTUNIdentityFailureAutoRestores(t *testing.T) {
	network := newFakeNetwork()
	network.readyErr = fmt.Errorf("%w: identity was not proven", errTUNIdentityMismatch)
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StatePrepared || got.ErrorCode != ErrorTUNIdentityMismatch {
		t.Fatalf("Connect() = %#v", got)
	}
	if network.isBlocked() || network.isActive() || network.activateCalls != 0 || process.stopCalls != 1 {
		t.Fatalf("identity failure state: blocked=%v activate=%d stop=%d", network.isBlocked(), network.activateCalls, process.stopCalls)
	}
}

func TestControllerTUNNotFoundMapsToDedicatedCode(t *testing.T) {
	network := newFakeNetwork()
	network.readyErr = fmt.Errorf("%w: deadline expired", errTUNNotFound)
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StatePrepared || got.ErrorCode != ErrorTUNNotFound {
		t.Fatalf("Connect() = %#v", got)
	}
}

func TestControllerMonitorFailureAutoRestores(t *testing.T) {
	network := newFakeNetwork()
	process := newFakeProcess()
	controller := newTestController(network, process, testDependencies(nil))
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}

	network.failures <- errors.New("adapter reconciliation failed")
	waitForState(t, controller, accessmodel.StatePrepared)

	if network.isBlocked() || network.isActive() || network.restoreCalls != 1 || process.stopCalls != 1 {
		t.Fatalf("monitor failure state: blocked=%v restore=%d stop=%d", network.isBlocked(), network.restoreCalls, process.stopCalls)
	}
	if got := controller.Status(); got.ErrorCode != ErrorReadinessLost {
		t.Fatalf("Status() = %#v", got)
	}
}

func TestControllerNetworkChangedMonitorFailureKeepsCausalCode(t *testing.T) {
	network := newFakeNetwork()
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))
	if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v", got)
	}

	network.failures <- fmt.Errorf("%w: fingerprint drift", errNetworkChanged)
	waitForState(t, controller, accessmodel.StatePrepared)

	if got := controller.Status(); got.ErrorCode != ErrorNetworkChanged {
		t.Fatalf("Status() = %#v", got)
	}
}

func TestControllerRouteActivationFailureAutoRestores(t *testing.T) {
	network := newFakeNetwork()
	network.activateErr = errors.New("route failed")
	controller := newTestController(network, newFakeProcess(), testDependencies(nil))

	got := controller.Connect(context.Background())

	if got.State != accessmodel.StatePrepared || got.ErrorCode != ErrorRouteActivationFailed || network.isBlocked() {
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
	enableCalls    int
	monitorCalls   int
	activateCalls  int
	restoreCalls   int
	reconcileCalls int
	restoreErrors  []error
	activateErr    error
	readyErr       error
	prepareErr     error
	captureErr     error
	enableErr      error
	log            []string
	trace          *callTrace
	failures       chan error
	residue        traceevent.Residue
	lastResidueVar traceevent.Residue
	residueErr     error
}

func newFakeNetwork() *fakeNetwork { return &fakeNetwork{failures: make(chan error, 1)} }

func (f *fakeNetwork) Prepare(context.Context) (PreparedNetwork, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.trace != nil {
		f.trace.record("prepare")
	}
	if f.prepareErr != nil {
		return PreparedNetwork{}, f.prepareErr
	}
	return PreparedNetwork{Generation: 1, Fingerprint: "fingerprint", AdapterCount: 7, RuleCount: 10}, nil
}

func (f *fakeNetwork) Capture(_ context.Context, _ PreparedNetwork) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captureCalls++
	f.log = append(f.log, "capture")
	if f.trace != nil {
		f.trace.record("capture")
	}
	if f.captureErr != nil {
		return nil, f.captureErr
	}
	return "original", nil
}

func (f *fakeNetwork) EnableProtection(_ context.Context, _ PreparedNetwork) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableCalls++
	f.blocked = true
	f.log = append(f.log, "enable")
	if f.trace != nil {
		f.trace.record("enable")
	}
	if f.enableErr != nil {
		return f.enableErr
	}
	return nil
}

func (f *fakeNetwork) StartMonitor(_ context.Context, _ PreparedNetwork) (<-chan error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.monitorCalls++
	f.failures = make(chan error, 1)
	if f.trace != nil {
		f.trace.record("monitor")
	}
	return f.failures, nil
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

func (f *fakeNetwork) WaitTUNReady(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.trace != nil {
		f.trace.record("tun")
	}
	return f.readyErr
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

func (f *fakeNetwork) Residue(context.Context) (traceevent.Residue, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastResidueVar = f.residue
	return f.residue, f.residueErr
}

func (f *fakeNetwork) isBlocked() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.blocked }
func (f *fakeNetwork) isActive() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.active }
func (f *fakeNetwork) lastResidue() traceevent.Residue {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastResidueVar
}

type fakeProcess struct {
	mu              sync.Mutex
	startErr        error
	readyErr        error
	stopErr         error
	startProven     bool
	stopProven      bool
	waitProven      bool
	readyGate       chan struct{}
	started         chan struct{}
	startOnce       sync.Once
	done            chan ProcessTermination
	exitOnce        sync.Once
	startCalls      int
	stopCalls       int
	stopSignalsDone bool
	log             []string
	trace           *callTrace
	startContext    context.Context
}

func newFakeProcess() *fakeProcess {
	return &fakeProcess{started: make(chan struct{}), done: make(chan ProcessTermination, 1), startProven: true, stopProven: true, waitProven: true, stopSignalsDone: true}
}

func (f *fakeProcess) Start(ctx context.Context, _ string, _ string) (ProcessInstance, ProcessStartResult) {
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
	return f, ProcessStartResult{Err: err, TerminationProven: f.startProven}
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

func (f *fakeProcess) Stop(context.Context) ProcessTermination {
	f.mu.Lock()
	f.stopCalls++
	f.log = append(f.log, "stop")
	if f.trace != nil {
		f.trace.record("stop")
	}
	err := f.stopErr
	f.mu.Unlock()
	if f.stopSignalsDone {
		f.exit(nil)
	}
	return ProcessTermination{Err: err, Proven: f.stopProven}
}

func (f *fakeProcess) Done() <-chan ProcessTermination { return f.done }

func (f *fakeProcess) exit(err error) {
	f.exitOnce.Do(func() {
		f.mu.Lock()
		termination := ProcessTermination{Err: err, Proven: f.waitProven}
		f.mu.Unlock()
		f.done <- termination
	})
}

func (f *fakeProcess) tryExit(err error) { f.exit(err) }

type queuedProcessSupervisor struct {
	mu        sync.Mutex
	instances []*fakeProcess
}

func (f *queuedProcessSupervisor) Start(ctx context.Context, executable, config string) (ProcessInstance, ProcessStartResult) {
	f.mu.Lock()
	if len(f.instances) == 0 {
		f.mu.Unlock()
		return nil, ProcessStartResult{Err: errors.New("no queued process"), TerminationProven: true}
	}
	instance := f.instances[0]
	f.instances = f.instances[1:]
	f.mu.Unlock()
	return instance.Start(ctx, executable, config)
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

type recordingTraceSink struct {
	mu     sync.Mutex
	events []traceevent.Event
}

func (r *recordingTraceSink) Record(event traceevent.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *recordingTraceSink) eventsCopy() []traceevent.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]traceevent.Event(nil), r.events...)
}

func traceKeys(events []traceevent.Event) []string {
	keys := make([]string, 0, len(events))
	for _, event := range events {
		keys = append(keys, event.Stage+":"+event.Event)
	}
	return keys
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertTracePairs(t *testing.T, events []traceevent.Event) {
	t.Helper()
	balances := map[string]int{}
	for _, event := range events {
		key := fmt.Sprintf("%d/%s", event.Generation, event.Stage)
		switch event.Event {
		case traceevent.EventStarted:
			balances[key]++
		case traceevent.EventSucceeded, traceevent.EventFailed:
			balances[key]--
			if balances[key] < 0 {
				t.Fatalf("terminal event without start for %s: %#v", key, events)
			}
		}
	}
	for key, balance := range balances {
		if balance != 0 {
			t.Fatalf("unpaired trace stage %s balance=%d: %#v", key, balance, events)
		}
	}
}
