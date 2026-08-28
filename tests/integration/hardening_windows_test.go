//go:build windows

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/tests/integration/fixtureproto"
)

func TestTrustedBaselineRecreatesRestoreInputAfterEvidenceTamper(t *testing.T) {
	caseDir := t.TempDir()
	evidencePath := filepath.Join(caseDir, "baseline.json")
	want := []byte(`{"adapters":[{"id":"a"}]}`)
	custody, err := newTrustedBaseline(caseDir, evidencePath, want)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()

	if err := os.WriteFile(evidencePath, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	restorePath, err := custody.RestoreInput()
	if err != nil {
		t.Fatal(err)
	}
	if restorePath == evidencePath || restorePath == custody.trustedPath {
		t.Fatalf("RestoreInput() = %q, want a newly recreated trusted input", restorePath)
	}
	got, err := os.ReadFile(restorePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("restore input = %s, want %s", got, want)
	}
	if err := custody.Verify(); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
}

func TestTrustedBaselineOpenHandleDeniesModification(t *testing.T) {
	caseDir := t.TempDir()
	evidencePath := filepath.Join(caseDir, "baseline.json")
	custody, err := newTrustedBaseline(caseDir, evidencePath, []byte(`{"trusted":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()

	if err := os.WriteFile(custody.trustedPath, []byte("replacement"), 0o600); err == nil {
		t.Fatal("trusted baseline could be modified while its custody handle was open")
	}
}

func TestTrustedBaselinePinsCaseDirectoryAgainstReplacement(t *testing.T) {
	root := t.TempDir()
	caseDir := filepath.Join(root, "case")
	if err := os.Mkdir(caseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	custody, err := newTrustedBaseline(caseDir, filepath.Join(caseDir, "baseline.json"), []byte(`{"trusted":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	if err := os.Rename(caseDir, filepath.Join(root, "moved")); err == nil {
		t.Fatal("baseline case directory could be replaced while custody was active")
	}
	if err := custody.Verify(); err != nil {
		t.Fatalf("custody verify after replacement attempt: %v", err)
	}
}

func TestRestorationUsesIndependentBudgetsAndStillRunsRestoreAfterHungCleanup(t *testing.T) {
	var mu sync.Mutex
	called := make([]string, 0, 2)
	cleanup := func(ctx context.Context) error {
		mu.Lock()
		called = append(called, "cleanup")
		mu.Unlock()
		select {}
	}
	restore := func(ctx context.Context) error {
		mu.Lock()
		called = append(called, "restore")
		mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	started := time.Now()
	type result struct{ cleanup, restore error }
	done := make(chan result, 1)
	go func() {
		cleanupErr, restoreErr := runRestorationActions(cleanup, restore, 25*time.Millisecond, 250*time.Millisecond)
		done <- result{cleanupErr, restoreErr}
	}()
	var cleanupErr, restoreErr error
	select {
	case outcome := <-done:
		cleanupErr, restoreErr = outcome.cleanup, outcome.restore
	case <-time.After(200 * time.Millisecond):
		t.Fatal("non-cooperative cleanup prevented prioritized restore")
	}
	if !errors.Is(cleanupErr, context.DeadlineExceeded) {
		t.Fatalf("cleanup error = %v, want deadline", cleanupErr)
	}
	if restoreErr != nil {
		t.Fatalf("restore error = %v", restoreErr)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("independent restore was starved by cleanup: %v", elapsed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(called) != 2 || called[0] != "cleanup" || called[1] != "restore" {
		t.Fatalf("calls = %v, want cleanup then restore", called)
	}
}

func TestCallDriverRejectsStaleBoundResponse(t *testing.T) {
	harness := boundHarness(t)
	harness.invokeDriver = func(_ context.Context, request fixtureproto.Request) ([]byte, error) {
		response := boundResponse(request, harness.config.binding)
		response.RequestNonce = "stale-response"
		return json.Marshal(response)
	}
	_, err := harness.callDriver(context.Background(), fixtureproto.Request{Action: "capture", Scenario: "core-exits"})
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("callDriver() = %v, want stale nonce refusal", err)
	}
}

func TestCallDriverRejectsConstantForgedSnapshotHash(t *testing.T) {
	harness := boundHarness(t)
	harness.invokeDriver = func(_ context.Context, request fixtureproto.Request) ([]byte, error) {
		response := boundResponse(request, harness.config.binding)
		response.Evidence.Facts["snapshot_sha256"] = strings.Repeat("9", 64)
		return json.Marshal(response)
	}
	_, err := harness.callDriver(context.Background(), fixtureproto.Request{Action: "capture", Scenario: "core-exits"})
	if err == nil || !strings.Contains(err.Error(), "snapshot hash") {
		t.Fatalf("callDriver() = %v, want forged constant snapshot refusal", err)
	}
}

func TestCallDriverReverifiesAndLocksDriverBeforeEveryAction(t *testing.T) {
	harness := boundHarness(t)
	verifyCalls := 0
	harness.verifyAndLockDriver = func() (io.Closer, error) {
		verifyCalls++
		if verifyCalls == 2 {
			return nil, errors.New("driver changed")
		}
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	invokeCalls := 0
	harness.invokeDriver = func(_ context.Context, request fixtureproto.Request) ([]byte, error) {
		invokeCalls++
		return json.Marshal(boundResponse(request, harness.config.binding))
	}
	if _, err := harness.callDriver(context.Background(), fixtureproto.Request{Action: "preflight"}); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.callDriver(context.Background(), fixtureproto.Request{Action: "preflight"}); err == nil || !strings.Contains(err.Error(), "driver changed") {
		t.Fatalf("second callDriver() = %v, want stale-driver refusal", err)
	}
	if invokeCalls != 1 {
		t.Fatalf("driver invocations = %d, want 1", invokeCalls)
	}
}

func TestCallDriverRevalidatesRunDirectoryIdentityBeforePrivilegedAction(t *testing.T) {
	harness := boundHarness(t)
	checks := 0
	harness.validateRunDirectory = func() error {
		checks++
		if checks == 2 {
			return errors.New("run directory identity changed")
		}
		return nil
	}
	harness.invokeDriver = func(_ context.Context, request fixtureproto.Request) ([]byte, error) {
		return json.Marshal(boundResponse(request, harness.config.binding))
	}
	if _, err := harness.callDriver(context.Background(), fixtureproto.Request{Action: "preflight"}); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.callDriver(context.Background(), fixtureproto.Request{Action: "case-setup", Scenario: "core-exits"}); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("callDriver() = %v, want run-directory refusal", err)
	}
}

func TestLiveHarnessHoldsRunDirectoryAgainstReplacement(t *testing.T) {
	harness, err := newLiveHarness(liveConfig{preflight: preflightResult{EvidenceDirectory: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	defer harness.closeRunDirectory()
	if err := os.Rename(harness.runDir, harness.runDir+"-replacement"); err == nil {
		t.Fatal("run directory could be renamed while harness custody was active")
	}
}

func TestFixtureConfigIsHashPinnedAndDenyWriteLockedPerAction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture-config.json")
	original := []byte(`{"schema_version":1}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	locked, err := lockPinnedData(path, digest(original))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err == nil {
		locked.Close()
		t.Fatal("fixture config could be changed during a privileged action")
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if handle, err := lockPinnedData(path, digest(original)); err == nil {
		handle.Close()
		t.Fatal("fixture config tamper passed its hash pin")
	}
}

func TestEveryDriverActionReceivesABoundedContext(t *testing.T) {
	harness := boundHarness(t)
	harness.actionTimeout = 30 * time.Millisecond
	harness.invokeDriver = func(ctx context.Context, _ fixtureproto.Request) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	started := time.Now()
	_, err := harness.action("case-setup", "core-exits", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("action() = %v, want deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("hung driver action was not bounded: %v", elapsed)
	}
}

func TestLiveDriverTimeoutJoinsQuiescenceBeforeReturning(t *testing.T) {
	harness := boundHarness(t)
	harness.actionTimeout = 20 * time.Millisecond
	harness.driverJoinTimeout = 200 * time.Millisecond
	quiesced := make(chan struct{})
	harness.invokeDriver = func(ctx context.Context, _ fixtureproto.Request) ([]byte, error) {
		<-ctx.Done()
		time.Sleep(40 * time.Millisecond)
		close(quiesced)
		return nil, ctx.Err()
	}
	_, err := harness.action("case-setup", "core-exits", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("action() = %v, want deadline", err)
	}
	select {
	case <-quiesced:
	default:
		t.Fatal("driver timeout returned before process-tree quiescence")
	}
}

func TestCaptureAddsDeadlineWhenCallerHasNone(t *testing.T) {
	harness := boundHarness(t)
	harness.actionTimeout = 30 * time.Millisecond
	harness.invokeDriver = func(ctx context.Context, _ fixtureproto.Request) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		_, err := harness.capture(context.Background(), "core-exits", harness.runDir)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("capture() = %v, want deadline", err)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("capture without caller deadline left driver action unbounded")
	}
}

func TestLeakProofSpansFullReconciliationWindowWithHealthyOwnedSentinels(t *testing.T) {
	started := time.Now()
	counts := map[string]int{}
	err := proveLeakBlocked(45*time.Millisecond, 10*time.Millisecond, "public-data", "public-health", "corporate", func(endpoint, identity, via string) (bool, error) {
		counts[endpoint]++
		switch endpoint {
		case "public-data":
			return false, errors.New("blocked as required")
		case "public-health":
			if identity != "public/1" || via != "" {
				t.Fatalf("public health binding = %q/%q", identity, via)
			}
		case "corporate":
			if identity != "corporate/1" || via != "" {
				t.Fatalf("corporate binding = %q/%q", identity, via)
			}
		}
		return true, nil
	}, "public/1", "corporate/1")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 40*time.Millisecond {
		t.Fatalf("leak proof stopped before reconciliation window: %v", elapsed)
	}
	if counts["public-data"] < 4 || counts["public-data"] != counts["public-health"] || counts["public-data"] != counts["corporate"] {
		t.Fatalf("probe counts = %v, want spaced data and health checks on every attempt", counts)
	}
}

func TestLeakProofRejectsFalsePassWhenPublicSentinelIsUnhealthy(t *testing.T) {
	err := proveLeakBlocked(time.Millisecond, time.Millisecond, "public-data", "public-health", "corporate", func(endpoint, _, _ string) (bool, error) {
		if endpoint == "public-data" || endpoint == "public-health" {
			return false, errors.New("unreachable")
		}
		return true, nil
	}, "public/1", "corporate/1")
	if err == nil || !strings.Contains(err.Error(), "public sentinel health") {
		t.Fatalf("proveLeakBlocked() = %v, want unhealthy-sentinel refusal", err)
	}
}

func TestLeakProofRejectsAnyReceivedPublicDataEvenWithInvalidReceipt(t *testing.T) {
	err := proveLeakBlocked(time.Millisecond, time.Millisecond, "public-data", "public-health", "corporate", func(endpoint, _, _ string) (bool, error) {
		if endpoint == "public-data" {
			return true, errors.New("wrong identity or traversal")
		}
		return true, nil
	}, "public/1", "corporate/1")
	if err == nil || !strings.Contains(err.Error(), "PUBLIC TCP LEAK") {
		t.Fatalf("proveLeakBlocked() = %v, want any received data to prove a leak", err)
	}
}

func TestTraversalReceiptRequiresFakeUpstreamIdentity(t *testing.T) {
	receipt := sentinelReceipt{Nonce: "nonce-1", Identity: "public/1"}
	if err := validateSentinelReceipt("nonce-1", "public/1", "fake-upstream/1", receipt); err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("validateSentinelReceipt() = %v, want direct-route false-pass refusal", err)
	}
}

func boundHarness(t *testing.T) *liveHarness {
	t.Helper()
	binding := fixtureproto.FixtureBinding{
		PayloadSHA256: strings.Repeat("1", 64), ConfigSHA256: strings.Repeat("2", 64), ServerConfigSHA256: strings.Repeat("3", 64), ActionConfigSHA256: strings.Repeat("4", 64),
		FakeUpstreamIdentity: "fake-upstream/1", PublicSentinelIdentity: "public/1", CorporateSentinelIdentity: "corporate/1",
		PublicSentinelEndpoint: "198.18.0.2:18080", PublicSentinelHealthEndpoint: "172.20.9.251:18080", CorporateSentinelEndpoint: "172.20.9.250:18081", FakeUpstreamControlEndpoint: "172.20.9.15:18082", FakeUpstreamDataEndpoint: "172.20.9.15:18083",
		Artifacts: fixtureproto.ArtifactBinding{ManifestSHA256: strings.Repeat("5", 64), AgentSHA256: strings.Repeat("6", 64), CoreSHA256: strings.Repeat("7", 64), UISHA256: strings.Repeat("8", 64), ServerServiceSHA256: strings.Repeat("9", 64), DriverSHA256: strings.Repeat("a", 64), SentinelSHA256: strings.Repeat("b", 64), ActionHelperSHA256: strings.Repeat("c", 64), PowerShellSHA256: strings.Repeat("d", 64), InstallerSHA256: strings.Repeat("e", 64), CaptureScriptSHA256: strings.Repeat("f", 64)},
	}
	return &liveHarness{
		config: liveConfig{binding: binding, preflight: preflightResult{Hostname: "host-1"}},
		runDir: t.TempDir(), runID: "run-1", runDirectoryIdentity: "volume:1/file:2",
		verifyAndLockDriver:  func() (io.Closer, error) { return io.NopCloser(bytes.NewReader(nil)), nil },
		validateRunDirectory: func() error { return nil },
		actionTimeout:        time.Second,
	}
}

func boundResponse(request fixtureproto.Request, binding fixtureproto.FixtureBinding) fixtureproto.Response {
	facts := map[string]string{"host_identity": "host-1"}
	switch request.Action {
	case "capture":
		facts["snapshot_sha256"] = strings.Repeat("3", 64)
	case "preflight":
		facts["payload_sha256"] = binding.PayloadSHA256
		facts["config_sha256"] = binding.ConfigSHA256
		facts["sentinel_identities_verified"] = "true"
	case "case-setup":
		facts["service_present"] = "true"
		facts["agent_hash_verified"] = "true"
		facts["installed_hashes_verified"] = "true"
	}
	response := fixtureproto.Response{
		ProtocolVersion: fixtureproto.ProtocolVersion, RequestNonce: request.RequestNonce, RunID: request.RunID,
		Scenario: request.Scenario, Action: request.Action, OK: true, Binding: binding,
		Evidence: fixtureproto.ActionEvidence{Kind: request.Action, ObservationNonce: request.RequestNonce, Facts: facts},
		Snapshot: fixtureproto.Snapshot{
			ObservationNonce:     request.RequestNonce,
			Adapters:             []fixtureproto.AdapterRecord{{InterfaceIndex: 7, InterfaceGUID: "{guid}", InterfaceAlias: "Ethernet", Status: "Up"}},
			Routes:               []fixtureproto.RouteRecord{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7, NextHop: "192.0.2.1", RouteMetric: 10}},
			DNS:                  []fixtureproto.DNSRecord{{InterfaceIndex: 7, InterfaceAlias: "Ethernet", ServerAddresses: []string{"192.0.2.53"}}},
			Services:             []fixtureproto.ServiceRecord{{Name: "RegenBioOverseasAccessAgent", Present: false, Status: "Absent", StartMode: "Absent"}},
			Processes:            []fixtureproto.ProcessRecord{{Role: "agent", Present: false}, {Role: "core", Present: false}, {Role: "ui", Present: false}, {Role: "fake-upstream", Present: false}},
			OwnedFirewallRules:   []fixtureproto.FirewallRecord{{Name: "owned", Present: false, DefinitionSHA256: strings.Repeat("0", 64)}},
			MSIRegistrations:     []fixtureproto.MSIRecord{{ProductCode: "{D1234567-89AB-4CDE-8012-3456789ABCDE}", Present: false}},
			InstalledFiles:       []fixtureproto.FileRecord{{Role: "agent", Path: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, Present: false}},
			RuntimeFiles:         []fixtureproto.FileRecord{{Role: "credential", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`, Present: false}},
			RegistryRecords:      []fixtureproto.StateRecord{{Kind: "registry", Name: "product", Present: false}},
			OwnershipArtifacts:   []fixtureproto.StateRecord{{Kind: "ownership", Name: "ledger", Present: false}},
			RecoveryArtifacts:    []fixtureproto.StateRecord{{Kind: "recovery", Name: "machine", Present: false}},
			TransactionArtifacts: []fixtureproto.StateRecord{{Kind: "transaction", Name: "journal", Present: false}},
			FixtureResidues:      []fixtureproto.StateRecord{{Kind: "fixture-residue", Name: "service", Present: false}},
			Listeners:            []fixtureproto.ListenerRecord{{Role: "fake-upstream", Endpoint: "172.20.9.15:18083", Present: false}},
		},
	}
	canonical, _ := response.Snapshot.CanonicalState()
	response.Evidence.Facts["post_state_sha256"] = digest(canonical)
	if request.Action == "capture" {
		response.Evidence.Facts["snapshot_sha256"] = digest(canonical)
	}
	return response
}
