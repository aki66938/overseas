//go:build windows

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/clientapi"
	"golang.org/x/sys/windows"
)

const (
	envIntegration               = "OVERSEAS_ACCESS_INTEGRATION"
	envIntegrationDryRun         = "OVERSEAS_ACCESS_INTEGRATION_DRY_RUN"
	envDisposableAcknowledgement = "OVERSEAS_ACCESS_DISPOSABLE_HOST_ACK"
	envDisposableToken           = "OVERSEAS_ACCESS_DISPOSABLE_HOST_TOKEN"
	envEvidenceDirectory         = "OVERSEAS_ACCESS_BASELINE_DIR"
	envIntegrationDriver         = "OVERSEAS_ACCESS_INTEGRATION_DRIVER"
	envPublicSentinel            = "OVERSEAS_ACCESS_PUBLIC_SENTINEL"
	envCorporateSentinel         = "OVERSEAS_ACCESS_CORPORATE_SENTINEL"
	envCorporateCIDR             = "OVERSEAS_ACCESS_CORPORATE_CIDR"

	disposableAcknowledgement = "I_ACKNOWLEDGE_THIS_WINDOWS_HOST_IS_DISPOSABLE"
	driverProtocolVersion     = 1
	probeTimeout              = 1500 * time.Millisecond
	stateTimeout              = 15 * time.Second
)

type preflightInput struct {
	Environment map[string]string
	Elevated    bool
	Hostname    string
}

type preflightResult struct {
	Enabled           bool
	EvidenceDirectory string
}

type scenario struct {
	Name          string
	ConnectCycles int
}

type liveConfig struct {
	preflight         preflightResult
	dryRun            bool
	driverPath        string
	publicSentinel    string
	corporateSentinel string
	corporateCIDR     netip.Prefix
}

type driverRequest struct {
	ProtocolVersion   int    `json:"protocol_version"`
	Action            string `json:"action"`
	Scenario          string `json:"scenario,omitempty"`
	EvidenceDirectory string `json:"evidence_directory"`
	BaselinePath      string `json:"baseline_path,omitempty"`
}

type driverResponse struct {
	ProtocolVersion int             `json:"protocol_version"`
	OK              bool            `json:"ok"`
	Message         string          `json:"message,omitempty"`
	Snapshot        json.RawMessage `json:"snapshot,omitempty"`
}

type liveHarness struct {
	config      liveConfig
	runDir      string
	client      *clientapi.Client
	actionMu    sync.Mutex
	actionCount int

	mu             sync.Mutex
	activeScenario string
	activeBaseline string
	restorePoison  error
}

var lastChance struct {
	sync.Mutex
	harness *liveHarness
}

func TestPreflightDoesNotOptInImplicitly(t *testing.T) {
	result, err := evaluatePreflight(preflightInput{})
	if err != nil {
		t.Fatalf("evaluatePreflight() error = %v", err)
	}
	if result.Enabled {
		t.Fatal("integration was enabled without the exact opt-in")
	}
}

func TestPreflightRejectsPartialAuthorization(t *testing.T) {
	evidence := t.TempDir()
	host := "DISPOSABLE-01"
	base := preflightInput{
		Environment: map[string]string{
			envIntegration:               "1",
			envDisposableAcknowledgement: disposableAcknowledgement,
			envDisposableToken:           host,
			envEvidenceDirectory:         evidence,
		},
		Elevated: true,
		Hostname: host,
	}

	tests := []struct {
		name string
		edit func(*preflightInput)
		want string
	}{
		{name: "invalid opt-in", edit: func(input *preflightInput) { input.Environment[envIntegration] = "true" }, want: envIntegration},
		{name: "not elevated", edit: func(input *preflightInput) { input.Elevated = false }, want: "elevated"},
		{name: "missing acknowledgement", edit: func(input *preflightInput) { delete(input.Environment, envDisposableAcknowledgement) }, want: envDisposableAcknowledgement},
		{name: "wrong acknowledgement", edit: func(input *preflightInput) { input.Environment[envDisposableAcknowledgement] = "yes" }, want: envDisposableAcknowledgement},
		{name: "missing token", edit: func(input *preflightInput) { delete(input.Environment, envDisposableToken) }, want: envDisposableToken},
		{name: "token for another host", edit: func(input *preflightInput) { input.Environment[envDisposableToken] = "OTHER-HOST" }, want: "current host"},
		{name: "relative evidence path", edit: func(input *preflightInput) { input.Environment[envEvidenceDirectory] = "evidence" }, want: "absolute"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := clonePreflightInput(base)
			test.edit(&input)
			_, err := evaluatePreflight(input)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("evaluatePreflight() error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestPreflightRejectsEvidenceDirectoryWithPriorContents(t *testing.T) {
	evidence := t.TempDir()
	if err := os.WriteFile(filepath.Join(evidence, "old-run.json"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := evaluatePreflight(preflightInput{
		Environment: map[string]string{
			envIntegration:               "1",
			envDisposableAcknowledgement: disposableAcknowledgement,
			envDisposableToken:           "DISPOSABLE-01",
			envEvidenceDirectory:         evidence,
		},
		Elevated: true,
		Hostname: "DISPOSABLE-01",
	})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("evaluatePreflight() error = %v, want empty-directory refusal", err)
	}
}

func TestPreflightAcceptsExplicitDisposableHostAuthorization(t *testing.T) {
	host := "DISPOSABLE-01"
	evidence := t.TempDir()
	result, err := evaluatePreflight(preflightInput{
		Environment: map[string]string{
			envIntegration:               "1",
			envDisposableAcknowledgement: disposableAcknowledgement,
			envDisposableToken:           strings.ToLower(host),
			envEvidenceDirectory:         evidence,
		},
		Elevated: true,
		Hostname: host,
	})
	if err != nil {
		t.Fatalf("evaluatePreflight() error = %v", err)
	}
	if !result.Enabled || result.EvidenceDirectory != evidence {
		t.Fatalf("evaluatePreflight() = %#v", result)
	}
}

func TestScenarioPlanCoversRequiredLifecycleMatrix(t *testing.T) {
	want := []string{
		"connect-success-to-fake-upstream",
		"upstream-absent",
		"upstream-dies-while-connected",
		"core-exits",
		"ui-exits",
		"service-restarts",
		"machine-style-recovery",
		"twenty-connect-disconnect-cycles",
		"uninstall-cleanup",
	}
	got := scenarioPlan()
	if len(got) != len(want) {
		t.Fatalf("scenarioPlan() length = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index].Name != want[index] {
			t.Fatalf("scenarioPlan()[%d].Name = %q, want %q", index, got[index].Name, want[index])
		}
		if got[index].ConnectCycles < 1 {
			t.Fatalf("scenarioPlan()[%d].ConnectCycles = %d", index, got[index].ConnectCycles)
		}
	}
	if got[7].ConnectCycles != 20 {
		t.Fatalf("stress scenario cycles = %d, want 20", got[7].ConnectCycles)
	}
}

func TestUnavailableUpstreamAcceptsLocallyReadyOrFailedCore(t *testing.T) {
	for _, state := range []accessmodel.ConnectionState{accessmodel.StateConnected, accessmodel.StateFailed} {
		if !isUnavailableTunnelState(state) {
			t.Errorf("isUnavailableTunnelState(%q) = false, want true", state)
		}
	}
	for _, state := range []accessmodel.ConnectionState{accessmodel.StateConnecting, accessmodel.StateDisconnected} {
		if isUnavailableTunnelState(state) {
			t.Errorf("isUnavailableTunnelState(%q) = true, want false", state)
		}
	}
}

func TestLastChanceReleaseRequiresProvenRestoration(t *testing.T) {
	harness := &liveHarness{}
	if !harness.mayReleaseLastChance() {
		t.Fatal("clean inactive harness retained the last-chance hook")
	}
	harness.activeScenario = "core-exits"
	if harness.mayReleaseLastChance() {
		t.Fatal("active case released the last-chance hook")
	}
	harness.activeScenario = ""
	harness.restorePoison = errors.New("state drift")
	if harness.mayReleaseLastChance() {
		t.Fatal("poisoned restoration released the last-chance hook")
	}
}

func TestCanonicalSnapshotRequiresEveryBaselineSurface(t *testing.T) {
	complete := []byte(`{"routes":[],"dns":[],"adapters":[],"services":[],"processes":[],"owned_firewall_rules":[]}`)
	first, err := canonicalSnapshot(complete)
	if err != nil {
		t.Fatalf("canonicalSnapshot() error = %v", err)
	}
	second, err := canonicalSnapshot([]byte(`{"services":[],"routes":[],"owned_firewall_rules":[],"processes":[],"adapters":[],"dns":[]}`))
	if err != nil {
		t.Fatalf("canonicalSnapshot() reordered error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical snapshots differ:\n%s\n%s", first, second)
	}
	_, err = canonicalSnapshot([]byte(`{"routes":[],"dns":[],"adapters":[],"services":[],"processes":[]}`))
	if err == nil || !strings.Contains(err.Error(), "owned_firewall_rules") {
		t.Fatalf("canonicalSnapshot() missing-surface error = %v", err)
	}
	_, err = canonicalSnapshot([]byte(`{"routes":null,"dns":[],"adapters":[],"services":[],"processes":[],"owned_firewall_rules":[]}`))
	if err == nil || !strings.Contains(err.Error(), "routes") {
		t.Fatalf("canonicalSnapshot() null-surface error = %v", err)
	}
}

func TestPreservedBaselineRejectsDriverModification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	want := []byte(`{"routes":[]}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provePreservedBaseline(path, want); err != nil {
		t.Fatalf("provePreservedBaseline() unchanged error = %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"routes":["changed"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provePreservedBaseline(path, want); err == nil {
		t.Fatal("provePreservedBaseline() accepted modified evidence")
	}
}

func TestDriverFailureDoesNotEchoDriverOutput(t *testing.T) {
	const secret = "INTEGRATION-DRIVER-SECRET"
	driver := filepath.Join(t.TempDir(), "failure.ps1")
	script := "$null = [Console]::In.ReadToEnd(); [Console]::Error.Write('" + secret + "'); exit 9"
	if err := os.WriteFile(driver, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := &liveHarness{config: liveConfig{driverPath: driver}, runDir: t.TempDir()}
	_, err := harness.callDriver(context.Background(), driverRequest{ProtocolVersion: driverProtocolVersion, Action: "preflight"})
	if err == nil {
		t.Fatal("callDriver() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("callDriver() disclosed driver output: %v", err)
	}
}

func TestRepositoryIntegrationContractDocumentsExternalLiveGate(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read integration README: %v", err)
	}
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	for _, required := range []string{
		disposableAcknowledgement,
		envDisposableToken,
		envEvidenceDirectory,
		envIntegrationDryRun,
		"Task 10",
		"must not be run on a developer workstation",
		"routes, DNS, adapters, services, processes, and owned firewall rules",
	} {
		if !bytes.Contains(readme, []byte(required)) {
			t.Errorf("README is missing %q", required)
		}
	}
	for _, required := range []string{"test-integration-preflight:", "test-integration-live:", "$$env:" + envIntegration + " -ne '1'"} {
		if !bytes.Contains(makefile, []byte(required)) {
			t.Errorf("Makefile is missing %q", required)
		}
	}
}

func TestWindowsFailClosedLifecycle(t *testing.T) {
	input, err := currentPreflightInput()
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := evaluatePreflight(input)
	if err != nil {
		t.Fatalf("integration authorization refused: %v", err)
	}
	if !preflight.Enabled {
		t.Skip("privileged integration disabled; run the preflight target or follow tests/integration/README.md on a disposable host")
	}

	config, err := loadLiveConfig(preflight)
	if err != nil {
		t.Fatalf("integration fixture refused: %v", err)
	}
	harness, err := newLiveHarness(config)
	if err != nil {
		t.Fatal(err)
	}
	registerLastChance(harness)
	defer func() {
		if harness.mayReleaseLastChance() {
			registerLastChance(nil)
		}
	}()

	if err := harness.action(context.Background(), "preflight", "", ""); err != nil {
		t.Fatalf("fixture preflight failed: %v", err)
	}
	if config.dryRun {
		t.Logf("preflight-only PASS; evidence: %s", harness.runDir)
		return
	}

	for _, testCase := range scenarioPlan() {
		if harness.poisoned() != nil {
			t.Fatalf("refusing further cases after restoration failure: %v", harness.poisoned())
		}
		if ok := t.Run(testCase.Name, func(t *testing.T) { harness.runScenario(t, testCase) }); !ok && harness.poisoned() != nil {
			break
		}
	}
}

func evaluatePreflight(input preflightInput) (preflightResult, error) {
	optIn := input.Environment[envIntegration]
	if optIn == "" {
		return preflightResult{}, nil
	}
	if optIn != "1" {
		return preflightResult{}, fmt.Errorf("%s must be exactly 1", envIntegration)
	}
	if !input.Elevated {
		return preflightResult{}, errors.New("integration requires an elevated Administrator token")
	}
	if input.Environment[envDisposableAcknowledgement] != disposableAcknowledgement {
		return preflightResult{}, fmt.Errorf("%s must be exactly %q", envDisposableAcknowledgement, disposableAcknowledgement)
	}
	token := strings.TrimSpace(input.Environment[envDisposableToken])
	if token == "" {
		return preflightResult{}, fmt.Errorf("%s is required", envDisposableToken)
	}
	if !strings.EqualFold(token, strings.TrimSpace(input.Hostname)) {
		return preflightResult{}, fmt.Errorf("%s must name the current host %q", envDisposableToken, input.Hostname)
	}
	evidence := input.Environment[envEvidenceDirectory]
	if evidence == "" || !filepath.IsAbs(evidence) || filepath.Clean(evidence) != evidence {
		return preflightResult{}, fmt.Errorf("%s must be an absolute clean path", envEvidenceDirectory)
	}
	info, err := os.Lstat(evidence)
	if err != nil {
		return preflightResult{}, fmt.Errorf("inspect %s: %w", envEvidenceDirectory, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return preflightResult{}, fmt.Errorf("%s must be an existing ordinary directory", envEvidenceDirectory)
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(evidence))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return preflightResult{}, fmt.Errorf("%s must not be a reparse point", envEvidenceDirectory)
	}
	entries, err := os.ReadDir(evidence)
	if err != nil {
		return preflightResult{}, fmt.Errorf("read %s: %w", envEvidenceDirectory, err)
	}
	if len(entries) != 0 {
		return preflightResult{}, fmt.Errorf("%s must be empty for a new evidence run", envEvidenceDirectory)
	}
	return preflightResult{Enabled: true, EvidenceDirectory: evidence}, nil
}

func currentPreflightInput() (preflightInput, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return preflightInput{}, fmt.Errorf("read hostname: %w", err)
	}
	environment := make(map[string]string)
	for _, name := range []string{envIntegration, envDisposableAcknowledgement, envDisposableToken, envEvidenceDirectory} {
		environment[name] = os.Getenv(name)
	}
	return preflightInput{Environment: environment, Elevated: windows.GetCurrentProcessToken().IsElevated(), Hostname: hostname}, nil
}

func loadLiveConfig(preflight preflightResult) (liveConfig, error) {
	driver, err := validateOrdinaryFile(os.Getenv(envIntegrationDriver))
	if err != nil {
		return liveConfig{}, fmt.Errorf("%s: %w", envIntegrationDriver, err)
	}
	publicEndpoint, publicAddress, err := parseSentinel(envPublicSentinel, os.Getenv(envPublicSentinel))
	if err != nil {
		return liveConfig{}, err
	}
	corporateEndpoint, corporateAddress, err := parseSentinel(envCorporateSentinel, os.Getenv(envCorporateSentinel))
	if err != nil {
		return liveConfig{}, err
	}
	corporateCIDR, err := netip.ParsePrefix(strings.TrimSpace(os.Getenv(envCorporateCIDR)))
	if err != nil || corporateCIDR.String() != strings.TrimSpace(os.Getenv(envCorporateCIDR)) {
		return liveConfig{}, fmt.Errorf("%s must be a canonical CIDR", envCorporateCIDR)
	}
	if !corporateCIDR.Contains(corporateAddress) {
		return liveConfig{}, fmt.Errorf("%s must be inside %s", envCorporateSentinel, envCorporateCIDR)
	}
	if corporateCIDR.Contains(publicAddress) {
		return liveConfig{}, fmt.Errorf("%s must be outside %s", envPublicSentinel, envCorporateCIDR)
	}
	if publicAddress.IsLoopback() || corporateAddress.IsLoopback() || publicAddress == corporateAddress {
		return liveConfig{}, errors.New("sentinels must be distinct non-loopback addresses")
	}
	dryRunText := os.Getenv(envIntegrationDryRun)
	if dryRunText != "" && dryRunText != "1" {
		return liveConfig{}, fmt.Errorf("%s must be empty or exactly 1", envIntegrationDryRun)
	}
	return liveConfig{preflight: preflight, dryRun: dryRunText == "1", driverPath: driver, publicSentinel: publicEndpoint, corporateSentinel: corporateEndpoint, corporateCIDR: corporateCIDR}, nil
}

func validateOrdinaryFile(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("must be an absolute clean path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("must be an ordinary file")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.New("must not be a reparse point")
	}
	return path, nil
}

func parseSentinel(name, value string) (string, netip.Addr, error) {
	endpoint, err := netip.ParseAddrPort(strings.TrimSpace(value))
	if err != nil || endpoint.Port() == 0 || !endpoint.Addr().Is4() || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return "", netip.Addr{}, fmt.Errorf("%s must be a nonzero IPv4 address:port", name)
	}
	return endpoint.String(), endpoint.Addr(), nil
}

func scenarioPlan() []scenario {
	return []scenario{
		{Name: "connect-success-to-fake-upstream", ConnectCycles: 1},
		{Name: "upstream-absent", ConnectCycles: 1},
		{Name: "upstream-dies-while-connected", ConnectCycles: 1},
		{Name: "core-exits", ConnectCycles: 1},
		{Name: "ui-exits", ConnectCycles: 1},
		{Name: "service-restarts", ConnectCycles: 1},
		{Name: "machine-style-recovery", ConnectCycles: 1},
		{Name: "twenty-connect-disconnect-cycles", ConnectCycles: 20},
		{Name: "uninstall-cleanup", ConnectCycles: 1},
	}
}

func newLiveHarness(config liveConfig) (*liveHarness, error) {
	runDir := filepath.Join(config.preflight.EvidenceDirectory, "run-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence run: %w", err)
	}
	return &liveHarness{config: config, runDir: runDir, client: clientapi.New()}, nil
}

func (h *liveHarness) runScenario(t *testing.T, testCase scenario) {
	t.Helper()
	caseDir := filepath.Join(h.runDir, testCase.Name)
	if err := os.Mkdir(caseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(caseDir, "baseline.json")
	baseline, err := h.capture(context.Background(), testCase.Name, caseDir)
	if err != nil {
		t.Fatalf("capture baseline: %v", err)
	}
	if err := writeNewFile(baselinePath, baseline); err != nil {
		t.Fatalf("preserve baseline: %v", err)
	}
	h.setActive(testCase.Name, baselinePath)
	defer func() {
		if err := h.restoreAndProve(testCase.Name, caseDir, baselinePath, baseline); err != nil {
			h.markPoisoned(err)
			t.Errorf("FINAL RESTORATION COULD NOT BE PROVEN: %v", err)
			return
		}
		h.clearActive()
	}()

	assertReachable(t, "baseline public sentinel", h.config.publicSentinel)
	assertReachable(t, "baseline corporate sentinel", h.config.corporateSentinel)
	if err := h.action(context.Background(), "case-setup", testCase.Name, baselinePath); err != nil {
		t.Fatalf("case setup: %v", err)
	}
	if err := h.action(context.Background(), "fake-upstream-stop", testCase.Name, baselinePath); err != nil {
		t.Fatalf("force fake upstream absent: %v", err)
	}

	switch testCase.Name {
	case "connect-success-to-fake-upstream":
		h.startUpstreamAndConnect(t, testCase.Name, baselinePath)
		assertReachable(t, "public sentinel through fake upstream", h.config.publicSentinel)
		assertReachable(t, "corporate sentinel while connected", h.config.corporateSentinel)
		h.disconnect(t)
	case "upstream-absent":
		h.connectWithUnavailableUpstream(t)
		h.assertLeakBlocked(t)
		h.disconnect(t)
	case "upstream-dies-while-connected":
		h.startUpstreamAndConnect(t, testCase.Name, baselinePath)
		h.mustAction(t, "fake-upstream-stop", testCase.Name, baselinePath)
		h.assertLeakBlocked(t)
		h.disconnect(t)
	case "core-exits":
		h.startUpstreamAndConnect(t, testCase.Name, baselinePath)
		h.mustAction(t, "core-crash", testCase.Name, baselinePath)
		h.waitForState(t, accessmodel.StateFailed)
		h.assertLeakBlocked(t)
		h.disconnect(t)
	case "ui-exits":
		h.mustAction(t, "ui-start", testCase.Name, baselinePath)
		h.startUpstreamAndConnect(t, testCase.Name, baselinePath)
		h.mustAction(t, "ui-exit", testCase.Name, baselinePath)
		h.waitForState(t, accessmodel.StateConnected)
		assertReachable(t, "public sentinel after UI exit", h.config.publicSentinel)
		assertReachable(t, "corporate sentinel after UI exit", h.config.corporateSentinel)
		h.disconnect(t)
	case "service-restarts":
		h.startUpstreamAndConnect(t, testCase.Name, baselinePath)
		h.mustAction(t, "agent-crash", testCase.Name, baselinePath)
		h.assertLeakBlocked(t)
		h.mustAction(t, "agent-start", testCase.Name, baselinePath)
		h.waitForState(t, accessmodel.StateDisconnected)
	case "machine-style-recovery":
		h.mustAction(t, "stage-machine-recovery", testCase.Name, baselinePath)
		h.assertLeakBlocked(t)
		h.mustAction(t, "machine-recover", testCase.Name, baselinePath)
		h.waitForState(t, accessmodel.StateDisconnected)
	case "twenty-connect-disconnect-cycles":
		h.mustAction(t, "fake-upstream-start", testCase.Name, baselinePath)
		for cycle := 1; cycle <= testCase.ConnectCycles; cycle++ {
			h.connectMustSucceed(t)
			assertReachable(t, fmt.Sprintf("public sentinel cycle %d", cycle), h.config.publicSentinel)
			assertReachable(t, fmt.Sprintf("corporate sentinel cycle %d", cycle), h.config.corporateSentinel)
			h.disconnect(t)
			assertReachable(t, fmt.Sprintf("restored public sentinel cycle %d", cycle), h.config.publicSentinel)
			assertReachable(t, fmt.Sprintf("restored corporate sentinel cycle %d", cycle), h.config.corporateSentinel)
		}
	case "uninstall-cleanup":
		h.startUpstreamAndConnect(t, testCase.Name, baselinePath)
		h.disconnect(t)
		h.mustAction(t, "uninstall", testCase.Name, baselinePath)
	default:
		t.Fatalf("unimplemented scenario %q", testCase.Name)
	}
}

func (h *liveHarness) mustAction(t *testing.T, action, scenarioName, baselinePath string) {
	t.Helper()
	if err := h.action(context.Background(), action, scenarioName, baselinePath); err != nil {
		t.Fatal(err)
	}
}

func (h *liveHarness) startUpstreamAndConnect(t *testing.T, scenarioName, baselinePath string) {
	t.Helper()
	h.mustAction(t, "fake-upstream-start", scenarioName, baselinePath)
	h.connectMustSucceed(t)
}

func (h *liveHarness) connectMustSucceed(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), stateTimeout)
	defer cancel()
	status, err := h.client.Connect(ctx)
	if err != nil || status.State != accessmodel.StateConnected {
		t.Fatalf("Connect() = %#v, %v; want connected", status, err)
	}
}

func (h *liveHarness) connectWithUnavailableUpstream(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), stateTimeout)
	defer cancel()
	status, err := h.client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect() transport error = %v; service must remain observable", err)
	}
	if !isUnavailableTunnelState(status.State) {
		t.Fatalf("Connect() = %#v, want connected or failed before leak assertion", status)
	}
}

func isUnavailableTunnelState(state accessmodel.ConnectionState) bool {
	return state == accessmodel.StateConnected || state == accessmodel.StateFailed
}

func (h *liveHarness) disconnect(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), stateTimeout)
	defer cancel()
	status, err := h.client.Disconnect(ctx)
	if err != nil || status.State != accessmodel.StateDisconnected {
		t.Fatalf("Disconnect() = %#v, %v; restoration was not proven", status, err)
	}
}

func (h *liveHarness) waitForState(t *testing.T, want accessmodel.ConnectionState) {
	t.Helper()
	deadline := time.Now().Add(stateTimeout)
	var last clientapi.Status
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		last, lastErr = h.client.Status(ctx)
		cancel()
		if lastErr == nil && last.State == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("wait for state %s: %v", want, lastErr)
	}
	if last.State != want {
		t.Fatalf("state = %#v, want %s", last, want)
	}
}

func (h *liveHarness) assertLeakBlocked(t *testing.T) {
	t.Helper()
	for attempt := 1; attempt <= 3; attempt++ {
		if err := dialSentinel(h.config.publicSentinel); err == nil {
			t.Fatalf("PUBLIC TCP LEAK: ordinary-gateway sentinel %s was reachable on attempt %d while tunnel was unavailable", h.config.publicSentinel, attempt)
		}
	}
	assertReachable(t, "corporate sentinel during fail-closed state", h.config.corporateSentinel)
}

func assertReachable(t *testing.T, description, endpoint string) {
	t.Helper()
	if err := dialSentinel(endpoint); err != nil {
		t.Fatalf("%s %s is unreachable: %v", description, endpoint, err)
	}
}

func dialSentinel(endpoint string) error {
	connection, err := net.DialTimeout("tcp4", endpoint, probeTimeout)
	if err != nil {
		return err
	}
	return connection.Close()
}

func (h *liveHarness) capture(ctx context.Context, scenarioName, evidenceDirectory string) ([]byte, error) {
	response, err := h.callDriver(ctx, driverRequest{ProtocolVersion: driverProtocolVersion, Action: "capture", Scenario: scenarioName, EvidenceDirectory: evidenceDirectory})
	if err != nil {
		return nil, err
	}
	return canonicalSnapshot(response.Snapshot)
}

func canonicalSnapshot(data []byte) ([]byte, error) {
	var snapshot map[string]json.RawMessage
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	required := []string{"adapters", "dns", "owned_firewall_rules", "processes", "routes", "services"}
	for _, name := range required {
		value, exists := snapshot[name]
		if !exists {
			return nil, fmt.Errorf("snapshot is missing %s", name)
		}
		trimmed := bytes.TrimSpace(value)
		if len(trimmed) == 0 || trimmed[0] != '[' {
			return nil, fmt.Errorf("snapshot %s must be an array", name)
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(value, &entries); err != nil {
			return nil, fmt.Errorf("snapshot %s must be an array: %w", name, err)
		}
	}
	if len(snapshot) != len(required) {
		return nil, errors.New("snapshot contains an unapproved surface")
	}
	return json.Marshal(snapshot)
}

func (h *liveHarness) restoreAndProve(scenarioName, caseDir, baselinePath string, baseline []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	beforeErr := provePreservedBaseline(baselinePath, baseline)
	cleanupErr := h.action(ctx, "case-cleanup", scenarioName, baselinePath)
	restoreErr := h.action(ctx, "restore", scenarioName, baselinePath)
	afterErr := provePreservedBaseline(baselinePath, baseline)
	final, captureErr := h.capture(ctx, scenarioName, caseDir)
	if captureErr == nil {
		captureErr = writeNewFile(filepath.Join(caseDir, "final.json"), final)
	}
	if beforeErr != nil || cleanupErr != nil || restoreErr != nil || afterErr != nil || captureErr != nil {
		return errors.Join(beforeErr, cleanupErr, restoreErr, afterErr, captureErr)
	}
	if !bytes.Equal(baseline, final) {
		drift := map[string]string{"baseline_sha256": digest(baseline), "final_sha256": digest(final)}
		encoded, _ := json.MarshalIndent(drift, "", "  ")
		_ = writeNewFile(filepath.Join(caseDir, "STATE-DRIFT.json"), encoded)
		return fmt.Errorf("exact baseline mismatch: before %s, after %s", drift["baseline_sha256"], drift["final_sha256"])
	}
	return nil
}

func provePreservedBaseline(path string, want []byte) error {
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read preserved baseline: %w", err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("preserved baseline evidence was modified")
	}
	return nil
}

func (h *liveHarness) action(ctx context.Context, action, scenarioName, baselinePath string) error {
	_, err := h.callDriver(ctx, driverRequest{ProtocolVersion: driverProtocolVersion, Action: action, Scenario: scenarioName, EvidenceDirectory: h.runDir, BaselinePath: baselinePath})
	return err
}

func (h *liveHarness) callDriver(ctx context.Context, request driverRequest) (driverResponse, error) {
	h.actionMu.Lock()
	defer h.actionMu.Unlock()
	requestData, err := json.Marshal(request)
	if err != nil {
		return driverResponse{}, err
	}
	var command *exec.Cmd
	if strings.EqualFold(filepath.Ext(h.config.driverPath), ".ps1") {
		command = exec.CommandContext(ctx, "pwsh.exe", "-NoProfile", "-NonInteractive", "-File", h.config.driverPath)
	} else {
		command = exec.CommandContext(ctx, h.config.driverPath)
	}
	command.Stdin = bytes.NewReader(append(requestData, '\n'))
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return driverResponse{}, fmt.Errorf("driver action %s failed: %w", request.Action, err)
	}
	var response driverResponse
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return driverResponse{}, fmt.Errorf("driver action %s returned invalid JSON: %w", request.Action, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return driverResponse{}, fmt.Errorf("driver action %s returned trailing data", request.Action)
	}
	if response.ProtocolVersion != driverProtocolVersion || !response.OK {
		return driverResponse{}, fmt.Errorf("driver action %s refused with protocol %d", request.Action, response.ProtocolVersion)
	}
	h.actionCount++
	record := map[string]any{"sequence": h.actionCount, "action": request.Action, "scenario": request.Scenario, "ok": response.OK, "timestamp_utc": time.Now().UTC().Format(time.RFC3339Nano)}
	recordData, _ := json.Marshal(record)
	if err := writeNewFile(filepath.Join(h.runDir, fmt.Sprintf("action-%04d.json", h.actionCount)), recordData); err != nil {
		return driverResponse{}, fmt.Errorf("write action evidence: %w", err)
	}
	return response, nil
}

func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func clonePreflightInput(input preflightInput) preflightInput {
	result := input
	result.Environment = make(map[string]string, len(input.Environment))
	for key, value := range input.Environment {
		result.Environment[key] = value
	}
	return result
}

func (h *liveHarness) setActive(scenarioName, baselinePath string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeScenario, h.activeBaseline = scenarioName, baselinePath
}

func (h *liveHarness) clearActive() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeScenario, h.activeBaseline = "", ""
}

func (h *liveHarness) markPoisoned(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.restorePoison = err
}

func (h *liveHarness) poisoned() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.restorePoison
}

func (h *liveHarness) mayReleaseLastChance() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.activeScenario == "" && h.activeBaseline == "" && h.restorePoison == nil
}

func (h *liveHarness) lastChanceRestore() error {
	h.mu.Lock()
	scenarioName, baselinePath := h.activeScenario, h.activeBaseline
	h.mu.Unlock()
	if scenarioName == "" || baselinePath == "" {
		return h.poisoned()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	baseline, baselineErr := os.ReadFile(baselinePath)
	cleanupErr := h.action(ctx, "case-cleanup", scenarioName, baselinePath)
	restoreErr := h.action(ctx, "restore", scenarioName, baselinePath)
	final, captureErr := h.capture(ctx, scenarioName, filepath.Dir(baselinePath))
	var writeErr, driftErr error
	if captureErr == nil {
		writeErr = writeNewFile(filepath.Join(filepath.Dir(baselinePath), "last-chance-final.json"), final)
		if baselineErr == nil && !bytes.Equal(baseline, final) {
			driftErr = fmt.Errorf("last-chance state differs: before %s, after %s", digest(baseline), digest(final))
		}
	}
	return errors.Join(baselineErr, cleanupErr, restoreErr, captureErr, writeErr, driftErr)
}

func registerLastChance(harness *liveHarness) {
	lastChance.Lock()
	defer lastChance.Unlock()
	lastChance.harness = harness
}

func TestMain(m *testing.M) {
	code := m.Run()
	lastChance.Lock()
	harness := lastChance.harness
	lastChance.Unlock()
	if harness != nil {
		if err := harness.lastChanceRestore(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "integration last-chance restoration failed: %v\n", err)
			code = 1
		}
	}
	os.Exit(code)
}
