//go:build windows

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"unsafe"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/clientapi"
	"corp.example/overseas-access-gateway/internal/coreverify"
	"corp.example/overseas-access-gateway/tests/integration/fixtureproto"
	"golang.org/x/sys/windows"
)

const (
	envIntegration               = "OVERSEAS_ACCESS_INTEGRATION"
	envIntegrationDryRun         = "OVERSEAS_ACCESS_INTEGRATION_DRY_RUN"
	envDisposableAcknowledgement = "OVERSEAS_ACCESS_DISPOSABLE_HOST_ACK"
	envDisposableToken           = "OVERSEAS_ACCESS_DISPOSABLE_HOST_TOKEN"
	envEvidenceDirectory         = "OVERSEAS_ACCESS_BASELINE_DIR"
	envIntegrationDriver         = "OVERSEAS_ACCESS_INTEGRATION_DRIVER"
	envIntegrationDriverSHA256   = "OVERSEAS_ACCESS_INTEGRATION_DRIVER_SHA256"
	envIntegrationDriverSigner   = "OVERSEAS_ACCESS_INTEGRATION_DRIVER_SIGNER"
	envPayloadSHA256             = "OVERSEAS_ACCESS_PAYLOAD_SHA256"
	envGeneratedConfigSHA256     = "OVERSEAS_ACCESS_GENERATED_CONFIG_SHA256"
	envFakeUpstreamIdentity      = "OVERSEAS_ACCESS_FAKE_UPSTREAM_IDENTITY"
	envPublicSentinelIdentity    = "OVERSEAS_ACCESS_PUBLIC_SENTINEL_IDENTITY"
	envCorporateSentinelIdentity = "OVERSEAS_ACCESS_CORPORATE_SENTINEL_IDENTITY"
	envFixtureConfig             = "OVERSEAS_ACCESS_FIXTURE_CONFIG"
	envFixtureConfigSHA256       = "OVERSEAS_ACCESS_FIXTURE_CONFIG_SHA256"
	envPublicSentinel            = "OVERSEAS_ACCESS_PUBLIC_SENTINEL"
	envCorporateSentinel         = "OVERSEAS_ACCESS_CORPORATE_SENTINEL"
	envPublicSentinelHealth      = "OVERSEAS_ACCESS_PUBLIC_SENTINEL_HEALTH"
	envFakeUpstreamControl       = "OVERSEAS_ACCESS_FAKE_UPSTREAM_CONTROL"
	envCorporateCIDR             = "OVERSEAS_ACCESS_CORPORATE_CIDR"

	disposableAcknowledgement = "I_ACKNOWLEDGE_THIS_WINDOWS_HOST_IS_DISPOSABLE"
	probeTimeout              = 1500 * time.Millisecond
	stateTimeout              = 15 * time.Second
	trustedBaselineSDDL       = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

type trustedBaseline struct {
	data                  []byte
	hash                  string
	evidencePath          string
	trustedPath           string
	trustedHandle         *os.File
	restoreInputs         []*os.File
	caseDirectoryHandle   *os.File
	caseDirectoryIdentity string
}

type preflightInput struct {
	Environment map[string]string
	Elevated    bool
	Hostname    string
}

type preflightResult struct {
	Enabled           bool
	EvidenceDirectory string
	Hostname          string
}

type scenario struct {
	Name          string
	ConnectCycles int
}

type liveConfig struct {
	preflight            preflightResult
	dryRun               bool
	driverPath           string
	driverSHA256         string
	driverSigners        []string
	fixtureConfigPath    string
	fixtureConfigSHA256  string
	binding              fixtureproto.FixtureBinding
	publicSentinel       string
	publicSentinelHealth string
	corporateSentinel    string
	corporateCIDR        netip.Prefix
}

type liveHarness struct {
	config               liveConfig
	runDir               string
	client               *clientapi.Client
	recordMu             sync.Mutex
	actionCount          int
	runID                string
	runDirectoryIdentity string
	runDirectoryHandle   *os.File
	invokeDriver         func(context.Context, fixtureproto.Request) ([]byte, error)
	verifyAndLockDriver  func() (io.Closer, error)
	validateRunDirectory func() error
	actionTimeout        time.Duration
	cleanupTimeout       time.Duration
	restoreTimeout       time.Duration
	reconciliationWindow time.Duration
	probeInterval        time.Duration
	probeReceipt         func(string, string, string) (bool, error)

	mu             sync.Mutex
	activeScenario string
	activeBaseline *trustedBaseline
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

func TestDriverFailureDoesNotEchoDriverOutput(t *testing.T) {
	const secret = "INTEGRATION-DRIVER-SECRET"
	harness := boundHarness(t)
	harness.invokeDriver = func(context.Context, fixtureproto.Request) ([]byte, error) {
		return nil, errors.New(secret)
	}
	_, err := harness.callDriver(context.Background(), fixtureproto.Request{Action: "preflight"})
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
		envIntegrationDriverSHA256,
		envIntegrationDriverSigner,
		envFixtureConfigSHA256,
		envPublicSentinelHealth,
		"Task 10",
		"must not be run on a developer workstation",
		"routes, DNS, adapters, services, processes, and owned firewall rules",
	} {
		if !bytes.Contains(readme, []byte(required)) {
			t.Errorf("README is missing %q", required)
		}
	}
	for _, required := range []string{"test-integration-preflight:", "test-integration-live:", "build-integration-fixtures:", "$$env:" + envIntegration + " -ne '1'"} {
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
			_ = harness.closeRunDirectory()
		}
	}()

	if _, err := harness.action("preflight", "", nil); err != nil {
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
	return preflightResult{Enabled: true, EvidenceDirectory: evidence, Hostname: strings.TrimSpace(input.Hostname)}, nil
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
	fakeControlEndpoint, fakeControlAddress, err := parseSentinel(envFakeUpstreamControl, os.Getenv(envFakeUpstreamControl))
	if err != nil {
		return liveConfig{}, err
	}
	corporateCIDR, err := netip.ParsePrefix(strings.TrimSpace(os.Getenv(envCorporateCIDR)))
	if err != nil || corporateCIDR.String() != strings.TrimSpace(os.Getenv(envCorporateCIDR)) {
		return liveConfig{}, fmt.Errorf("%s must be a canonical CIDR", envCorporateCIDR)
	}
	publicHealthEndpoint, publicHealthAddress, err := parseSentinel(envPublicSentinelHealth, os.Getenv(envPublicSentinelHealth))
	if err != nil {
		return liveConfig{}, err
	}
	if !corporateCIDR.Contains(publicHealthAddress) {
		return liveConfig{}, fmt.Errorf("%s must use the independently permitted health path inside %s", envPublicSentinelHealth, envCorporateCIDR)
	}
	if !corporateCIDR.Contains(fakeControlAddress) {
		return liveConfig{}, fmt.Errorf("%s must use the permitted fixture path inside %s", envFakeUpstreamControl, envCorporateCIDR)
	}
	if !corporateCIDR.Contains(corporateAddress) {
		return liveConfig{}, fmt.Errorf("%s must be inside %s", envCorporateSentinel, envCorporateCIDR)
	}
	if corporateCIDR.Contains(publicAddress) {
		return liveConfig{}, fmt.Errorf("%s must be outside %s", envPublicSentinel, envCorporateCIDR)
	}
	if publicAddress.IsLoopback() || corporateAddress.IsLoopback() || publicAddress == corporateAddress || publicHealthEndpoint == corporateEndpoint {
		return liveConfig{}, errors.New("sentinels must be distinct non-loopback addresses")
	}
	dryRunText := os.Getenv(envIntegrationDryRun)
	if dryRunText != "" && dryRunText != "1" {
		return liveConfig{}, fmt.Errorf("%s must be empty or exactly 1", envIntegrationDryRun)
	}
	driverHash, err := requiredSHA256(envIntegrationDriverSHA256)
	if err != nil {
		return liveConfig{}, err
	}
	signer := strings.TrimSpace(os.Getenv(envIntegrationDriverSigner))
	if signer == "" {
		return liveConfig{}, fmt.Errorf("%s is required", envIntegrationDriverSigner)
	}
	fixtureConfigPath, err := validateOrdinaryFile(os.Getenv(envFixtureConfig))
	if err != nil {
		return liveConfig{}, fmt.Errorf("%s: %w", envFixtureConfig, err)
	}
	fixtureConfigHash, err := requiredSHA256(envFixtureConfigSHA256)
	if err != nil {
		return liveConfig{}, err
	}
	binding := fixtureproto.FixtureBinding{
		PayloadSHA256:             strings.TrimSpace(os.Getenv(envPayloadSHA256)),
		ConfigSHA256:              strings.TrimSpace(os.Getenv(envGeneratedConfigSHA256)),
		FakeUpstreamIdentity:      strings.TrimSpace(os.Getenv(envFakeUpstreamIdentity)),
		PublicSentinelIdentity:    strings.TrimSpace(os.Getenv(envPublicSentinelIdentity)),
		CorporateSentinelIdentity: strings.TrimSpace(os.Getenv(envCorporateSentinelIdentity)),
		PublicSentinelEndpoint:    publicEndpoint, PublicSentinelHealthEndpoint: publicHealthEndpoint,
		CorporateSentinelEndpoint: corporateEndpoint, FakeUpstreamControlEndpoint: fakeControlEndpoint,
	}
	if !isSHA256(binding.PayloadSHA256) {
		return liveConfig{}, fmt.Errorf("%s must be a lowercase SHA-256", envPayloadSHA256)
	}
	if !isSHA256(binding.ConfigSHA256) {
		return liveConfig{}, fmt.Errorf("%s must be a lowercase SHA-256", envGeneratedConfigSHA256)
	}
	if binding.FakeUpstreamIdentity == "" || binding.PublicSentinelIdentity == "" || binding.CorporateSentinelIdentity == "" {
		return liveConfig{}, errors.New("all fixture and sentinel identities are required")
	}
	if binding.FakeUpstreamIdentity == binding.PublicSentinelIdentity || binding.FakeUpstreamIdentity == binding.CorporateSentinelIdentity || binding.PublicSentinelIdentity == binding.CorporateSentinelIdentity {
		return liveConfig{}, errors.New("fixture and sentinel identities must be distinct")
	}
	return liveConfig{preflight: preflight, dryRun: dryRunText == "1", driverPath: driver, driverSHA256: driverHash, driverSigners: []string{signer}, fixtureConfigPath: fixtureConfigPath, fixtureConfigSHA256: fixtureConfigHash, binding: binding, publicSentinel: publicEndpoint, publicSentinelHealth: publicHealthEndpoint, corporateSentinel: corporateEndpoint, corporateCIDR: corporateCIDR}, nil
}

func requiredSHA256(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if !isSHA256(value) {
		return "", fmt.Errorf("%s must be a lowercase SHA-256", name)
	}
	return value, nil
}

func isSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
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
	runID := "run-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	runDir := filepath.Join(config.preflight.EvidenceDirectory, runID)
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence run: %w", err)
	}
	runHandle, identity, err := openPinnedDirectory(runDir)
	if err != nil {
		return nil, fmt.Errorf("identify evidence run: %w", err)
	}
	h := &liveHarness{config: config, runDir: runDir, runID: runID, runDirectoryIdentity: identity, runDirectoryHandle: runHandle, client: clientapi.New(), actionTimeout: 30 * time.Second, cleanupTimeout: 5 * time.Second, restoreTimeout: 60 * time.Second, reconciliationWindow: stateTimeout, probeInterval: time.Second, probeReceipt: probeSentinelReceipt}
	h.validateRunDirectory = func() error {
		current, err := directoryIdentity(runDir)
		if err != nil {
			return err
		}
		if current != identity {
			return errors.New("evidence run directory identity changed")
		}
		return nil
	}
	h.verifyAndLockDriver = func() (io.Closer, error) { return verifyAndLockInputs(config) }
	h.invokeDriver = h.invokeExecutableDriver
	return h, nil
}

func directoryIdentity(path string) (string, error) {
	file, identity, err := openPinnedDirectory(path)
	if file != nil {
		_ = file.Close()
	}
	return identity, err
}

func openPinnedDirectory(path string) (*os.File, string, error) {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return nil, "", errors.New("run directory is absent, not a directory, or a reparse point")
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, "", errors.New("wrap run directory handle")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		file.Close()
		return nil, "", err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		file.Close()
		return nil, "", errors.New("opened run directory handle is a reparse point or not a directory")
	}
	return file, fmt.Sprintf("volume:%08x/file:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func (h *liveHarness) closeRunDirectory() error {
	if h == nil || h.runDirectoryHandle == nil {
		return nil
	}
	err := h.runDirectoryHandle.Close()
	h.runDirectoryHandle = nil
	return err
}

func verifyAndLockExecutable(config liveConfig) (io.Closer, error) {
	if !strings.EqualFold(filepath.Ext(config.driverPath), ".exe") {
		return nil, errors.New("integration driver must be a signed .exe")
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(config.driverPath), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("lock driver: %w", err)
	}
	file := os.NewFile(uintptr(handle), config.driverPath)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errors.New("wrap driver handle")
	}
	if err := coreverify.Verify(config.driverPath, config.driverSHA256, config.driverSigners); err != nil {
		file.Close()
		return nil, fmt.Errorf("verify pinned driver: %w", err)
	}
	return file, nil
}

type closerGroup []io.Closer

func (c closerGroup) Close() error {
	var errs []error
	for index := len(c) - 1; index >= 0; index-- {
		errs = append(errs, c[index].Close())
	}
	return errors.Join(errs...)
}

func verifyAndLockInputs(config liveConfig) (io.Closer, error) {
	driver, err := verifyAndLockExecutable(config)
	if err != nil {
		return nil, err
	}
	fixtureConfig, err := lockPinnedData(config.fixtureConfigPath, config.fixtureConfigSHA256)
	if err != nil {
		_ = driver.Close()
		return nil, fmt.Errorf("verify pinned fixture config: %w", err)
	}
	return closerGroup{driver, fixtureConfig}, nil
}

func lockPinnedData(path, expectedSHA256 string) (io.Closer, error) {
	if _, err := validateOrdinaryFile(path); err != nil || !isSHA256(expectedSHA256) {
		return nil, errors.New("pinned data path or hash is invalid")
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errors.New("wrap pinned data handle")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		file.Close()
		return nil, err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expectedSHA256)) != 1 {
		file.Close()
		return nil, errors.New("pinned data hash mismatch")
	}
	return file, nil
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
	custody, err := newTrustedBaseline(caseDir, baselinePath, baseline)
	if err != nil {
		t.Fatalf("preserve trusted baseline: %v", err)
	}
	h.setActive(testCase.Name, custody)
	defer func() {
		if err := h.restoreAndProve(testCase.Name, caseDir, custody); err != nil {
			h.markPoisoned(err)
			t.Errorf("FINAL RESTORATION COULD NOT BE PROVEN: %v", err)
			return
		}
		h.clearActive()
		_ = custody.Close()
	}()

	h.assertReceipt(t, "baseline public sentinel", h.config.publicSentinel, h.config.binding.PublicSentinelIdentity, "")
	h.assertReceipt(t, "baseline corporate sentinel", h.config.corporateSentinel, h.config.binding.CorporateSentinelIdentity, "")
	if _, err := h.action("case-setup", testCase.Name, custody); err != nil {
		t.Fatalf("case setup: %v", err)
	}
	if _, err := h.action("fake-upstream-stop", testCase.Name, custody); err != nil {
		t.Fatalf("force fake upstream absent: %v", err)
	}

	switch testCase.Name {
	case "connect-success-to-fake-upstream":
		h.startUpstreamAndConnect(t, testCase.Name, custody)
		h.assertReceipt(t, "public sentinel through fake upstream", h.config.publicSentinel, h.config.binding.PublicSentinelIdentity, h.config.binding.FakeUpstreamIdentity)
		h.assertReceipt(t, "corporate sentinel while connected", h.config.corporateSentinel, h.config.binding.CorporateSentinelIdentity, "")
		h.disconnect(t)
	case "upstream-absent":
		h.connectWithUnavailableUpstream(t)
		h.assertLeakBlocked(t)
		h.disconnect(t)
	case "upstream-dies-while-connected":
		h.startUpstreamAndConnect(t, testCase.Name, custody)
		h.mustAction(t, "fake-upstream-stop", testCase.Name, custody)
		h.assertLeakBlocked(t)
		h.disconnect(t)
	case "core-exits":
		h.startUpstreamAndConnect(t, testCase.Name, custody)
		h.mustAction(t, "core-crash", testCase.Name, custody)
		h.waitForState(t, accessmodel.StateFailed)
		h.assertLeakBlocked(t)
		h.disconnect(t)
	case "ui-exits":
		h.mustAction(t, "ui-start", testCase.Name, custody)
		h.startUpstreamAndConnect(t, testCase.Name, custody)
		h.mustAction(t, "ui-exit", testCase.Name, custody)
		h.waitForState(t, accessmodel.StateConnected)
		h.assertReceipt(t, "public sentinel after UI exit", h.config.publicSentinel, h.config.binding.PublicSentinelIdentity, h.config.binding.FakeUpstreamIdentity)
		h.assertReceipt(t, "corporate sentinel after UI exit", h.config.corporateSentinel, h.config.binding.CorporateSentinelIdentity, "")
		h.disconnect(t)
	case "service-restarts":
		h.startUpstreamAndConnect(t, testCase.Name, custody)
		h.mustAction(t, "agent-crash", testCase.Name, custody)
		h.assertLeakBlocked(t)
		h.mustAction(t, "agent-start", testCase.Name, custody)
		h.waitForState(t, accessmodel.StateDisconnected)
	case "machine-style-recovery":
		h.mustAction(t, "stage-machine-recovery", testCase.Name, custody)
		h.assertLeakBlocked(t)
		h.mustAction(t, "machine-recover", testCase.Name, custody)
		h.waitForState(t, accessmodel.StateDisconnected)
	case "twenty-connect-disconnect-cycles":
		h.mustAction(t, "fake-upstream-start", testCase.Name, custody)
		for cycle := 1; cycle <= testCase.ConnectCycles; cycle++ {
			h.connectMustSucceed(t)
			h.assertReceipt(t, fmt.Sprintf("public sentinel cycle %d", cycle), h.config.publicSentinel, h.config.binding.PublicSentinelIdentity, h.config.binding.FakeUpstreamIdentity)
			h.assertReceipt(t, fmt.Sprintf("corporate sentinel cycle %d", cycle), h.config.corporateSentinel, h.config.binding.CorporateSentinelIdentity, "")
			h.disconnect(t)
			h.assertReceipt(t, fmt.Sprintf("restored public sentinel cycle %d", cycle), h.config.publicSentinel, h.config.binding.PublicSentinelIdentity, "")
			h.assertReceipt(t, fmt.Sprintf("restored corporate sentinel cycle %d", cycle), h.config.corporateSentinel, h.config.binding.CorporateSentinelIdentity, "")
		}
	case "uninstall-cleanup":
		h.startUpstreamAndConnect(t, testCase.Name, custody)
		h.disconnect(t)
		h.mustAction(t, "uninstall", testCase.Name, custody)
	default:
		t.Fatalf("unimplemented scenario %q", testCase.Name)
	}
}

func (h *liveHarness) mustAction(t *testing.T, action, scenarioName string, baseline *trustedBaseline) fixtureproto.Response {
	t.Helper()
	response, err := h.action(action, scenarioName, baseline)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (h *liveHarness) startUpstreamAndConnect(t *testing.T, scenarioName string, baseline *trustedBaseline) {
	t.Helper()
	h.mustAction(t, "fake-upstream-start", scenarioName, baseline)
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
	probe := h.probeReceipt
	if probe == nil {
		probe = probeSentinelReceipt
	}
	if err := proveLeakBlocked(h.reconciliationWindow, h.probeInterval, h.config.publicSentinel, h.config.publicSentinelHealth, h.config.corporateSentinel, probe, h.config.binding.PublicSentinelIdentity, h.config.binding.CorporateSentinelIdentity); err != nil {
		t.Fatal(err)
	}
}

type sentinelReceipt struct {
	Nonce           string `json:"nonce"`
	Identity        string `json:"identity"`
	ViaFakeUpstream string `json:"via_fake_upstream,omitempty"`
}

func proveLeakBlocked(window, interval time.Duration, publicEndpoint, publicHealthEndpoint, corporateEndpoint string, probe func(string, string, string) (bool, error), publicIdentity, corporateIdentity string) error {
	if window <= 0 || interval <= 0 || probe == nil {
		return errors.New("leak-proof timing and probe must be configured")
	}
	deadline := time.Now().Add(window)
	for attempt := 1; ; attempt++ {
		received, _ := probe(publicEndpoint, publicIdentity, "")
		if received {
			return fmt.Errorf("PUBLIC TCP LEAK: ordinary-gateway sentinel was reachable on attempt %d while tunnel was unavailable", attempt)
		}
		if _, err := probe(publicHealthEndpoint, publicIdentity, ""); err != nil {
			return fmt.Errorf("public sentinel health/ownership failed on attempt %d: %w", attempt, err)
		}
		if _, err := probe(corporateEndpoint, corporateIdentity, ""); err != nil {
			return fmt.Errorf("corporate sentinel health/ownership failed on attempt %d: %w", attempt, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		if remaining < interval {
			time.Sleep(remaining)
		} else {
			time.Sleep(interval)
		}
	}
}

func probeSentinelReceipt(endpoint, expectedIdentity, expectedVia string) (bool, error) {
	nonce, err := randomNonce()
	if err != nil {
		return false, err
	}
	connection, err := net.DialTimeout("tcp4", endpoint, probeTimeout)
	if err != nil {
		return false, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(probeTimeout))
	if err := json.NewEncoder(connection).Encode(map[string]string{"nonce": nonce}); err != nil {
		return true, err
	}
	var receipt sentinelReceipt
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(connection, 4097)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return true, err
	}
	return true, validateSentinelReceipt(nonce, expectedIdentity, expectedVia, receipt)
}

func validateSentinelReceipt(nonce, expectedIdentity, expectedVia string, receipt sentinelReceipt) error {
	if receipt.Nonce != nonce || nonce == "" || receipt.Identity != expectedIdentity || expectedIdentity == "" {
		return errors.New("sentinel nonce/identity receipt mismatch")
	}
	if receipt.ViaFakeUpstream != expectedVia {
		return errors.New("sentinel traversal receipt mismatch")
	}
	return nil
}

func (h *liveHarness) assertReceipt(t *testing.T, description, endpoint, identity, via string) {
	t.Helper()
	probe := h.probeReceipt
	if probe == nil {
		probe = probeSentinelReceipt
	}
	if _, err := probe(endpoint, identity, via); err != nil {
		t.Fatalf("%s %s receipt failed: %v", description, endpoint, err)
	}
}

func (h *liveHarness) capture(ctx context.Context, scenarioName, _ string) ([]byte, error) {
	response, err := h.callDriver(ctx, fixtureproto.Request{Action: "capture", Scenario: scenarioName})
	if err != nil {
		return nil, err
	}
	return response.Snapshot.CanonicalState()
}

func (h *liveHarness) restoreAndProve(scenarioName, caseDir string, baseline *trustedBaseline) error {
	cleanupErr, restoreErr := runRestorationActions(
		func(ctx context.Context) error {
			_, err := h.actionWithContext(ctx, "case-cleanup", scenarioName, baseline)
			return err
		},
		func(ctx context.Context) error {
			restorePath, err := baseline.RestoreInput()
			if err != nil {
				return err
			}
			request := fixtureproto.Request{Action: "restore", Scenario: scenarioName, BaselinePath: restorePath, BaselineSHA256: baseline.hash}
			_, err = h.callDriver(ctx, request)
			return err
		},
		h.cleanupTimeout,
		h.restoreTimeout,
	)
	captureCtx, cancel := context.WithTimeout(context.Background(), h.actionTimeout)
	defer cancel()
	final, captureErr := h.capture(captureCtx, scenarioName, caseDir)
	if captureErr == nil {
		captureErr = writeNewFile(filepath.Join(caseDir, "final.json"), final)
	}
	if cleanupErr != nil || restoreErr != nil || captureErr != nil {
		return errors.Join(cleanupErr, restoreErr, captureErr)
	}
	if !bytes.Equal(baseline.data, final) {
		drift := map[string]string{"baseline_sha256": baseline.hash, "final_sha256": digest(final)}
		encoded, _ := json.MarshalIndent(drift, "", "  ")
		_ = writeNewFile(filepath.Join(caseDir, "STATE-DRIFT.json"), encoded)
		return fmt.Errorf("exact baseline mismatch: before %s, after %s", drift["baseline_sha256"], drift["final_sha256"])
	}
	return nil
}

func (h *liveHarness) action(action, scenarioName string, baseline *trustedBaseline) (fixtureproto.Response, error) {
	timeout := h.actionTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return h.actionWithContext(ctx, action, scenarioName, baseline)
}

func (h *liveHarness) actionWithContext(ctx context.Context, action, scenarioName string, baseline *trustedBaseline) (fixtureproto.Response, error) {
	request := fixtureproto.Request{Action: action, Scenario: scenarioName}
	if baseline != nil {
		request.BaselinePath = baseline.trustedPath
		request.BaselineSHA256 = baseline.hash
	}
	return h.callDriver(ctx, request)
}

func (h *liveHarness) callDriver(ctx context.Context, request fixtureproto.Request) (fixtureproto.Response, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		timeout := h.actionTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	type callResult struct {
		response fixtureproto.Response
		err      error
	}
	done := make(chan callResult, 1)
	go func() {
		response, err := h.callDriverOnce(ctx, request)
		done <- callResult{response, err}
	}()
	select {
	case result := <-done:
		return result.response, result.err
	case <-ctx.Done():
		return fixtureproto.Response{}, ctx.Err()
	}
}

func (h *liveHarness) callDriverOnce(ctx context.Context, request fixtureproto.Request) (fixtureproto.Response, error) {
	if h.validateRunDirectory == nil || h.verifyAndLockDriver == nil || h.invokeDriver == nil {
		return fixtureproto.Response{}, errors.New("driver custody is not configured")
	}
	if err := h.validateRunDirectory(); err != nil {
		return fixtureproto.Response{}, fmt.Errorf("refuse action %s: %w", request.Action, err)
	}
	locked, err := h.verifyAndLockDriver()
	if err != nil {
		return fixtureproto.Response{}, fmt.Errorf("refuse action %s: %w", request.Action, err)
	}
	nonce, err := randomNonce()
	if err != nil {
		return fixtureproto.Response{}, err
	}
	request.ProtocolVersion = fixtureproto.ProtocolVersion
	request.RequestNonce = nonce
	request.RunID = h.runID
	request.EvidenceDirectory = h.runDir
	request.EvidenceDirectoryIdentity = h.runDirectoryIdentity
	type invocationResult struct {
		data []byte
		err  error
	}
	invocation := make(chan invocationResult, 1)
	go func() {
		data, invokeErr := h.invokeDriver(ctx, request)
		closeErr := locked.Close()
		invocation <- invocationResult{data: data, err: errors.Join(invokeErr, closeErr)}
	}()
	var responseData []byte
	select {
	case result := <-invocation:
		responseData, err = result.data, result.err
	case <-ctx.Done():
		return fixtureproto.Response{}, ctx.Err()
	}
	if err != nil {
		if ctx.Err() != nil {
			return fixtureproto.Response{}, ctx.Err()
		}
		return fixtureproto.Response{}, fmt.Errorf("driver action %s failed", request.Action)
	}
	var response fixtureproto.Response
	decoder := json.NewDecoder(bytes.NewReader(responseData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return fixtureproto.Response{}, fmt.Errorf("driver action %s returned invalid JSON: %w", request.Action, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fixtureproto.Response{}, fmt.Errorf("driver action %s returned trailing data", request.Action)
	}
	if err := fixtureproto.ValidateResponse(request, h.config.binding, response); err != nil {
		return fixtureproto.Response{}, fmt.Errorf("driver action %s evidence refused: %w", request.Action, err)
	}
	canonical, err := response.Snapshot.CanonicalState()
	if err != nil {
		return fixtureproto.Response{}, err
	}
	if response.Evidence.Facts["post_state_sha256"] != digest(canonical) {
		return fixtureproto.Response{}, errors.New("driver post-state hash does not match the bound snapshot")
	}
	if h.config.preflight.Hostname != "" && !strings.EqualFold(response.Evidence.Facts["host_identity"], h.config.preflight.Hostname) {
		return fixtureproto.Response{}, errors.New("driver host identity does not match the disposable host authorization")
	}
	if request.Action == "capture" && response.Evidence.Facts["snapshot_sha256"] != digest(canonical) {
		return fixtureproto.Response{}, errors.New("driver snapshot hash does not match the structured capture")
	}
	h.recordMu.Lock()
	defer h.recordMu.Unlock()
	h.actionCount++
	record := map[string]any{"sequence": h.actionCount, "request_nonce": request.RequestNonce, "run_id": request.RunID, "action": request.Action, "scenario": request.Scenario, "binding": response.Binding, "evidence": response.Evidence, "snapshot": response.Snapshot, "ok": response.OK, "timestamp_utc": time.Now().UTC().Format(time.RFC3339Nano)}
	recordData, _ := json.Marshal(record)
	if err := writeNewFile(filepath.Join(h.runDir, fmt.Sprintf("action-%04d.json", h.actionCount)), recordData); err != nil {
		return fixtureproto.Response{}, fmt.Errorf("write action evidence: %w", err)
	}
	return response, nil
}

func (h *liveHarness) invokeExecutableDriver(ctx context.Context, request fixtureproto.Request) ([]byte, error) {
	requestData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, h.config.driverPath)
	command.Env = append(environmentWithout(os.Environ(), envFixtureConfig), envFixtureConfig+"="+h.config.fixtureConfigPath)
	command.Stdin = bytes.NewReader(append(requestData, '\n'))
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

func environmentWithout(environment []string, name string) []string {
	prefix := name + "="
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.EqualFold(entry[:min(len(entry), len(prefix))], prefix) {
			result = append(result, entry)
		}
	}
	return result
}

func randomNonce() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate action nonce: %w", err)
	}
	return hex.EncodeToString(nonce[:]), nil
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

func newTrustedBaseline(caseDir, evidencePath string, data []byte) (*trustedBaseline, error) {
	directoryHandle, directoryIdentityValue, err := openPinnedDirectory(caseDir)
	if err != nil {
		return nil, fmt.Errorf("pin baseline directory: %w", err)
	}
	if err := writeNewFile(evidencePath, data); err != nil {
		directoryHandle.Close()
		return nil, err
	}
	path, file, err := createProtectedImmutable(caseDir, ".trusted-baseline-", data)
	if err != nil {
		directoryHandle.Close()
		return nil, err
	}
	return &trustedBaseline{
		data:                  append([]byte(nil), data...),
		hash:                  digest(data),
		evidencePath:          evidencePath,
		trustedPath:           path,
		trustedHandle:         file,
		caseDirectoryHandle:   directoryHandle,
		caseDirectoryIdentity: directoryIdentityValue,
	}, nil
}

func (b *trustedBaseline) Verify() error {
	if b == nil || b.trustedHandle == nil {
		return errors.New("trusted baseline custody is unavailable")
	}
	currentDirectoryIdentity, err := directoryIdentity(filepath.Dir(b.evidencePath))
	if err != nil || currentDirectoryIdentity != b.caseDirectoryIdentity {
		return errors.New("trusted baseline directory identity changed")
	}
	data := make([]byte, len(b.data))
	if _, err := b.trustedHandle.ReadAt(data, 0); err != nil {
		return fmt.Errorf("read trusted baseline handle: %w", err)
	}
	if !bytes.Equal(data, b.data) || digest(data) != b.hash {
		return errors.New("trusted baseline handle no longer matches memory")
	}
	return nil
}

func (b *trustedBaseline) RestoreInput() (string, error) {
	if err := b.Verify(); err != nil {
		return "", err
	}
	evidence, evidenceErr := os.ReadFile(b.evidencePath)
	if evidenceErr == nil && bytes.Equal(evidence, b.data) {
		return b.trustedPath, nil
	}
	directory := filepath.Dir(b.evidencePath)
	path, file, err := createProtectedImmutable(directory, ".trusted-restore-input-", b.data)
	if err != nil {
		return "", fmt.Errorf("recreate trusted restore input: %w", err)
	}
	b.restoreInputs = append(b.restoreInputs, file)
	verification := make([]byte, len(b.data))
	if _, err := file.ReadAt(verification, 0); err != nil || !bytes.Equal(verification, b.data) || digest(verification) != b.hash {
		return "", errors.New("recreated restore input could not be verified")
	}
	return path, nil
}

func (b *trustedBaseline) Close() error {
	if b == nil {
		return nil
	}
	var errs []error
	for _, file := range append([]*os.File{b.trustedHandle, b.caseDirectoryHandle}, b.restoreInputs...) {
		if file != nil {
			errs = append(errs, file.Close())
		}
	}
	b.trustedHandle = nil
	b.caseDirectoryHandle = nil
	b.restoreInputs = nil
	return errors.Join(errs...)
}

func createProtectedImmutable(directory, prefix string, data []byte) (string, *os.File, error) {
	securityDescriptor, err := windows.SecurityDescriptorFromString(trustedBaselineSDDL)
	if err != nil {
		return "", nil, err
	}
	attributes := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: securityDescriptor}
	for range 32 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		path := filepath.Join(directory, prefix+hex.EncodeToString(random[:])+".json")
		pathUTF16, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return "", nil, err
		}
		handle, err := windows.CreateFile(pathUTF16, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		file := os.NewFile(uintptr(handle), path)
		if file == nil {
			_ = windows.CloseHandle(handle)
			return "", nil, errors.New("wrap trusted baseline handle")
		}
		if _, err := file.Write(data); err != nil {
			_ = file.Close()
			return "", nil, err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return "", nil, err
		}
		return path, file, nil
	}
	return "", nil, errors.New("could not allocate trusted baseline file")
}

func runRestorationActions(cleanup, restore func(context.Context) error, cleanupBudget, restoreBudget time.Duration) (error, error) {
	cleanupErr := runBoundedAction(cleanup, cleanupBudget)
	restoreErr := runBoundedAction(restore, restoreBudget)
	return cleanupErr, restoreErr
}

func runBoundedAction(action func(context.Context) error, budget time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- action(ctx) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
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

func (h *liveHarness) setActive(scenarioName string, baseline *trustedBaseline) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeScenario, h.activeBaseline = scenarioName, baseline
}

func (h *liveHarness) clearActive() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeScenario, h.activeBaseline = "", nil
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
	return h.activeScenario == "" && h.activeBaseline == nil && h.restorePoison == nil
}

func (h *liveHarness) lastChanceRestore() error {
	h.mu.Lock()
	scenarioName, baseline := h.activeScenario, h.activeBaseline
	h.mu.Unlock()
	if scenarioName == "" || baseline == nil {
		return h.poisoned()
	}
	caseDir := filepath.Dir(baseline.evidencePath)
	cleanupErr, restoreErr := runRestorationActions(
		func(ctx context.Context) error {
			_, err := h.actionWithContext(ctx, "case-cleanup", scenarioName, baseline)
			return err
		},
		func(ctx context.Context) error {
			restorePath, err := baseline.RestoreInput()
			if err != nil {
				return err
			}
			_, err = h.callDriver(ctx, fixtureproto.Request{Action: "restore", Scenario: scenarioName, BaselinePath: restorePath, BaselineSHA256: baseline.hash})
			return err
		},
		h.cleanupTimeout,
		h.restoreTimeout,
	)
	finalCtx, cancel := context.WithTimeout(context.Background(), h.actionTimeout)
	defer cancel()
	final, captureErr := h.capture(finalCtx, scenarioName, caseDir)
	var writeErr, driftErr error
	if captureErr == nil {
		writeErr = writeNewFile(filepath.Join(caseDir, "last-chance-final.json"), final)
		if !bytes.Equal(baseline.data, final) {
			driftErr = fmt.Errorf("last-chance state differs: before %s, after %s", baseline.hash, digest(final))
		}
	}
	closeErr := baseline.Close()
	runCloseErr := h.closeRunDirectory()
	return errors.Join(cleanupErr, restoreErr, captureErr, writeErr, driftErr, closeErr, runCloseErr)
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
