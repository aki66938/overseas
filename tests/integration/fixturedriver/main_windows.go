//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"corp.example/overseas-access-gateway/internal/coreverify"
	"corp.example/overseas-access-gateway/tests/integration/fixtureconfig"
	"corp.example/overseas-access-gateway/tests/integration/fixtureproto"
	"corp.example/overseas-access-gateway/tests/integration/winjob"
	"golang.org/x/sys/windows"
)

const (
	fixtureConfigEnvironment = "OVERSEAS_ACCESS_FIXTURE_CONFIG"
	agentServiceName         = "RegenBioOverseasAccessAgent"
	runtimeFirewallGroup     = "RegenBioOverseasAccess.Managed"
	commandTimeout           = 45 * time.Second
	probeTimeout             = 3 * time.Second
)

var mutatingActions = []string{
	"case-setup", "fake-upstream-start", "fake-upstream-stop", "core-crash",
	"ui-start", "ui-exit", "agent-crash", "agent-start", "stage-machine-recovery",
	"machine-recover", "uninstall", "case-cleanup", "restore",
}

type fixtureConfig struct {
	SchemaVersion                int                         `json:"schema_version"`
	HostIdentity                 string                      `json:"host_identity"`
	EvidenceRoot                 string                      `json:"evidence_root"`
	PayloadPath                  string                      `json:"payload_path"`
	CredentialSourcePath         string                      `json:"credential_source_path"`
	CredentialSourceSHA256       string                      `json:"credential_source_sha256"`
	GeneratedConfigPath          string                      `json:"generated_config_path"`
	ServerConfigPath             string                      `json:"server_config_path"`
	ServerAttestationPath        string                      `json:"server_attestation_path"`
	ServerAttestationSHA256      string                      `json:"server_attestation_sha256"`
	ServerHostKeyFingerprint     string                      `json:"server_host_key_fingerprint"`
	ActionConfigPath             string                      `json:"action_config_path"`
	FixtureManifestPath          string                      `json:"fixture_manifest_path"`
	FixtureManifestSignaturePath string                      `json:"fixture_manifest_signature_path"`
	FixtureManifestSigners       []string                    `json:"fixture_manifest_signers"`
	ArtifactSigners              map[string][]string         `json:"artifact_signers"`
	PowerShellPath               string                      `json:"powershell_path"`
	ActionHelperPath             string                      `json:"action_helper_path"`
	Binding                      fixtureproto.FixtureBinding `json:"binding"`
	PublicSentinel               string                      `json:"public_sentinel"`
	PublicSentinelHealth         string                      `json:"public_sentinel_health"`
	CorporateSentinel            string                      `json:"corporate_sentinel"`
	FakeUpstreamControl          string                      `json:"fake_upstream_control"`
	FakeUpstreamData             string                      `json:"fake_upstream_data"`
}

type dependencies struct {
	runCommand        func(context.Context, []string, fixtureproto.Request, string) error
	capture           func(context.Context, string) (fixtureproto.Snapshot, error)
	probeIdentity     func(context.Context, string, string, bool) error
	hashFile          func(string) (string, error)
	validateEvidence  func(string, string) error
	verifyCommand     func(string, []string) (io.Closer, error)
	lockInput         func(string, string) (io.Closer, error)
	validateFixture   func(context.Context, fixtureConfig) (io.Closer, error)
	validateGenerated func(fixtureConfig) error
}

func (c fixtureConfig) Validate() error {
	if c.SchemaVersion != 1 || strings.TrimSpace(c.HostIdentity) == "" {
		return errors.New("fixture schema and host identity are required")
	}
	for name, value := range map[string]string{
		"payload path": c.PayloadPath, "generated config path": c.GeneratedConfigPath, "server config path": c.ServerConfigPath, "action config path": c.ActionConfigPath, "fixture manifest path": c.FixtureManifestPath, "fixture manifest signature path": c.FixtureManifestSignaturePath, "powershell path": c.PowerShellPath, "action helper path": c.ActionHelperPath, "evidence root": c.EvidenceRoot,
		"credential source path": c.CredentialSourcePath, "server attestation path": c.ServerAttestationPath,
		"public sentinel": c.PublicSentinel, "public sentinel health": c.PublicSentinelHealth, "corporate sentinel": c.CorporateSentinel,
		"fake upstream control": c.FakeUpstreamControl, "fake upstream data": c.FakeUpstreamData,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	for name, value := range map[string]string{"payload path": c.PayloadPath, "credential source path": c.CredentialSourcePath, "generated config path": c.GeneratedConfigPath, "server config path": c.ServerConfigPath, "server attestation path": c.ServerAttestationPath, "action config path": c.ActionConfigPath, "fixture manifest path": c.FixtureManifestPath, "fixture manifest signature path": c.FixtureManifestSignaturePath, "powershell path": c.PowerShellPath, "action helper path": c.ActionHelperPath, "evidence root": c.EvidenceRoot} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be absolute and clean", name)
		}
	}
	for name, value := range map[string]string{"payload hash": c.Binding.PayloadSHA256, "credential source hash": c.CredentialSourceSHA256, "config hash": c.Binding.ConfigSHA256, "server config hash": c.Binding.ServerConfigSHA256, "server attestation hash": c.ServerAttestationSHA256, "action config hash": c.Binding.ActionConfigSHA256, "manifest hash": c.Binding.Artifacts.ManifestSHA256} {
		if !isSHA256(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if !strings.HasPrefix(c.ServerHostKeyFingerprint, "SHA256:") || strings.TrimSpace(strings.TrimPrefix(c.ServerHostKeyFingerprint, "SHA256:")) == "" {
		return errors.New("server host key fingerprint is invalid")
	}
	if c.Binding.FakeUpstreamIdentity == "" || c.Binding.PublicSentinelIdentity == "" || c.Binding.CorporateSentinelIdentity == "" {
		return errors.New("all fixture identities are required")
	}
	if c.Binding.ServerListenerEndpoint == "" || len(c.Binding.Network.CorporateCIDRs) == 0 || len(c.Binding.Network.CorporateDNS) == 0 || len(c.Binding.Network.InternalSuffixes) == 0 || len(c.Binding.PayloadFiles) == 0 {
		return errors.New("server, signed corporate network, and complete payload bindings are required")
	}
	if len(c.FixtureManifestSigners) == 0 {
		return errors.New("fixture manifest signer allowlist is required")
	}
	for _, role := range []string{"agent", "core", "ui", "server-service", "driver", "sentinel", "action-helper"} {
		if len(c.ArtifactSigners[role]) == 0 {
			return fmt.Errorf("artifact signer allowlist for %s is required", role)
		}
	}
	if c.Binding.FakeUpstreamIdentity == c.Binding.PublicSentinelIdentity || c.Binding.FakeUpstreamIdentity == c.Binding.CorporateSentinelIdentity || c.Binding.PublicSentinelIdentity == c.Binding.CorporateSentinelIdentity {
		return errors.New("fixture identities must be distinct")
	}
	if c.Binding.PublicSentinelEndpoint != c.PublicSentinel || c.Binding.PublicSentinelHealthEndpoint != c.PublicSentinelHealth || c.Binding.CorporateSentinelEndpoint != c.CorporateSentinel || c.Binding.FakeUpstreamControlEndpoint != c.FakeUpstreamControl || c.Binding.FakeUpstreamDataEndpoint != c.FakeUpstreamData {
		return errors.New("fixture binding endpoints do not match configured endpoints")
	}
	if !strings.EqualFold(filepath.Ext(c.ActionHelperPath), ".exe") {
		return errors.New("action helper must be an absolute .exe")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "fixture driver refused the request")
		os.Exit(1)
	}
}

func run() error {
	configPath := os.Getenv(fixtureConfigEnvironment)
	if configPath == "" || !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath {
		return errors.New("fixture config path is invalid")
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var config fixtureConfig
	decoder := json.NewDecoder(bytes.NewReader(configData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	requestData, err := io.ReadAll(io.LimitReader(os.Stdin, 256*1024+1))
	if err != nil || len(requestData) > 256*1024 {
		return errors.New("request is unavailable or oversized")
	}
	var request fixtureproto.Request
	decoder = json.NewDecoder(bytes.NewReader(requestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	response, err := executeRequest(ctx, config, request, dependencies{
		runCommand: runConfiguredCommand,
		capture: func(ctx context.Context, nonce string) (fixtureproto.Snapshot, error) {
			return captureWindows(ctx, nonce, config)
		},
		probeIdentity:    probeFixtureIdentity,
		hashFile:         hashFile,
		validateEvidence: validateEvidenceDirectory,
		verifyCommand:    config.verifyAndLockCommand,
		lockInput:        lockPinnedInput,
		validateFixture:  validateFixtureAssets,
		validateGenerated: func(config fixtureConfig) error {
			manifestData, err := os.ReadFile(config.FixtureManifestPath)
			if err != nil {
				return err
			}
			manifest, err := fixtureconfig.ParseManifest(manifestData)
			if err != nil {
				return err
			}
			client, err := os.ReadFile(config.GeneratedConfigPath)
			if err != nil {
				return err
			}
			server, err := os.ReadFile(config.ServerConfigPath)
			if err != nil {
				return err
			}
			if err := fixtureconfig.ValidateGeneratedConfigs(client, server, config.FakeUpstreamData, manifest.NetworkPolicy()); err != nil {
				return err
			}
			actionData, err := os.ReadFile(config.ActionConfigPath)
			if err != nil {
				return err
			}
			actionConfig, err := fixtureconfig.ParseActionConfig(actionData)
			if err != nil {
				return err
			}
			if actionConfig.FixtureManifestPath != config.FixtureManifestPath || actionConfig.GeneratedConfigPath != config.GeneratedConfigPath || actionConfig.ServerConfigPath != config.ServerConfigPath || actionConfig.ServerConfigSHA256 != config.Binding.ServerConfigSHA256 || actionConfig.ServerListenerEndpoint != config.Binding.ServerListenerEndpoint || actionConfig.CredentialSourcePath != config.CredentialSourcePath || actionConfig.CredentialSourceSHA256 != config.CredentialSourceSHA256 || actionConfig.ServerAttestationPath != config.ServerAttestationPath || actionConfig.ServerAttestationSHA256 != config.ServerAttestationSHA256 || actionConfig.ServerHostKeyFingerprint != config.ServerHostKeyFingerprint {
				return errors.New("action config fixture/config path mismatch")
			}
			if err := validateRemoteServerAttestation(config, manifest); err != nil {
				return err
			}
			return actionConfig.Validate(manifest, config.FakeUpstreamData, config.FakeUpstreamControl, config.PublicSentinel, config.Binding.FakeUpstreamIdentity, config.PayloadPath)
		},
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(response)
}

func executeRequest(ctx context.Context, config fixtureConfig, request fixtureproto.Request, deps dependencies) (fixtureproto.Response, error) {
	if err := config.Validate(); err != nil {
		return fixtureproto.Response{}, err
	}
	if request.ProtocolVersion != fixtureproto.ProtocolVersion || request.RunID == "" || request.RequestNonce == "" || request.Action == "" || request.EvidenceDirectoryIdentity == "" || !withinDirectory(config.EvidenceRoot, request.EvidenceDirectory) {
		return fixtureproto.Response{}, errors.New("request run/directory binding is invalid")
	}
	if deps.validateEvidence == nil {
		return fixtureproto.Response{}, errors.New("evidence identity validator is absent")
	}
	if err := deps.validateEvidence(request.EvidenceDirectory, request.EvidenceDirectoryIdentity); err != nil {
		return fixtureproto.Response{}, fmt.Errorf("evidence directory identity changed: %w", err)
	}
	if deps.runCommand == nil || deps.capture == nil || deps.probeIdentity == nil {
		return fixtureproto.Response{}, errors.New("fixture dependencies are incomplete")
	}
	if deps.lockInput == nil {
		return fixtureproto.Response{}, errors.New("pinned input locker is absent")
	}
	if deps.validateFixture != nil {
		fixtureLocks, err := deps.validateFixture(ctx, config)
		if err != nil {
			return fixtureproto.Response{}, fmt.Errorf("fixture artifact custody failed: %w", err)
		}
		defer fixtureLocks.Close()
	}
	payloadLock, err := deps.lockInput(config.PayloadPath, config.Binding.PayloadSHA256)
	if err != nil {
		return fixtureproto.Response{}, errors.New("payload pin changed")
	}
	defer payloadLock.Close()
	configLock, err := deps.lockInput(config.GeneratedConfigPath, config.Binding.ConfigSHA256)
	if err != nil {
		return fixtureproto.Response{}, errors.New("generated config pin changed")
	}
	defer configLock.Close()
	serverConfigLock, err := deps.lockInput(config.ServerConfigPath, config.Binding.ServerConfigSHA256)
	if err != nil {
		return fixtureproto.Response{}, errors.New("server config pin changed")
	}
	defer serverConfigLock.Close()
	actionConfigLock, err := deps.lockInput(config.ActionConfigPath, config.Binding.ActionConfigSHA256)
	if err != nil {
		return fixtureproto.Response{}, errors.New("action config pin changed")
	}
	defer actionConfigLock.Close()
	if deps.validateGenerated != nil {
		if err := deps.validateGenerated(config); err != nil {
			return fixtureproto.Response{}, fmt.Errorf("generated configuration isolation failed: %w", err)
		}
	}
	if deps.hashFile == nil {
		deps.hashFile = func(path string) (string, error) {
			switch path {
			case config.PayloadPath:
				return config.Binding.PayloadSHA256, nil
			case config.GeneratedConfigPath:
				return config.Binding.ConfigSHA256, nil
			case config.ServerConfigPath:
				return config.Binding.ServerConfigSHA256, nil
			case config.ActionConfigPath:
				return config.Binding.ActionConfigSHA256, nil
			case request.BaselinePath:
				return request.BaselineSHA256, nil
			default:
				return "", errors.New("unexpected hash path")
			}
		}
	}
	payloadHash, err := deps.hashFile(config.PayloadPath)
	if err != nil || payloadHash != config.Binding.PayloadSHA256 {
		return fixtureproto.Response{}, errors.New("payload hash changed")
	}
	configHash, err := deps.hashFile(config.GeneratedConfigPath)
	if err != nil || configHash != config.Binding.ConfigSHA256 {
		return fixtureproto.Response{}, errors.New("generated config hash changed")
	}
	serverConfigHash, err := deps.hashFile(config.ServerConfigPath)
	if err != nil || serverConfigHash != config.Binding.ServerConfigSHA256 {
		return fixtureproto.Response{}, errors.New("server config hash changed")
	}
	actionConfigHash, err := deps.hashFile(config.ActionConfigPath)
	if err != nil || actionConfigHash != config.Binding.ActionConfigSHA256 {
		return fixtureproto.Response{}, errors.New("action config hash changed")
	}
	if request.Action != "preflight" && request.Action != "capture" {
		if !withinDirectory(request.EvidenceDirectory, request.BaselinePath) || !isSHA256(request.BaselineSHA256) {
			return fixtureproto.Response{}, errors.New("trusted baseline request is invalid")
		}
		baselineHash, err := deps.hashFile(request.BaselinePath)
		if err != nil || baselineHash != request.BaselineSHA256 {
			return fixtureproto.Response{}, errors.New("restore input hash changed")
		}
	}

	switch request.Action {
	case "preflight":
		if err := deps.probeIdentity(ctx, config.PublicSentinel, config.Binding.PublicSentinelIdentity, false); err != nil {
			return fixtureproto.Response{}, fmt.Errorf("public sentinel: %w", err)
		}
		if err := deps.probeIdentity(ctx, config.PublicSentinelHealth, config.Binding.PublicSentinelIdentity, false); err != nil {
			return fixtureproto.Response{}, fmt.Errorf("public sentinel health: %w", err)
		}
		if err := deps.probeIdentity(ctx, config.CorporateSentinel, config.Binding.CorporateSentinelIdentity, false); err != nil {
			return fixtureproto.Response{}, fmt.Errorf("corporate sentinel: %w", err)
		}
	case "capture":
	default:
		command := []string{config.ActionHelperPath}
		if deps.verifyCommand == nil {
			return fixtureproto.Response{}, errors.New("command verifier is absent")
		}
		lockedCommand, err := deps.verifyCommand(request.Action, command)
		if err != nil {
			return fixtureproto.Response{}, fmt.Errorf("configured command refused: %w", err)
		}
		defer lockedCommand.Close()
		if err := deps.runCommand(ctx, command, request, config.ActionConfigPath); err != nil {
			return fixtureproto.Response{}, err
		}
	}

	snapshot, err := deps.capture(ctx, request.RequestNonce)
	if err != nil {
		return fixtureproto.Response{}, err
	}
	if err := snapshot.Validate(request.RequestNonce, config.Binding); err != nil {
		return fixtureproto.Response{}, err
	}
	if err := validateActionListeners(request.Action, request.RunID, snapshot, config.Binding); err != nil {
		return fixtureproto.Response{}, err
	}
	state, err := snapshot.CanonicalState()
	if err != nil {
		return fixtureproto.Response{}, err
	}
	facts := buildActionFacts(config, request, snapshot, state)
	if request.Action == "restore" && facts["state_restored"] != "true" {
		return fixtureproto.Response{}, errors.New("restore post-state does not equal trusted baseline")
	}
	return fixtureproto.Response{
		ProtocolVersion: fixtureproto.ProtocolVersion,
		RequestNonce:    request.RequestNonce,
		RunID:           request.RunID,
		Scenario:        request.Scenario,
		Action:          request.Action,
		OK:              true,
		Binding:         config.Binding,
		Evidence:        fixtureproto.ActionEvidence{Kind: request.Action, ObservationNonce: request.RequestNonce, Facts: facts},
		Snapshot:        snapshot,
	}, nil
}

func validateActionListeners(action, runID string, snapshot fixtureproto.Snapshot, binding fixtureproto.FixtureBinding) error {
	present := make(map[string]fixtureproto.ListenerRecord, len(snapshot.Listeners))
	for _, listener := range snapshot.Listeners {
		if listener.Present {
			present[listener.Endpoint] = listener
		}
	}
	require := func(endpoint, role, hash string) error {
		listener, ok := present[endpoint]
		if !ok {
			return fmt.Errorf("required %s listener %s is absent", role, endpoint)
		}
		if listener.Role != role || listener.ImageSHA256 != hash {
			return fmt.Errorf("required %s listener identity/hash mismatch", role)
		}
		return nil
	}
	absent := func(endpoint string) error {
		if _, ok := present[endpoint]; ok {
			return fmt.Errorf("listener residue remains at %s", endpoint)
		}
		return nil
	}
	requireSamePID := func(first, second, description string) (int, error) {
		a, aOK := present[first]
		b, bOK := present[second]
		if !aOK || !bOK || a.PID <= 0 || a.PID != b.PID {
			return 0, fmt.Errorf("%s listeners must be owned by the same process", description)
		}
		return a.PID, nil
	}
	switch action {
	case "preflight":
		for _, item := range []struct{ endpoint, role, hash string }{{binding.PublicSentinelEndpoint, "sentinel", binding.Artifacts.SentinelSHA256}, {binding.PublicSentinelHealthEndpoint, "sentinel", binding.Artifacts.SentinelSHA256}, {binding.CorporateSentinelEndpoint, "sentinel", binding.Artifacts.SentinelSHA256}} {
			if err := require(item.endpoint, item.role, item.hash); err != nil {
				return err
			}
		}
		if _, err := requireSamePID(binding.PublicSentinelEndpoint, binding.PublicSentinelHealthEndpoint, "public data/health"); err != nil {
			return err
		}
		if err := absent(binding.FakeUpstreamControlEndpoint); err != nil {
			return fmt.Errorf("fake control endpoint is not free for the run-owned service: %w", err)
		}
		if err := absent(binding.FakeUpstreamDataEndpoint); err != nil {
			return fmt.Errorf("fake data endpoint is not free for the run-owned service: %w", err)
		}
	case "fake-upstream-start":
		if err := require(binding.FakeUpstreamControlEndpoint, "fake-upstream", binding.Artifacts.SentinelSHA256); err != nil {
			return err
		}
		if err := require(binding.FakeUpstreamDataEndpoint, "fake-upstream", binding.Artifacts.SentinelSHA256); err != nil {
			return err
		}
		listenerPID, err := requireSamePID(binding.FakeUpstreamControlEndpoint, binding.FakeUpstreamDataEndpoint, "fake control/data")
		if err != nil {
			return err
		}
		var fakeProcess fixtureproto.ProcessRecord
		for _, process := range snapshot.Processes {
			if process.Role == "fake-upstream" && process.Present {
				fakeProcess = process
			}
		}
		if fakeProcess.PID != listenerPID || fakeProcess.ParentPID <= 0 {
			return errors.New("fake listeners are not owned by the captured fake-upstream process")
		}
		expectedService := "RegenBioFixture-" + fixtureRunToken(runID) + "-Fake"
		for _, service := range snapshot.Services {
			if service.Name == expectedService && service.Present && service.Status == "Running" && service.Role == "action-helper" && service.PID == fakeProcess.ParentPID && service.PathSHA256 == binding.Artifacts.ActionHelperSHA256 {
				return nil
			}
		}
		return errors.New("fake listener process is not parented by the run-owned action-helper supervisor")
	case "fake-upstream-stop", "uninstall", "case-cleanup", "restore":
		if err := absent(binding.FakeUpstreamControlEndpoint); err != nil {
			return err
		}
		return absent(binding.FakeUpstreamDataEndpoint)
	}
	return nil
}

func fixtureRunToken(value string) string {
	var result strings.Builder
	for _, r := range value {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			result.WriteRune(r)
		}
	}
	text := result.String()
	if len(text) > 32 {
		return text[:32]
	}
	return text
}

func (c fixtureConfig) verifyAndLockCommand(_ string, command []string) (io.Closer, error) {
	if len(command) == 0 {
		return nil, errors.New("empty command")
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(command[0]), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), command[0])
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errors.New("wrap command handle")
	}
	if !strings.EqualFold(filepath.Clean(command[0]), filepath.Clean(c.ActionHelperPath)) {
		file.Close()
		return nil, errors.New("command is not the fixed action helper")
	}
	if err := coreverify.Verify(command[0], c.Binding.Artifacts.ActionHelperSHA256, c.ArtifactSigners["action-helper"]); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var errs []error
	for index := len(m) - 1; index >= 0; index-- {
		errs = append(errs, m[index].Close())
	}
	return errors.Join(errs...)
}

func validateFixtureAssets(ctx context.Context, config fixtureConfig) (io.Closer, error) {
	var locks multiCloser
	fail := func(err error) (io.Closer, error) { _ = locks.Close(); return nil, err }
	manifestLock, err := lockPinnedInput(config.FixtureManifestPath, config.Binding.Artifacts.ManifestSHA256)
	if err != nil {
		return fail(fmt.Errorf("lock manifest: %w", err))
	}
	locks = append(locks, manifestLock)
	signatureLock, err := lockUnhashedInput(config.FixtureManifestSignaturePath)
	if err != nil {
		return fail(fmt.Errorf("lock manifest signature: %w", err))
	}
	locks = append(locks, signatureLock)
	payloadSignaturePath := config.PayloadPath + ".p7s"
	payloadSignatureLock, err := lockUnhashedInput(payloadSignaturePath)
	if err != nil {
		return fail(fmt.Errorf("lock payload manifest signature: %w", err))
	}
	locks = append(locks, payloadSignatureLock)
	credentialSourceLock, err := lockPinnedInput(config.CredentialSourcePath, config.CredentialSourceSHA256)
	if err != nil {
		return fail(fmt.Errorf("lock credential source: %w", err))
	}
	locks = append(locks, credentialSourceLock)
	serverAttestationLock, err := lockPinnedInput(config.ServerAttestationPath, config.ServerAttestationSHA256)
	if err != nil {
		return fail(fmt.Errorf("lock server attestation: %w", err))
	}
	locks = append(locks, serverAttestationLock)
	manifestData, err := os.ReadFile(config.FixtureManifestPath)
	if err != nil {
		return fail(err)
	}
	manifest, err := fixtureconfig.ParseManifest(manifestData)
	if err != nil {
		return fail(err)
	}
	derived, err := manifest.ArtifactBinding(config.Binding.Artifacts.ManifestSHA256)
	if err != nil {
		return fail(err)
	}
	if derived != config.Binding.Artifacts {
		return fail(errors.New("manifest-derived artifact binding mismatch"))
	}
	if !equalStringLists(manifest.CorporateCIDRs, config.Binding.Network.CorporateCIDRs) || !equalStringLists(manifest.CorporateDNS, config.Binding.Network.CorporateDNS) || !equalStringLists(manifest.InternalSuffixes, config.Binding.Network.InternalSuffixes) {
		return fail(errors.New("manifest-derived corporate network binding mismatch"))
	}
	payloadData, err := os.ReadFile(config.PayloadPath)
	if err != nil {
		return fail(err)
	}
	payloadManifest, err := fixtureconfig.ParsePayloadManifest(payloadData)
	if err != nil {
		return fail(err)
	}
	payloadBindings, err := fixtureconfig.PayloadBindings(payloadManifest)
	if err != nil {
		return fail(err)
	}
	if !equalPayloadBindings(payloadBindings, config.Binding.PayloadFiles) {
		return fail(errors.New("manifest-derived payload file binding mismatch"))
	}
	if manifest.Artifacts["powershell"].Path != config.PowerShellPath || !strings.EqualFold(filepath.Clean(manifest.Artifacts["action-helper"].Path), filepath.Clean(config.ActionHelperPath)) {
		return fail(errors.New("manifest PowerShell/action-helper path mismatch"))
	}
	if digestBytes([]byte(windowsCaptureScript)) != manifest.Artifacts["capture-script"].SHA256 {
		return fail(errors.New("manifest capture-script hash does not match embedded capture"))
	}
	currentExecutable, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	if !strings.EqualFold(filepath.Clean(currentExecutable), filepath.Clean(manifest.Artifacts["driver"].Path)) {
		return fail(errors.New("manifest driver path is not the running image"))
	}
	if err := verifyDetachedManifest(ctx, config); err != nil {
		return fail(err)
	}
	if err := verifyDetachedFile(ctx, config, config.PayloadPath, payloadSignaturePath); err != nil {
		return fail(errors.New("detached payload manifest signature refused"))
	}
	for role, artifact := range manifest.Artifacts {
		locked, lockErr := lockPinnedInput(artifact.Path, artifact.SHA256)
		if lockErr != nil {
			return fail(fmt.Errorf("lock artifact %s: %w", role, lockErr))
		}
		locks = append(locks, locked)
		if signers, executable := config.ArtifactSigners[role]; executable {
			if err := coreverify.Verify(artifact.Path, artifact.SHA256, signers); err != nil {
				return fail(fmt.Errorf("verify artifact %s: %w", role, err))
			}
		}
	}
	if err := validateRemoteServerAttestation(config, manifest); err != nil {
		return fail(err)
	}
	return locks, nil
}

func validateRemoteServerAttestation(config fixtureConfig, manifest fixtureconfig.Manifest) error {
	data, err := os.ReadFile(config.ServerAttestationPath)
	if err != nil {
		return err
	}
	attestation, err := fixtureconfig.ParseServerAttestation(data)
	if err != nil {
		return err
	}
	return attestation.Validate(manifest, config.Binding.ServerListenerEndpoint, config.Binding.ServerConfigSHA256, config.ServerHostKeyFingerprint)
}

func lockUnhashedInput(path string) (io.Closer, error) {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errors.New("wrap pinned signature")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		file.Close()
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		file.Close()
		return nil, errors.New("manifest signature is not an ordinary file")
	}
	return file, nil
}

const verifyDetachedManifestScript = `$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Security;$m=[IO.File]::ReadAllBytes($args[0]);$c=New-Object Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$m);$s=New-Object Security.Cryptography.Pkcs.SignedCms -ArgumentList @($c,$true);$s.Decode([Convert]::FromBase64String([IO.File]::ReadAllText($args[1]).Trim()));$s.CheckSignature($true);$allowed=@($args[2].Split(',')|ForEach-Object{$_.ToUpperInvariant()});if($s.SignerInfos.Count-ne 1-or $null-eq $s.SignerInfos[0].Certificate-or $allowed-notcontains $s.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant()){exit 17}`

func verifyDetachedManifest(ctx context.Context, config fixtureConfig) error {
	return verifyDetachedFile(ctx, config, config.FixtureManifestPath, config.FixtureManifestSignaturePath)
}

func verifyDetachedFile(ctx context.Context, config fixtureConfig, contentPath, signaturePath string) error {
	if actual, err := hashFile(config.PowerShellPath); err != nil || actual != config.Binding.Artifacts.PowerShellSHA256 {
		return errors.New("manifest verifier PowerShell hash changed")
	}
	for _, signer := range config.FixtureManifestSigners {
		if len(signer) != 40 {
			return errors.New("manifest signer must be a SHA-1 thumbprint")
		}
		if _, err := hex.DecodeString(signer); err != nil {
			return errors.New("manifest signer thumbprint is invalid")
		}
	}
	_, err := winjob.Run(ctx, config.PowerShellPath, []string{"-NoProfile", "-NonInteractive", "-Command", verifyDetachedManifestScript, contentPath, signaturePath, strings.Join(config.FixtureManifestSigners, ",")}, os.Environ(), nil)
	if err != nil {
		return errors.New("detached fixture manifest signature refused")
	}
	return nil
}

func equalStringLists(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func equalPayloadBindings(left, right []fixtureproto.PayloadFileBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func lockPinnedInput(path, expected string) (io.Closer, error) {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errors.New("wrap pinned input")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		file.Close()
		return nil, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		file.Close()
		return nil, errors.New("hash mismatch")
	}
	return file, nil
}

func withinDirectory(directory, path string) bool {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(path) || filepath.Clean(directory) != directory || filepath.Clean(path) != path {
		return false
	}
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateEvidenceDirectory(path, expectedIdentity string) error {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("evidence directory is absent, not a directory, or a reparse point")
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("opened evidence directory is a reparse point or not a directory")
	}
	actual := fmt.Sprintf("volume:%08x/file:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
	if actual != expectedIdentity {
		return errors.New("identity mismatch")
	}
	return nil
}

func buildActionFacts(config fixtureConfig, request fixtureproto.Request, snapshot fixtureproto.Snapshot, state []byte) map[string]string {
	facts := map[string]string{
		"host_identity":     config.HostIdentity,
		"post_state_sha256": digestBytes(state),
	}
	if request.Action == "capture" {
		facts["snapshot_sha256"] = digestBytes(state)
	}
	if request.Action == "preflight" {
		facts["payload_sha256"] = config.Binding.PayloadSHA256
		facts["config_sha256"] = config.Binding.ConfigSHA256
		facts["sentinel_identities_verified"] = "true"
	}
	processPresent := make(map[string]bool)
	for _, process := range snapshot.Processes {
		processPresent[process.Role] = process.Present
	}
	servicePresent := false
	agentHashVerified := false
	for _, service := range snapshot.Services {
		if service.Name == agentServiceName {
			servicePresent = service.Present
			agentHashVerified = !service.Present || service.PathSHA256 == config.Binding.Artifacts.AgentSHA256
		}
	}
	firewallPresent := false
	for _, rule := range snapshot.OwnedFirewallRules {
		firewallPresent = firewallPresent || rule.Present
	}
	tunPresent := false
	for _, adapter := range snapshot.Adapters {
		tunPresent = tunPresent || adapter.InterfaceAlias == "RegenBioOverseasAccess"
	}
	for name, value := range map[string]bool{
		"service_absent":         !servicePresent,
		"service_present":        servicePresent,
		"core_absent":            !processPresent["core"],
		"core_present":           processPresent["core"],
		"ui_absent":              !processPresent["ui"],
		"ui_present":             processPresent["ui"],
		"agent_absent":           !processPresent["agent"],
		"agent_present":          processPresent["agent"],
		"fake_upstream_absent":   !processPresent["fake-upstream"],
		"fake_upstream_present":  processPresent["fake-upstream"],
		"server_service_absent":  !processPresent["server-service"],
		"server_service_present": processPresent["server-service"],
		"owned_firewall_absent":  !firewallPresent,
		"owned_firewall_present": firewallPresent,
		"tun_absent":             !tunPresent,
		"agent_hash_verified":    agentHashVerified,
	} {
		facts[name] = fmt.Sprintf("%t", value)
	}
	installedHashesVerified := len(snapshot.InstalledFiles) == len(config.Binding.PayloadFiles)
	requiredInstalled := make(map[string]bool, len(config.Binding.PayloadFiles))
	for _, expected := range config.Binding.PayloadFiles {
		requiredInstalled[strings.ToLower(expected.Path)] = false
	}
	for _, file := range snapshot.InstalledFiles {
		key := strings.ToLower(file.Path)
		verified, required := requiredInstalled[key]
		_ = verified
		if !required || !file.Present || file.SHA256 != file.ExpectedSHA256 {
			installedHashesVerified = false
			continue
		}
		requiredInstalled[key] = true
	}
	for _, verified := range requiredInstalled {
		installedHashesVerified = installedHashesVerified && verified
	}
	facts["installed_hashes_verified"] = fmt.Sprintf("%t", installedHashesVerified)
	facts["unexpected_files_absent"] = fmt.Sprintf("%t", len(snapshot.UnexpectedFiles) == 0)
	credentialProvisioned := false
	runtimeConfigVerified := false
	for _, file := range snapshot.RuntimeFiles {
		if file.Role == "config" {
			runtimeConfigVerified = file.Present && file.SHA256 == config.Binding.ConfigSHA256
		}
		if file.Role == "credential" {
			credentialProvisioned = file.Present
		}
	}
	facts["credential_provisioned"] = fmt.Sprintf("%t", credentialProvisioned)
	facts["runtime_config_verified"] = fmt.Sprintf("%t", runtimeConfigVerified)
	uiHashVerified := !processPresent["ui"]
	fakeHashVerified := !processPresent["fake-upstream"]
	for _, process := range snapshot.Processes {
		if process.Role == "ui" && process.Present {
			uiHashVerified = process.ImageSHA256 == config.Binding.Artifacts.UISHA256
		}
		if process.Role == "fake-upstream" && process.Present {
			fakeHashVerified = process.ImageSHA256 == config.Binding.Artifacts.SentinelSHA256
		}
	}
	for _, listener := range snapshot.Listeners {
		if listener.Role == "fake-upstream" && listener.Present && listener.ImageSHA256 != config.Binding.Artifacts.SentinelSHA256 {
			fakeHashVerified = false
		}
	}
	facts["ui_hash_verified"] = fmt.Sprintf("%t", uiHashVerified)
	facts["fake_listener_hash_verified"] = fmt.Sprintf("%t", fakeHashVerified)
	allMSIAbsent := true
	for _, v := range snapshot.MSIRegistrations {
		allMSIAbsent = allMSIAbsent && !v.Present
	}
	allFilesAbsent := func(values []fixtureproto.FileRecord) bool {
		for _, v := range values {
			if v.Present {
				return false
			}
		}
		return true
	}
	allStateAbsent := func(values []fixtureproto.StateRecord, productOnly bool) bool {
		for _, v := range values {
			if !v.Present {
				continue
			}
			if productOnly && !(strings.HasSuffix(v.Name, "-Fake") || strings.HasSuffix(v.Name, "-UI")) {
				continue
			}
			return false
		}
		return true
	}
	facts["msi_absent"] = fmt.Sprintf("%t", allMSIAbsent)
	facts["installed_files_absent"] = fmt.Sprintf("%t", allFilesAbsent(snapshot.InstalledFiles))
	facts["unexpected_files_absent"] = fmt.Sprintf("%t", len(snapshot.UnexpectedFiles) == 0)
	allRootsAbsent := true
	for _, root := range snapshot.OwnedRoots {
		allRootsAbsent = allRootsAbsent && !root.Present
	}
	facts["owned_roots_absent"] = fmt.Sprintf("%t", allRootsAbsent)
	facts["runtime_files_absent"] = fmt.Sprintf("%t", allFilesAbsent(snapshot.RuntimeFiles))
	facts["registry_absent"] = fmt.Sprintf("%t", allStateAbsent(snapshot.RegistryRecords, false))
	facts["ownership_absent"] = fmt.Sprintf("%t", allStateAbsent(snapshot.OwnershipArtifacts, false))
	facts["recovery_absent"] = fmt.Sprintf("%t", allStateAbsent(snapshot.RecoveryArtifacts, false))
	recoveryStaged := false
	for _, artifact := range snapshot.RecoveryArtifacts {
		if artifact.Present && strings.HasPrefix(strings.ToLower(artifact.Name), "fixture-recovery-") {
			recoveryStaged = true
		}
	}
	facts["recovery_staged"] = fmt.Sprintf("%t", recoveryStaged)
	facts["fixture_recovery_absent"] = fmt.Sprintf("%t", !recoveryStaged)
	facts["transactions_absent"] = fmt.Sprintf("%t", allStateAbsent(snapshot.TransactionArtifacts, false))
	facts["fixture_product_residue_absent"] = fmt.Sprintf("%t", allStateAbsent(snapshot.FixtureResidues, true))
	serverPresent := processPresent["server-service"] || processPresent["server-core"]
	serverListenerPresent := false
	for _, listener := range snapshot.Listeners {
		if listener.Endpoint == config.Binding.ServerListenerEndpoint && listener.Present {
			serverListenerPresent = true
		}
	}
	serverServicePresent := false
	for _, service := range snapshot.Services {
		if service.Role == "server-service" && service.Present {
			serverServicePresent = true
		}
	}
	serverConfigPresent := false
	for _, file := range snapshot.RuntimeFiles {
		if file.Role == "server-config" && file.Present && file.SHA256 == config.Binding.ServerConfigSHA256 {
			serverConfigPresent = true
		}
	}
	serverIdentityVerified := false
	if request.Action == "case-setup" || request.Action == "preflight" || request.Action == "capture" || request.Action == "agent-start" || request.Action == "machine-recover" || request.Action == "uninstall" || request.Action == "restore" {
		manifestData, err := os.ReadFile(config.FixtureManifestPath)
		if err == nil {
			if manifest, parseErr := fixtureconfig.ParseManifest(manifestData); parseErr == nil {
				serverIdentityVerified = validateRemoteServerAttestation(config, manifest) == nil
			}
		}
	}
	facts["server_identity_verified"] = fmt.Sprintf("%t", serverIdentityVerified)
	facts["server_identity_absent"] = fmt.Sprintf("%t", !serverPresent && !serverListenerPresent && !serverServicePresent && !serverConfigPresent)
	if request.Action == "restore" {
		facts["restore_input_sha256"] = request.BaselineSHA256
		facts["state_restored"] = fmt.Sprintf("%t", digestBytes(state) == request.BaselineSHA256)
	}
	return facts
}

func runConfiguredCommand(ctx context.Context, command []string, request fixtureproto.Request, actionConfigPath string) error {
	if len(command) == 0 {
		return errors.New("empty command")
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return err
	}
	environment := withoutEnvironmentKeys(os.Environ(), "OVERSEAS_FIXTURE_RUN_ID", "OVERSEAS_FIXTURE_SCENARIO", "OVERSEAS_FIXTURE_ACTION", "OVERSEAS_FIXTURE_BASELINE_PATH", "OVERSEAS_FIXTURE_BASELINE_SHA256", "OVERSEAS_ACCESS_FIXTURE_ACTION_CONFIG", "OVERSEAS_FIXTURE_REQUEST_JSON")
	environment = append(environment,
		"OVERSEAS_FIXTURE_RUN_ID="+request.RunID,
		"OVERSEAS_FIXTURE_SCENARIO="+request.Scenario,
		"OVERSEAS_FIXTURE_ACTION="+request.Action,
		"OVERSEAS_FIXTURE_BASELINE_PATH="+request.BaselinePath,
		"OVERSEAS_FIXTURE_BASELINE_SHA256="+request.BaselineSHA256,
		"OVERSEAS_ACCESS_FIXTURE_ACTION_CONFIG="+actionConfigPath,
		"OVERSEAS_FIXTURE_REQUEST_JSON="+string(requestJSON),
	)
	output, err := winjob.Run(ctx, command[0], command[1:], environment, nil)
	if err != nil {
		return fmt.Errorf("configured action failed: %w", err)
	}
	var result struct {
		ProtocolVersion int               `json:"protocol_version"`
		RequestNonce    string            `json:"request_nonce"`
		RunID           string            `json:"run_id"`
		Scenario        string            `json:"scenario"`
		Action          string            `json:"action"`
		Facts           map[string]string `json:"facts"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || requireJSONEOF(decoder) != nil {
		return errors.New("configured action returned invalid bounded evidence")
	}
	if result.ProtocolVersion != request.ProtocolVersion || result.RequestNonce != request.RequestNonce || result.RunID != request.RunID || result.Scenario != request.Scenario || result.Action != request.Action || result.Facts["verified"] != "true" {
		return errors.New("configured action evidence binding mismatch")
	}
	return nil
}

func withoutEnvironmentKeys(environment []string, names ...string) []string {
	blocked := make(map[string]struct{}, len(names))
	for _, name := range names {
		blocked[strings.ToUpper(name)] = struct{}{}
	}
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, exists := blocked[strings.ToUpper(name)]; !exists {
			result = append(result, entry)
		}
	}
	return result
}

const windowsCaptureScript = `$ErrorActionPreference='Stop'
function Hash-Text([string]$value){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Hash-File([string]$path){if([string]::IsNullOrWhiteSpace($path)-or -not(Test-Path -LiteralPath $path -PathType Leaf)){return ''};return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Service-Executable([string]$value){if($value -match '^"([^"]+)"'){return $matches[1]};return ($value -split '\s+')[0]}
$adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop|ForEach-Object{[ordered]@{interface_index=[int]$_.ifIndex;interface_guid=[string]$_.InterfaceGuid;interface_alias=[string]$_.InterfaceAlias;status=[string]$_.Status}}|Sort-Object interface_guid)
$routes=@(Get-NetRoute -ErrorAction Stop|ForEach-Object{[ordered]@{destination_prefix=[string]$_.DestinationPrefix;interface_index=[int]$_.InterfaceIndex;next_hop=[string]$_.NextHop;route_metric=[int]$_.RouteMetric}}|Sort-Object destination_prefix,interface_index,next_hop,route_metric)
$dns=@(Get-DnsClientServerAddress -ErrorAction Stop|Where-Object{@($_.ServerAddresses).Count -gt 0}|ForEach-Object{[ordered]@{interface_index=[int]$_.InterfaceIndex;interface_alias=[string]$_.InterfaceAlias;server_addresses=@($_.ServerAddresses|ForEach-Object{[string]$_}|Sort-Object)}}|Sort-Object interface_index)
$svc=Get-CimInstance Win32_Service -Filter "Name='RegenBioOverseasAccessAgent'" -ErrorAction SilentlyContinue
$servicePath=if($null-eq $svc){''}else{Service-Executable ([string]$svc.PathName)}
$services=@([ordered]@{role='agent';name='RegenBioOverseasAccessAgent';present=[bool]($null-ne $svc);status=$(if($null-eq $svc){'Absent'}else{[string]$svc.State});start_mode=$(if($null-eq $svc){'Absent'}else{[string]$svc.StartMode});path=$servicePath;path_sha256=$(Hash-File $servicePath);pid=$(if($null-eq $svc){0}else{[int]$svc.ProcessId})})
$serverSvc=Get-CimInstance Win32_Service -Filter "Name='RegenBioOverseasAccessServer'" -ErrorAction SilentlyContinue
$serverServicePath=if($null-eq $serverSvc){''}else{Service-Executable ([string]$serverSvc.PathName)}
$services+=@([ordered]@{role='server-service';name='RegenBioOverseasAccessServer';present=[bool]($null-ne $serverSvc);status=$(if($null-eq $serverSvc){'Absent'}else{[string]$serverSvc.State});start_mode=$(if($null-eq $serverSvc){'Absent'}else{[string]$serverSvc.StartMode});path=$serverServicePath;path_sha256=$(Hash-File $serverServicePath);pid=$(if($null-eq $serverSvc){0}else{[int]$serverSvc.ProcessId})})
$services+=@(Get-CimInstance Win32_Service -ErrorAction Stop|Where-Object{$_.Name -like 'RegenBioFixture-*'}|ForEach-Object{$path=Service-Executable ([string]$_.PathName);[ordered]@{role='action-helper';name=[string]$_.Name;present=$true;status=[string]$_.State;start_mode=[string]$_.StartMode;path=$path;path_sha256=$(Hash-File $path);pid=[int]$_.ProcessId}})
$processRoles=@(@('agent',$env:FIXTURE_AGENT_PATH),@('core',$env:FIXTURE_CORE_PATH),@('ui',$env:FIXTURE_UI_PATH),@('server-service','C:\Program Files\RegenBio\OverseasAccessServer\overseas-server-service.exe'),@('server-core','C:\Program Files\RegenBio\OverseasAccessServer\sing-box.exe'))
$processes=@(foreach($entry in $processRoles){$items=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue|Where-Object{[string]::Equals([string]$_.ExecutablePath,[string]$entry[1],[StringComparison]::OrdinalIgnoreCase)}|Sort-Object ProcessId);if($items.Count -eq 0){[ordered]@{role=$entry[0];present=$false;pid=0;parent_pid=0;image_path='';image_sha256=''}}elseif($items.Count -eq 1){[ordered]@{role=$entry[0];present=$true;pid=[int]$items[0].ProcessId;parent_pid=[int]$items[0].ParentProcessId;image_path=[string]$items[0].ExecutablePath;image_sha256=$(Hash-File ([string]$items[0].ExecutablePath))}}else{throw "ambiguous process role $($entry[0])"}})
$fakeItems=@(Get-CimInstance Win32_Process -Filter "Name='fixture-sentinel.exe'" -ErrorAction SilentlyContinue|Where-Object{$_.CommandLine -match '(?:^|\s)-mode(?:\s+|=)fake-upstream(?:\s|$)'}|Sort-Object ProcessId)
if($fakeItems.Count -eq 0){$processes+=@([ordered]@{role='fake-upstream';present=$false;pid=0;parent_pid=0;image_path='';image_sha256=''})}elseif($fakeItems.Count -eq 1){$processes+=@([ordered]@{role='fake-upstream';present=$true;pid=[int]$fakeItems[0].ProcessId;parent_pid=[int]$fakeItems[0].ParentProcessId;image_path=[string]$fakeItems[0].ExecutablePath;image_sha256=$(Hash-File ([string]$fakeItems[0].ExecutablePath))})}else{throw 'ambiguous process role fake-upstream'}
$names=@('RegenBioOverseasAccess.BlockPublicTCP','RegenBioOverseasAccess.BlockQUIC','RegenBioOverseasAccess.BlockPublicUDP','RegenBioOverseasAccess.BlockUnapprovedDNSUDP','RegenBioOverseasAccess.BlockUnapprovedDNSTCP','RegenBioOverseasAccess.BlockPublicEmergency','RegenBioOverseasAccess-AllowAgent-Out','RegenBioOverseasAccess-AllowCoreTCP-Out','RegenBioOverseasAccess-AllowCoreUDP-Out')
$firewall=@(foreach($name in $names){$rules=@(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue);if($rules.Count -eq 0){[ordered]@{name=$name;present=$false;definition_sha256=('0'*64)}}elseif($rules.Count -eq 1){$rule=$rules[0];$definition=[ordered]@{rule=$rule|Select-Object Name,DisplayName,Group,Direction,Action,Enabled,Profile,PolicyStoreSourceType;port=$rule|Get-NetFirewallPortFilter|Select-Object Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget;address=$rule|Get-NetFirewallAddressFilter|Select-Object LocalAddress,RemoteAddress;application=$rule|Get-NetFirewallApplicationFilter|Select-Object Program,Package;service=$rule|Get-NetFirewallServiceFilter|Select-Object Service;interface=$rule|Get-NetFirewallInterfaceFilter|Select-Object InterfaceAlias;interface_type=$rule|Get-NetFirewallInterfaceTypeFilter|Select-Object InterfaceType;security=$rule|Get-NetFirewallSecurityFilter|Select-Object Authentication,Encryption,RemoteMachine,RemoteUser,LocalUser}|ConvertTo-Json -Compress -Depth 6;[ordered]@{name=$name;present=$true;definition_sha256=$(Hash-Text $definition)}}else{throw "ambiguous firewall rule $name"}})
$uninstallRoots=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
$products=@(foreach($root in $uninstallRoots){@(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue|Where-Object{(Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).DisplayName -eq 'RegenBio Overseas Access'}|ForEach-Object{$p=Get-ItemProperty -LiteralPath $_.PSPath;[ordered]@{product_code=[string]$_.PSChildName;present=$true;version=[string]$p.DisplayVersion;package_sha256=$(Hash-Text (($p|Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation,UninstallString|ConvertTo-Json -Compress)))}})})
if($products.Count -eq 0){$products=@([ordered]@{product_code='{A4D8477C-7F2D-46E6-9B5C-65BE7E8474E1}';present=$false;version='';package_sha256=''})}
$payloadFiles=@($env:FIXTURE_PAYLOAD_FILES_JSON|ConvertFrom-Json)
$installed=@(foreach($entry in $payloadFiles){$present=Test-Path -LiteralPath ([string]$entry.path) -PathType Leaf;[ordered]@{role='payload';name=[string]$entry.name;path=[string]$entry.path;present=$present;sha256=$(if($present){Hash-File ([string]$entry.path)}else{''});expected_sha256=[string]$entry.sha256}})
$allowed=@{};foreach($entry in $payloadFiles){$allowed[[string]$entry.path]=$true};foreach($path in @('C:\Program Files\RegenBio\OverseasAccess\.regenbio-overseas-access.owner.json','C:\ProgramData\RegenBio\OverseasAccess\.regenbio-overseas-access.owner.json','C:\ProgramData\RegenBio\OverseasAccess\credential.bin','C:\ProgramData\RegenBio\OverseasAccess\sing-box.json','C:\ProgramData\RegenBio\OverseasAccess\runtime-owned.json','C:\ProgramData\RegenBio\OverseasAccess\network-state.json')){$allowed[$path]=$true}
$unexpected=@(foreach($root in @('C:\Program Files\RegenBio\OverseasAccess','C:\ProgramData\RegenBio\OverseasAccess')){@(Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction SilentlyContinue|Where-Object{-not $allowed.ContainsKey([string]$_.FullName)}|ForEach-Object{[ordered]@{role='unexpected';name=[string]$_.Name;path=[string]$_.FullName;present=$true;sha256=$(Hash-File $_.FullName)}})})
$ownedRoots=@(foreach($root in @('C:\Program Files\RegenBio\OverseasAccess','C:\ProgramData\RegenBio\OverseasAccess')){[ordered]@{path=$root;present=(Test-Path -LiteralPath $root -PathType Container)}})
$runtime=@(foreach($entry in @(@('credential','C:\ProgramData\RegenBio\OverseasAccess\credential.bin',''),@('config','C:\ProgramData\RegenBio\OverseasAccess\sing-box.json',$env:FIXTURE_CLIENT_CONFIG_SHA256),@('runtime-ledger','C:\ProgramData\RegenBio\OverseasAccess\runtime-owned.json',''),@('network-state','C:\ProgramData\RegenBio\OverseasAccess\network-state.json',''),@('server-config','C:\ProgramData\RegenBio\OverseasAccessServer\config.json',$env:FIXTURE_SERVER_CONFIG_SHA256))){$present=Test-Path -LiteralPath $entry[1] -PathType Leaf;[ordered]@{role=$entry[0];path=$entry[1];present=$present;sha256=$(if($present){Hash-File $entry[1]}else{''});expected_sha256=$entry[2]}})
function State-Path([string]$kind,[string]$name,[string]$path){$present=Test-Path -LiteralPath $path;[ordered]@{kind=$kind;name=$name;present=$present;definition_sha256=$(if($present){if(Test-Path -LiteralPath $path -PathType Leaf){Hash-File $path}else{Hash-Text ((Get-ChildItem -LiteralPath $path -Force -Recurse|Select-Object FullName,Length,LastWriteTimeUtc|ConvertTo-Json -Compress))}}else{''})}}
$registry=@(State-Path 'registry' 'client-owner-registry' 'HKLM:\Software\RegenBio\OverseasAccess')
$ownership=@((State-Path 'ownership' 'install-owner' 'C:\Program Files\RegenBio\OverseasAccess\.regenbio-overseas-access.owner.json'),(State-Path 'ownership' 'data-owner' 'C:\ProgramData\RegenBio\OverseasAccess\.regenbio-overseas-access.owner.json'),(State-Path 'ownership' 'runtime-ledger' 'C:\ProgramData\RegenBio\OverseasAccess\runtime-owned.json'))
$scheduled=@(Get-ScheduledTask -ErrorAction SilentlyContinue|Where-Object{$_.TaskName -like 'RegenBio*'}|ForEach-Object{[ordered]@{kind='recovery';name=[string]$_.TaskName;present=$true;definition_sha256=$(Hash-Text (($_|Select-Object TaskName,TaskPath,State|ConvertTo-Json -Compress)))}})
$scheduled+=@(Get-ChildItem -LiteralPath 'C:\ProgramData\RegenBio\OverseasAccess' -Filter 'fixture-recovery-*.json' -File -ErrorAction SilentlyContinue|ForEach-Object{[ordered]@{kind='recovery';name=[string]$_.Name;present=$true;definition_sha256=$(Hash-File $_.FullName)}})
if($scheduled.Count -eq 0){$scheduled=@([ordered]@{kind='recovery';name='RegenBioRecovery';present=$false;definition_sha256=''})}
$transactions=@((State-Path 'transaction' 'installer-transactions' 'C:\ProgramData\RegenBio\InstallerTransactions'))
$fixtureServices=@(Get-CimInstance Win32_Service -ErrorAction Stop|Where-Object{$_.Name -like 'RegenBioFixture-*'}|ForEach-Object{[ordered]@{kind='fixture-residue';name=[string]$_.Name;present=$true;definition_sha256=$(Hash-Text (($_|Select-Object Name,State,StartMode,PathName|ConvertTo-Json -Compress)))}})
if($fixtureServices.Count -eq 0){$fixtureServices=@([ordered]@{kind='fixture-residue';name='RegenBioFixture';present=$false;definition_sha256=''})}
$listeners=@(foreach($entry in @(@('fake-upstream',$env:FIXTURE_FAKE_DATA_ENDPOINT),@('fake-upstream',$env:FIXTURE_FAKE_CONTROL_ENDPOINT),@('sentinel',$env:FIXTURE_PUBLIC_ENDPOINT),@('sentinel',$env:FIXTURE_PUBLIC_HEALTH_ENDPOINT),@('sentinel',$env:FIXTURE_CORPORATE_ENDPOINT),@('server-core',$env:FIXTURE_SERVER_LISTENER_ENDPOINT))){$parts=$entry[1].Split(':');$connections=@(Get-NetTCPConnection -State Listen -LocalAddress $parts[0] -LocalPort ([int]$parts[1]) -ErrorAction SilentlyContinue);if($connections.Count -gt 1){throw "ambiguous listener $($entry[1])"};if($connections.Count -eq 0){[ordered]@{role=$entry[0];endpoint=$entry[1];present=$false;pid=0;image_path='';image_sha256=''}}else{$owner=Get-Process -Id $connections[0].OwningProcess -ErrorAction Stop;[ordered]@{role=$entry[0];endpoint=$entry[1];present=$true;pid=[int]$owner.Id;image_path=[string]$owner.Path;image_sha256=$(Hash-File ([string]$owner.Path))}}})
[ordered]@{observation_nonce=$env:FIXTURE_OBSERVATION_NONCE;adapters=$adapters;routes=$routes;dns=$dns;services=$services;processes=$processes;owned_firewall_rules=$firewall;msi_registrations=$products;installed_files=$installed;unexpected_files=$unexpected;owned_roots=$ownedRoots;runtime_files=$runtime;registry_records=$registry;ownership_artifacts=$ownership;recovery_artifacts=$scheduled;transaction_artifacts=$transactions;fixture_residues=$fixtureServices;listeners=$listeners}|ConvertTo-Json -Compress -Depth 8`

func captureWindows(ctx context.Context, nonce string, config fixtureConfig) (fixtureproto.Snapshot, error) {
	root := filepath.Clean(os.Getenv("SystemRoot"))
	expectedPowerShell := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if root == "." || !strings.EqualFold(filepath.Clean(config.PowerShellPath), expectedPowerShell) {
		return fixtureproto.Snapshot{}, errors.New("capture PowerShell is not the exact System32 executable")
	}
	if actual, err := hashFile(config.PowerShellPath); err != nil || actual != config.Binding.Artifacts.PowerShellSHA256 {
		return fixtureproto.Snapshot{}, errors.New("capture PowerShell hash changed")
	}
	if digestBytes([]byte(windowsCaptureScript)) != config.Binding.Artifacts.CaptureScriptSHA256 {
		return fixtureproto.Snapshot{}, errors.New("embedded capture script hash changed")
	}
	manifestData, err := os.ReadFile(config.FixtureManifestPath)
	if err != nil {
		return fixtureproto.Snapshot{}, fmt.Errorf("read locked fixture manifest for capture: %w", err)
	}
	manifest, err := fixtureconfig.ParseManifest(manifestData)
	if err != nil {
		return fixtureproto.Snapshot{}, fmt.Errorf("parse locked fixture manifest for capture: %w", err)
	}
	payloadJSON, err := json.Marshal(config.Binding.PayloadFiles)
	if err != nil {
		return fixtureproto.Snapshot{}, err
	}
	environment := withoutEnvironmentKeys(os.Environ(), "FIXTURE_OBSERVATION_NONCE", "FIXTURE_FAKE_DATA_ENDPOINT", "FIXTURE_FAKE_CONTROL_ENDPOINT", "FIXTURE_PUBLIC_ENDPOINT", "FIXTURE_PUBLIC_HEALTH_ENDPOINT", "FIXTURE_CORPORATE_ENDPOINT", "FIXTURE_AGENT_PATH", "FIXTURE_CORE_PATH", "FIXTURE_UI_PATH", "FIXTURE_SERVER_SERVICE_PATH", "FIXTURE_PAYLOAD_FILES_JSON", "FIXTURE_CLIENT_CONFIG_SHA256", "FIXTURE_SERVER_CONFIG_SHA256", "FIXTURE_SERVER_LISTENER_ENDPOINT")
	environment = append(environment, "FIXTURE_OBSERVATION_NONCE="+nonce, "FIXTURE_FAKE_DATA_ENDPOINT="+config.FakeUpstreamData, "FIXTURE_FAKE_CONTROL_ENDPOINT="+config.FakeUpstreamControl, "FIXTURE_PUBLIC_ENDPOINT="+config.PublicSentinel, "FIXTURE_PUBLIC_HEALTH_ENDPOINT="+config.PublicSentinelHealth, "FIXTURE_CORPORATE_ENDPOINT="+config.CorporateSentinel,
		"FIXTURE_AGENT_PATH="+manifest.Artifacts["agent"].InstalledPath, "FIXTURE_CORE_PATH="+manifest.Artifacts["core"].InstalledPath, "FIXTURE_UI_PATH="+manifest.Artifacts["ui"].InstalledPath, "FIXTURE_SERVER_SERVICE_PATH="+manifest.Artifacts["server-service"].InstalledPath,
		"FIXTURE_PAYLOAD_FILES_JSON="+string(payloadJSON), "FIXTURE_CLIENT_CONFIG_SHA256="+config.Binding.ConfigSHA256, "FIXTURE_SERVER_CONFIG_SHA256="+config.Binding.ServerConfigSHA256, "FIXTURE_SERVER_LISTENER_ENDPOINT="+config.Binding.ServerListenerEndpoint)
	output, err := winjob.Run(ctx, config.PowerShellPath, []string{"-NoProfile", "-NonInteractive", "-Command", windowsCaptureScript}, environment, nil)
	if err != nil {
		return fixtureproto.Snapshot{}, fmt.Errorf("capture Windows state: %w", err)
	}
	var snapshot fixtureproto.Snapshot
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return fixtureproto.Snapshot{}, err
	}
	return snapshot, requireJSONEOF(decoder)
}

func probeFixtureIdentity(ctx context.Context, endpoint, identity string, requireVia bool) error {
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	dialer := net.Dialer{Timeout: probeTimeout}
	connection, err := dialer.DialContext(ctx, "tcp4", endpoint)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(probeTimeout))
	if err := json.NewEncoder(connection).Encode(map[string]string{"nonce": nonce}); err != nil {
		return err
	}
	var response struct {
		Nonce           string `json:"nonce"`
		Identity        string `json:"identity"`
		ViaFakeUpstream string `json:"via_fake_upstream,omitempty"`
	}
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(connection, 4097)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return err
	}
	if response.Nonce != nonce || response.Identity != identity {
		return errors.New("sentinel receipt mismatch")
	}
	if requireVia && response.ViaFakeUpstream != identity {
		return errors.New("fake-upstream traversal receipt mismatch")
	}
	if !requireVia && response.ViaFakeUpstream != "" {
		return errors.New("sentinel health receipt unexpectedly traversed an upstream")
	}
	return nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func isSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}
