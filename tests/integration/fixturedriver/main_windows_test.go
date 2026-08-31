//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	"corp.example/overseas-access-gateway/tests/integration/fixtureproto"
)

func TestFixtureConfigRequiresSingleReviewedActionHelper(t *testing.T) {
	config := validFixtureConfig()
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	config.ActionHelperPath = ""
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "action helper") {
		t.Fatalf("Validate() = %v, want missing action helper", err)
	}
	config = validFixtureConfig()
	delete(config.ArtifactSigners, "action-helper")
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "action-helper") {
		t.Fatalf("Validate() = %v, want missing action-helper signer", err)
	}
	config = validFixtureConfig()
	config.CredentialSourcePath = ""
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "credential source path") {
		t.Fatalf("Validate() = %v, want missing credential source path", err)
	}
	config = validFixtureConfig()
	config.ServerAttestationSHA256 = "bad"
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "server attestation hash") {
		t.Fatalf("Validate() = %v, want bad attestation hash", err)
	}
}

func TestCaptureScriptDistinguishesFakeUpstreamFromSentinelProcesses(t *testing.T) {
	if !strings.Contains(windowsCaptureScript, "CommandLine") || !strings.Contains(windowsCaptureScript, "-mode") || !strings.Contains(windowsCaptureScript, "fake-upstream") {
		t.Fatal("capture script identifies fake upstream only by shared fixture-sentinel process name")
	}
}

func TestCaptureScriptParsesWithoutExecution(t *testing.T) {
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$null=[ScriptBlock]::Create([Console]::In.ReadToEnd())")
	command.Stdin = bytes.NewBufferString(windowsCaptureScript)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("capture script parse failed: %v: %s", err, output)
	}
}

func TestExecuteRequestRejectsRunDirectoryIdentityMismatchBeforeCommand(t *testing.T) {
	config := validFixtureConfig()
	request := fixtureproto.Request{ProtocolVersion: fixtureproto.ProtocolVersion, RequestNonce: "nonce-1", RunID: "run-1", Action: "case-setup", Scenario: "core-exits", EvidenceDirectory: `C:\evidence\run`, EvidenceDirectoryIdentity: "replaced", BaselinePath: `C:\evidence\run\trusted.json`, BaselineSHA256: strings.Repeat("1", 64)}
	called := false
	_, err := executeRequest(context.Background(), config, request, dependencies{
		runCommand: func(context.Context, []string, fixtureproto.Request, string) error { called = true; return nil },
		capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
			return absentSnapshot(request.RequestNonce), nil
		},
		probeIdentity: func(context.Context, string, string, bool) error { return nil },
		validateEvidence: func(_, identity string) error {
			if identity != "vol:1/file:2" {
				return errors.New("mismatch")
			}
			return nil
		},
		lockInput: testInputLocker,
	})
	if err == nil || !strings.Contains(err.Error(), "directory") || called {
		t.Fatalf("executeRequest() = %v, command called=%t; want pre-action identity refusal", err, called)
	}
}

func TestRestoreRehashesTrustedInputBeforeCommand(t *testing.T) {
	config := validFixtureConfig()
	request := fixtureproto.Request{ProtocolVersion: fixtureproto.ProtocolVersion, RequestNonce: "nonce-1", RunID: "run-1", Action: "restore", Scenario: "core-exits", EvidenceDirectory: `C:\evidence\run`, EvidenceDirectoryIdentity: "vol:1/file:2", BaselinePath: `C:\evidence\run\trusted.json`, BaselineSHA256: strings.Repeat("1", 64)}
	called := false
	_, err := executeRequest(context.Background(), config, request, dependencies{
		runCommand: func(context.Context, []string, fixtureproto.Request, string) error { called = true; return nil },
		capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
			snapshot := absentSnapshot(request.RequestNonce)
			snapshot.Listeners = []fixtureproto.ListenerRecord{
				{Role: "sentinel", Endpoint: config.PublicSentinel, Present: true, PID: 11, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
				{Role: "sentinel", Endpoint: config.PublicSentinelHealth, Present: true, PID: 11, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
				{Role: "sentinel", Endpoint: config.CorporateSentinel, Present: true, PID: 12, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
				{Role: "fake-upstream", Endpoint: config.FakeUpstreamControl, Present: true, PID: 13, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
				{Role: "fake-upstream", Endpoint: config.FakeUpstreamData, Present: true, PID: 13, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
			}
			return snapshot, nil
		},
		probeIdentity:    func(context.Context, string, string, bool) error { return nil },
		validateEvidence: func(string, string) error { return nil },
		lockInput:        testInputLocker,
		hashFile: func(path string) (string, error) {
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
				return "", errors.New("tampered")
			default:
				return "", errors.New("unexpected")
			}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "restore input") || called {
		t.Fatalf("executeRequest() = %v, command called=%t; want tampered restore refusal", err, called)
	}
}

func TestRestoreRefusesSuccessWhenPostStateDoesNotEqualTrustedBaseline(t *testing.T) {
	config := validFixtureConfig()
	request := fixtureproto.Request{ProtocolVersion: fixtureproto.ProtocolVersion, RequestNonce: "nonce-1", RunID: "run-1", Action: "restore", Scenario: "core-exits", EvidenceDirectory: `C:\evidence\run`, EvidenceDirectoryIdentity: "vol:1/file:2", BaselinePath: `C:\evidence\run\trusted.json`, BaselineSHA256: strings.Repeat("1", 64)}
	_, err := executeRequest(context.Background(), config, request, dependencies{
		runCommand: func(context.Context, []string, fixtureproto.Request, string) error { return nil },
		capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
			return absentSnapshot(request.RequestNonce), nil
		},
		probeIdentity:    func(context.Context, string, string, bool) error { return nil },
		validateEvidence: func(string, string) error { return nil },
		lockInput:        testInputLocker,
		verifyCommand:    func(string, []string) (io.Closer, error) { return io.NopCloser(bytes.NewReader(nil)), nil },
	})
	if err == nil || !strings.Contains(err.Error(), "post-state") {
		t.Fatalf("executeRequest() = %v, want immediate restore post-state refusal", err)
	}
}

func TestExecuteRequestBindsResponseAndCapturesActionSpecificPostState(t *testing.T) {
	config := validFixtureConfig()
	request := fixtureproto.Request{
		ProtocolVersion:           fixtureproto.ProtocolVersion,
		RequestNonce:              "nonce-1",
		RunID:                     "run-1",
		Action:                    "uninstall",
		Scenario:                  "uninstall-cleanup",
		EvidenceDirectory:         `C:\evidence\run`,
		EvidenceDirectoryIdentity: "vol:1/file:2",
		BaselinePath:              `C:\evidence\run\trusted.json`,
		BaselineSHA256:            strings.Repeat("1", 64),
	}
	commandCalls := 0
	response, err := executeRequest(context.Background(), config, request, dependencies{
		runCommand: func(context.Context, []string, fixtureproto.Request, string) error { commandCalls++; return nil },
		capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
			return absentSnapshot(request.RequestNonce), nil
		},
		probeIdentity:    func(context.Context, string, string, bool) error { return nil },
		validateEvidence: func(string, string) error { return nil },
		lockInput:        testInputLocker,
		verifyCommand:    func(string, []string) (io.Closer, error) { return io.NopCloser(bytes.NewReader(nil)), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if commandCalls != 1 {
		t.Fatalf("command calls = %d, want 1", commandCalls)
	}
	if err := fixtureproto.ValidateResponse(request, config.Binding, response); err != nil {
		t.Fatalf("ValidateResponse() = %v", err)
	}
	for _, fact := range []string{"service_absent", "core_absent", "ui_absent", "owned_firewall_absent", "post_state_sha256"} {
		if response.Evidence.Facts[fact] != "true" && fact != "post_state_sha256" {
			t.Errorf("uninstall fact %s = %q", fact, response.Evidence.Facts[fact])
		}
		if fact == "post_state_sha256" && response.Evidence.Facts[fact] == "" {
			t.Error("post-state hash is absent")
		}
	}
}

func TestExecuteRequestRefusesChangedCommandBeforeMutation(t *testing.T) {
	config := validFixtureConfig()
	request := fixtureproto.Request{ProtocolVersion: fixtureproto.ProtocolVersion, RequestNonce: "nonce-1", RunID: "run-1", Action: "uninstall", Scenario: "uninstall-cleanup", EvidenceDirectory: `C:\evidence\run`, EvidenceDirectoryIdentity: "vol:1/file:2", BaselinePath: `C:\evidence\run\trusted.json`, BaselineSHA256: strings.Repeat("1", 64)}
	called := false
	_, err := executeRequest(context.Background(), config, request, dependencies{
		runCommand: func(context.Context, []string, fixtureproto.Request, string) error { called = true; return nil },
		capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
			return absentSnapshot(request.RequestNonce), nil
		},
		probeIdentity:    func(context.Context, string, string, bool) error { return nil },
		validateEvidence: func(string, string) error { return nil },
		lockInput:        testInputLocker,
		verifyCommand:    func(string, []string) (io.Closer, error) { return nil, errors.New("command changed") },
	})
	if err == nil || !strings.Contains(err.Error(), "command changed") || called {
		t.Fatalf("executeRequest() = %v, called=%t; want stale command refusal", err, called)
	}
}

func TestExecuteRequestRefusesManifestOrConfigIsolationFailureBeforeMutation(t *testing.T) {
	request := fixtureproto.Request{ProtocolVersion: fixtureproto.ProtocolVersion, RequestNonce: "nonce-1", RunID: "run-1", Action: "uninstall", Scenario: "uninstall-cleanup", EvidenceDirectory: `C:\evidence\run`, EvidenceDirectoryIdentity: "vol:1/file:2", BaselinePath: `C:\evidence\run\trusted.json`, BaselineSHA256: strings.Repeat("1", 64)}
	for _, test := range []struct {
		name      string
		fixture   func(context.Context, fixtureConfig) (io.Closer, error)
		generated func(fixtureConfig) error
		want      string
	}{
		{name: "manifest", fixture: func(context.Context, fixtureConfig) (io.Closer, error) { return nil, errors.New("manifest changed") }, want: "manifest changed"},
		{name: "generated configs", fixture: func(context.Context, fixtureConfig) (io.Closer, error) {
			return io.NopCloser(bytes.NewReader(nil)), nil
		}, generated: func(fixtureConfig) error { return errors.New("prohibited telecom upstream") }, want: "telecom"},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			_, err := executeRequest(context.Background(), validFixtureConfig(), request, dependencies{
				runCommand: func(context.Context, []string, fixtureproto.Request, string) error { called = true; return nil }, capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
					return absentSnapshot(request.RequestNonce), nil
				}, probeIdentity: func(context.Context, string, string, bool) error { return nil }, validateEvidence: func(string, string) error { return nil }, lockInput: testInputLocker, validateFixture: test.fixture, validateGenerated: test.generated,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) || called {
				t.Fatalf("executeRequest()=%v called=%t, want pre-mutation %s refusal", err, called, test.want)
			}
		})
	}
}

func TestPreflightChecksSentinelsAndRequiresFakeServiceEndpointsFree(t *testing.T) {
	config := validFixtureConfig()
	request := fixtureproto.Request{ProtocolVersion: fixtureproto.ProtocolVersion, RequestNonce: "nonce-1", RunID: "run-1", Action: "preflight", EvidenceDirectory: `C:\evidence\run`, EvidenceDirectoryIdentity: "vol:1/file:2"}
	probes := make(map[string]bool)
	_, err := executeRequest(context.Background(), config, request, dependencies{
		runCommand: func(context.Context, []string, fixtureproto.Request, string) error { return nil },
		capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
			snapshot := absentSnapshot(request.RequestNonce)
			snapshot.Listeners = []fixtureproto.ListenerRecord{
				{Role: "sentinel", Endpoint: config.PublicSentinel, Present: true, PID: 11, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
				{Role: "sentinel", Endpoint: config.PublicSentinelHealth, Present: true, PID: 11, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
				{Role: "sentinel", Endpoint: config.CorporateSentinel, Present: true, PID: 12, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
				{Role: "fake-upstream", Endpoint: config.FakeUpstreamControl, Present: false},
				{Role: "fake-upstream", Endpoint: config.FakeUpstreamData, Present: false},
			}
			return snapshot, nil
		},
		probeIdentity: func(_ context.Context, endpoint, identity string, requireVia bool) error {
			probes[endpoint+"|"+identity] = requireVia
			return nil
		},
		validateEvidence: func(string, string) error { return nil },
		lockInput:        testInputLocker,
	})
	if err != nil {
		t.Fatal(err)
	}
	if probes[config.PublicSentinel+"|"+config.Binding.PublicSentinelIdentity] || probes[config.PublicSentinelHealth+"|"+config.Binding.PublicSentinelIdentity] || probes[config.CorporateSentinel+"|"+config.Binding.CorporateSentinelIdentity] {
		t.Fatalf("sentinel preflight unexpectedly required tunnel receipt: %v", probes)
	}
	if len(probes) != 3 {
		t.Fatalf("preflight probes = %v, want public data, public health, and corporate", probes)
	}
	if _, exists := probes[config.FakeUpstreamControl+"|"+config.Binding.FakeUpstreamIdentity]; exists {
		t.Fatalf("preflight unexpectedly required a fake service before its run-owned start action: %v", probes)
	}
}

func TestFakeListenerOwnershipRequiresOnePIDAndRunOwnedSupervisor(t *testing.T) {
	config := validFixtureConfig()
	snapshot := absentSnapshot("nonce-1")
	snapshot.Listeners = []fixtureproto.ListenerRecord{
		{Role: "fake-upstream", Endpoint: config.FakeUpstreamControl, Present: true, PID: 41, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
		{Role: "fake-upstream", Endpoint: config.FakeUpstreamData, Present: true, PID: 42, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256},
	}
	if err := validateActionListeners("fake-upstream-start", "run-1", snapshot, config.Binding); err == nil || !strings.Contains(err.Error(), "same process") {
		t.Fatalf("validateActionListeners() = %v, want split-listener refusal", err)
	}
	snapshot.Listeners[1].PID = 41
	for index := range snapshot.Processes {
		if snapshot.Processes[index].Role == "fake-upstream" {
			snapshot.Processes[index] = fixtureproto.ProcessRecord{Role: "fake-upstream", Present: true, PID: 41, ParentPID: 40, ImagePath: `C:\fixture\sentinel.exe`, ImageSHA256: config.Binding.Artifacts.SentinelSHA256}
		}
	}
	if err := validateActionListeners("fake-upstream-start", "run-1", snapshot, config.Binding); err == nil || !strings.Contains(err.Error(), "supervisor") {
		t.Fatalf("validateActionListeners() = %v, want missing run-owned supervisor refusal", err)
	}
}

func validFixtureConfig() fixtureConfig {
	return fixtureConfig{
		SchemaVersion:                1,
		HostIdentity:                 "host-1",
		EvidenceRoot:                 `C:\evidence`,
		PayloadPath:                  `C:\fixture\payload.msi`,
		CredentialSourcePath:         `C:\fixture\credential-source.exe`,
		CredentialSourceSHA256:       strings.Repeat("1", 64),
		GeneratedConfigPath:          `C:\fixture\agent.yaml`,
		ServerConfigPath:             `C:\fixture\server.json`,
		ServerAttestationPath:        `C:\fixture\server-attestation.json`,
		ServerAttestationSHA256:      strings.Repeat("4", 64),
		ServerHostKeyFingerprint:     "SHA256:vm101",
		ActionConfigPath:             `C:\fixture\action.json`,
		FixtureManifestPath:          `C:\fixture\fixture-manifest.json`,
		FixtureManifestSignaturePath: `C:\fixture\fixture-manifest.json.p7s`,
		FixtureManifestSigners:       []string{"0123456789abcdef0123456789abcdef01234567"},
		ArtifactSigners:              map[string][]string{"agent": {"CN=Fixture"}, "core": {"CN=Fixture"}, "ui": {"CN=Fixture"}, "server-service": {"CN=Fixture"}, "driver": {"CN=Fixture"}, "sentinel": {"CN=Fixture"}, "action-helper": {"CN=Fixture"}},
		PowerShellPath:               `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ActionHelperPath:             `C:\fixture\action.exe`,
		Binding: fixtureproto.FixtureBinding{
			PayloadSHA256:             strings.Repeat("2", 64),
			ConfigSHA256:              strings.Repeat("3", 64),
			ServerConfigSHA256:        strings.Repeat("5", 64),
			ActionConfigSHA256:        strings.Repeat("6", 64),
			FakeUpstreamIdentity:      "fake-upstream/1",
			PublicSentinelIdentity:    "public/1",
			CorporateSentinelIdentity: "corporate/1",
			PublicSentinelEndpoint:    "198.18.0.2:18080", PublicSentinelHealthEndpoint: "172.20.9.251:18080", CorporateSentinelEndpoint: "172.20.9.250:18081", FakeUpstreamControlEndpoint: "172.20.9.15:18082", FakeUpstreamDataEndpoint: "172.20.9.15:18083",
			ServerListenerEndpoint: "172.20.9.15:18443", Network: fixtureproto.NetworkBinding{CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"}, InternalSuffixes: []string{"intra.regen-bio.com"}}, PayloadFiles: []fixtureproto.PayloadFileBinding{{Name: "overseas-agent.exe", Path: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, SHA256: strings.Repeat("6", 64)}},
			Artifacts: fixtureproto.ArtifactBinding{ManifestSHA256: strings.Repeat("5", 64), AgentSHA256: strings.Repeat("6", 64), CoreSHA256: strings.Repeat("7", 64), UISHA256: strings.Repeat("8", 64), ServerServiceSHA256: strings.Repeat("9", 64), DriverSHA256: strings.Repeat("a", 64), SentinelSHA256: strings.Repeat("b", 64), ActionHelperSHA256: strings.Repeat("c", 64), PowerShellSHA256: strings.Repeat("d", 64), InstallerSHA256: strings.Repeat("e", 64), CaptureScriptSHA256: strings.Repeat("f", 64)},
		},
		PublicSentinel:       "198.18.0.2:18080",
		PublicSentinelHealth: "172.20.9.251:18080",
		CorporateSentinel:    "172.20.9.250:18081",
		FakeUpstreamControl:  "172.20.9.15:18082",
		FakeUpstreamData:     "172.20.9.15:18083",
	}
}

func testInputLocker(string, string) (io.Closer, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func absentSnapshot(nonce string) fixtureproto.Snapshot {
	return fixtureproto.Snapshot{
		ObservationNonce:     nonce,
		Adapters:             []fixtureproto.AdapterRecord{{InterfaceIndex: 7, InterfaceGUID: "{guid}", InterfaceAlias: "Ethernet", Status: "Up"}},
		Routes:               []fixtureproto.RouteRecord{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7, NextHop: "192.0.2.1", RouteMetric: 10}},
		DNS:                  []fixtureproto.DNSRecord{{InterfaceIndex: 7, InterfaceAlias: "Ethernet", ServerAddresses: []string{"192.0.2.53"}}},
		Services:             []fixtureproto.ServiceRecord{{Name: agentServiceName, Present: false, Status: "Absent", StartMode: "Absent"}},
		Processes:            []fixtureproto.ProcessRecord{{Role: "agent", Present: false}, {Role: "core", Present: false}, {Role: "ui", Present: false}, {Role: "fake-upstream", Present: false}},
		OwnedFirewallRules:   []fixtureproto.FirewallRecord{{Name: runtimeFirewallGroup, Present: false, DefinitionSHA256: strings.Repeat("0", 64)}},
		MSIRegistrations:     []fixtureproto.MSIRecord{{ProductCode: "{D1234567-89AB-4CDE-8012-3456789ABCDE}", Present: false}},
		InstalledFiles:       []fixtureproto.FileRecord{{Role: "payload", Name: "overseas-agent.exe", Path: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, ExpectedSHA256: strings.Repeat("6", 64), Present: false}},
		UnexpectedFiles:      []fixtureproto.FileRecord{},
		OwnedRoots:           []fixtureproto.RootRecord{{Path: `C:\Program Files\RegenBio\OverseasAccess`, Present: false}, {Path: `C:\ProgramData\RegenBio\OverseasAccess`, Present: false}},
		RuntimeFiles:         []fixtureproto.FileRecord{{Role: "credential", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`, Present: false}},
		RegistryRecords:      []fixtureproto.StateRecord{{Kind: "registry", Name: "product", Present: false}},
		OwnershipArtifacts:   []fixtureproto.StateRecord{{Kind: "ownership", Name: "ledger", Present: false}},
		RecoveryArtifacts:    []fixtureproto.StateRecord{{Kind: "recovery", Name: "machine", Present: false}},
		TransactionArtifacts: []fixtureproto.StateRecord{{Kind: "transaction", Name: "journal", Present: false}},
		FixtureResidues:      []fixtureproto.StateRecord{{Kind: "fixture-residue", Name: "service", Present: false}},
		Listeners:            []fixtureproto.ListenerRecord{{Role: "fake-upstream", Endpoint: "172.20.9.15:18083", Present: false}},
	}
}
