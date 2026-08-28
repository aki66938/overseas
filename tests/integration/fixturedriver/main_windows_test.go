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

func TestFixtureConfigRequiresConcreteCommandForEveryMutatingAction(t *testing.T) {
	config := validFixtureConfig()
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	delete(config.Commands, "restore")
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("Validate() = %v, want missing restore command", err)
	}
	config = validFixtureConfig()
	delete(config.CommandSHA256, "restore")
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("Validate() = %v, want missing restore command hash", err)
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
		runCommand: func(context.Context, []string, fixtureproto.Request) error { called = true; return nil },
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
		runCommand: func(context.Context, []string, fixtureproto.Request) error { called = true; return nil },
		capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
			return absentSnapshot(request.RequestNonce), nil
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
		runCommand: func(context.Context, []string, fixtureproto.Request) error { return nil },
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
		runCommand: func(context.Context, []string, fixtureproto.Request) error { commandCalls++; return nil },
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
		runCommand: func(context.Context, []string, fixtureproto.Request) error { called = true; return nil },
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

func TestPreflightIndependentlyChecksSentinelAndFakeUpstreamIdentities(t *testing.T) {
	config := validFixtureConfig()
	request := fixtureproto.Request{ProtocolVersion: fixtureproto.ProtocolVersion, RequestNonce: "nonce-1", RunID: "run-1", Action: "preflight", EvidenceDirectory: `C:\evidence\run`, EvidenceDirectoryIdentity: "vol:1/file:2"}
	probes := make(map[string]bool)
	_, err := executeRequest(context.Background(), config, request, dependencies{
		runCommand: func(context.Context, []string, fixtureproto.Request) error { return nil },
		capture: func(context.Context, string) (fixtureproto.Snapshot, error) {
			return absentSnapshot(request.RequestNonce), nil
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
	if len(probes) != 4 {
		t.Fatalf("preflight probes = %v, want public data, public health, corporate, and fake upstream", probes)
	}
	if value, exists := probes[config.FakeUpstreamControl+"|"+config.Binding.FakeUpstreamIdentity]; !exists || !value {
		t.Fatalf("fake upstream identity was not independently verified: %v", probes)
	}
}

func validFixtureConfig() fixtureConfig {
	commands := make(map[string][]string)
	commandHashes := make(map[string]string)
	commandSigners := make(map[string][]string)
	for _, action := range mutatingActions {
		commands[action] = []string{`C:\fixture\action.exe`, action}
		commandHashes[action] = strings.Repeat("4", 64)
		commandSigners[action] = []string{"CN=Fixture Actions"}
	}
	return fixtureConfig{
		SchemaVersion:       1,
		HostIdentity:        "host-1",
		EvidenceRoot:        `C:\evidence`,
		PayloadPath:         `C:\fixture\payload.msi`,
		GeneratedConfigPath: `C:\fixture\agent.yaml`,
		Binding: fixtureproto.FixtureBinding{
			PayloadSHA256:             strings.Repeat("2", 64),
			ConfigSHA256:              strings.Repeat("3", 64),
			FakeUpstreamIdentity:      "fake-upstream/1",
			PublicSentinelIdentity:    "public/1",
			CorporateSentinelIdentity: "corporate/1",
			PublicSentinelEndpoint:    "198.18.0.2:18080", PublicSentinelHealthEndpoint: "172.20.9.251:18080", CorporateSentinelEndpoint: "172.20.9.250:18081", FakeUpstreamControlEndpoint: "172.20.9.15:18082",
		},
		PublicSentinel:       "198.18.0.2:18080",
		PublicSentinelHealth: "172.20.9.251:18080",
		CorporateSentinel:    "172.20.9.250:18081",
		FakeUpstreamControl:  "172.20.9.15:18082",
		Commands:             commands,
		CommandSHA256:        commandHashes,
		CommandSigners:       commandSigners,
	}
}

func testInputLocker(string, string) (io.Closer, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func absentSnapshot(nonce string) fixtureproto.Snapshot {
	return fixtureproto.Snapshot{
		ObservationNonce:   nonce,
		Adapters:           []fixtureproto.AdapterRecord{{InterfaceIndex: 7, InterfaceGUID: "{guid}", InterfaceAlias: "Ethernet", Status: "Up"}},
		Routes:             []fixtureproto.RouteRecord{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7, NextHop: "192.0.2.1", RouteMetric: 10}},
		DNS:                []fixtureproto.DNSRecord{{InterfaceIndex: 7, InterfaceAlias: "Ethernet", ServerAddresses: []string{"192.0.2.53"}}},
		Services:           []fixtureproto.ServiceRecord{{Name: agentServiceName, Present: false, Status: "Absent", StartMode: "Absent"}},
		Processes:          []fixtureproto.ProcessRecord{{Role: "agent", Present: false}, {Role: "core", Present: false}, {Role: "ui", Present: false}, {Role: "fake-upstream", Present: false}},
		OwnedFirewallRules: []fixtureproto.FirewallRecord{{Name: runtimeFirewallGroup, Present: false, DefinitionSHA256: strings.Repeat("0", 64)}},
	}
}
