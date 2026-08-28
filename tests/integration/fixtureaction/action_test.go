package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"corp.example/overseas-access-gateway/tests/integration/fixtureconfig"
)

func TestDispatchSupportsExactlyReviewedLifecycleActions(t *testing.T) {
	want := []string{"case-setup", "fake-upstream-start", "fake-upstream-stop", "core-crash", "ui-start", "ui-exit", "agent-crash", "agent-start", "stage-machine-recovery", "machine-recover", "uninstall", "case-cleanup", "restore"}
	if got := SupportedActions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedActions() = %#v, want %#v", got, want)
	}
	for _, action := range want {
		t.Run(action, func(t *testing.T) {
			backend := &recordingBackend{facts: map[string]string{"verified": "true"}}
			request := validActionRequest(action)
			result, err := dispatch(context.Background(), request, backend)
			if err != nil {
				t.Fatalf("dispatch() = %v", err)
			}
			if result.Action != action || result.RequestNonce != request.RequestNonce || result.RunID != request.RunID || result.Facts["verified"] != "true" {
				t.Fatalf("result = %#v", result)
			}
			if backend.calls != 1 || backend.lastAction != action {
				t.Fatalf("backend calls = %d/%s", backend.calls, backend.lastAction)
			}
		})
	}
	if _, err := dispatch(context.Background(), validActionRequest("arbitrary-command"), &recordingBackend{}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("dispatch() = %v, want refusal", err)
	}
}

func TestInstalledArtifactVerificationRequiresManifestPathAndExactHash(t *testing.T) {
	manifest := fixtureconfig.Manifest{Artifacts: map[string]fixtureconfig.Artifact{
		"agent": {InstalledPath: `C:\Program Files\RegenBio\agent.exe`, SHA256: strings.Repeat("a", 64)},
		"core":  {InstalledPath: `C:\Program Files\RegenBio\core.exe`, SHA256: strings.Repeat("b", 64)},
		"ui":    {InstalledPath: `C:\Program Files\RegenBio\ui.exe`, SHA256: strings.Repeat("c", 64)},
	}}
	hashes := map[string]string{
		manifest.Artifacts["agent"].InstalledPath: manifest.Artifacts["agent"].SHA256,
		manifest.Artifacts["core"].InstalledPath:  manifest.Artifacts["core"].SHA256,
		manifest.Artifacts["ui"].InstalledPath:    manifest.Artifacts["ui"].SHA256,
	}
	hash := func(path string) (string, error) {
		value, ok := hashes[path]
		if !ok {
			return "", errors.New("absent")
		}
		return value, nil
	}
	if err := verifyInstalledArtifactHashes(manifest, []string{"agent", "core", "ui"}, hash); err != nil {
		t.Fatalf("verifyInstalledArtifactHashes() = %v", err)
	}
	hashes[manifest.Artifacts["core"].InstalledPath] = strings.Repeat("d", 64)
	if err := verifyInstalledArtifactHashes(manifest, []string{"agent", "core", "ui"}, hash); err == nil || !strings.Contains(err.Error(), "core") {
		t.Fatalf("verifyInstalledArtifactHashes() = %v, want core refusal", err)
	}
}

func TestAbsentArtifactVerificationUsesManifestInstalledPaths(t *testing.T) {
	manifest := fixtureconfig.Manifest{Artifacts: map[string]fixtureconfig.Artifact{
		"agent": {InstalledPath: `D:\Owned\agent.exe`},
		"core":  {InstalledPath: `D:\Owned\core.exe`},
		"ui":    {InstalledPath: `D:\Owned\ui.exe`},
	}}
	exists := map[string]bool{manifest.Artifacts["core"].InstalledPath: true}
	if err := verifyInstalledArtifactsAbsent(manifest, []string{"agent", "core", "ui"}, func(path string) bool { return exists[path] }); err == nil || !strings.Contains(err.Error(), "core") {
		t.Fatalf("verifyInstalledArtifactsAbsent() = %v, want core refusal", err)
	}
	delete(exists, manifest.Artifacts["core"].InstalledPath)
	if err := verifyInstalledArtifactsAbsent(manifest, []string{"agent", "core", "ui"}, func(path string) bool { return exists[path] }); err != nil {
		t.Fatalf("verifyInstalledArtifactsAbsent() = %v", err)
	}
}

func TestDispatchDoesNotReturnSuccessWithoutActionLocalVerification(t *testing.T) {
	backend := &recordingBackend{facts: map[string]string{"verified": "false"}}
	if _, err := dispatch(context.Background(), validActionRequest("uninstall"), backend); err == nil || !strings.Contains(err.Error(), "verify") {
		t.Fatalf("dispatch() = %v, want verification refusal", err)
	}
	backend = &recordingBackend{facts: nil}
	if _, err := dispatch(context.Background(), validActionRequest("case-cleanup"), backend); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("dispatch() = %v, want absent evidence refusal", err)
	}
}

func TestInstallerArgumentsAreFixedByTypedOperation(t *testing.T) {
	config := runtimeConfig{PowerShellPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, InstallerScriptPath: `C:\fixture\install-client.ps1`, BundlePath: `C:\fixture\bundle`, PayloadManifestPath: `C:\fixture\payload.json`}
	tests := []struct {
		operation, mode string
		want            []string
	}{
		{operation: "install", mode: "Install", want: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", config.InstallerScriptPath, "-Mode", "Install", "-BundlePath", config.BundlePath, "-PayloadManifestPath", config.PayloadManifestPath}},
		{operation: "repair", mode: "Repair", want: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", config.InstallerScriptPath, "-Mode", "Repair", "-BundlePath", config.BundlePath, "-PayloadManifestPath", config.PayloadManifestPath}},
		{operation: "uninstall", mode: "Uninstall", want: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", config.InstallerScriptPath, "-Mode", "Uninstall", "-Confirm:$false"}},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			executable, args, err := installerCommand(config, test.operation)
			if err != nil {
				t.Fatal(err)
			}
			if executable != config.PowerShellPath || !reflect.DeepEqual(args, test.want) {
				t.Fatalf("installerCommand() = %q %#v, want %#v", executable, args, test.want)
			}
		})
	}
	if _, _, err := installerCommand(config, "free-form"); err == nil {
		t.Fatal("installerCommand accepted free-form operation")
	}
}

func validActionRequest(action string) actionRequest {
	return actionRequest{ProtocolVersion: 3, RequestNonce: "nonce-1", RunID: "run-1", Scenario: "scenario-1", Action: action, EvidenceDirectory: `C:\evidence\run`, BaselinePath: `C:\evidence\run\baseline.json`, BaselineSHA256: strings.Repeat("a", 64)}
}

type recordingBackend struct {
	calls      int
	lastAction string
	facts      map[string]string
	err        error
}

func (b *recordingBackend) Execute(_ context.Context, request actionRequest) (map[string]string, error) {
	b.calls++
	b.lastAction = request.Action
	return b.facts, b.err
}
