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

func TestProvisionerPlanUsesInstalledManifestPinnedExecutableAndPipeOnlyInput(t *testing.T) {
	payload := testPayloadManifest()
	config := runtimeConfig{CredentialSourcePath: `C:\fixture\credential-source.exe`, CredentialSourceSHA256: strings.Repeat("f", 64)}
	client := []byte(`{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"shadowsocks","tag":"tunnel","server":"172.20.9.15","server_port":18443,"method":"2022-blake3-aes-128-gcm"}],"route":{"final":"tunnel"}}`)
	executable, source, metadata, err := provisionerPlan(config, client, payload)
	if err != nil {
		t.Fatal(err)
	}
	if executable != `C:\Program Files\RegenBio\OverseasAccess\credential-provisioner.exe` || source != config.CredentialSourcePath {
		t.Fatalf("plan executable=%q source=%q", executable, source)
	}
	if metadata.Method != "2022-blake3-aes-128-gcm" || metadata.Endpoint != "172.20.9.15:18443" {
		t.Fatalf("metadata=%#v", metadata)
	}
}

func TestCompletePayloadVerificationRejectsAnyMissingWrongOrResidualFile(t *testing.T) {
	payload := testPayloadManifest()
	installed, err := payload.InstalledFiles()
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for _, file := range installed {
		hashes[file.Path] = file.SHA256
	}
	hash := func(path string) (string, error) {
		value, ok := hashes[path]
		if !ok {
			return "", errors.New("absent")
		}
		return value, nil
	}
	if err := verifyInstalledPayloadHashes(payload, hash); err != nil {
		t.Fatal(err)
	}
	delete(hashes, installed[len(installed)-1].Path)
	if err := verifyInstalledPayloadHashes(payload, hash); err == nil || !strings.Contains(err.Error(), installed[len(installed)-1].Name) {
		t.Fatalf("missing payload accepted: %v", err)
	}
	hashes[installed[len(installed)-1].Path] = installed[len(installed)-1].SHA256
	if err := verifyInstalledPayloadAbsent(payload, func(path string) bool { return path == installed[0].Path }); err == nil || !strings.Contains(err.Error(), installed[0].Name) {
		t.Fatalf("residue accepted: %v", err)
	}
}

func TestCleanHostSetupSequenceRequiresCleanBaselineThenProvisionsBeforeAgentStart(t *testing.T) {
	var events []string
	step := func(name string, err error) func() error {
		return func() error { events = append(events, name); return err }
	}
	if err := runCaseSetup("install", func(operation string) error { events = append(events, "clean:"+operation); return nil }, func(operation string) error { events = append(events, operation); return nil }, step("provision", nil), step("agent-start", nil)); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events, ","); got != "clean:install,install,provision,agent-start" {
		t.Fatalf("sequence=%s", got)
	}
	events = nil
	if err := runCaseSetup("install", func(operation string) error { events = append(events, "clean:"+operation); return nil }, func(operation string) error { events = append(events, operation); return nil }, step("provision", errors.New("refused")), step("agent-start", nil)); err == nil {
		t.Fatal("provisioning failure was accepted")
	}
	if got := strings.Join(events, ","); got != "clean:install,install,provision" {
		t.Fatalf("failure sequence=%s", got)
	}
}

func testPayloadManifest() fixtureconfig.PayloadManifest {
	names := []string{"overseas-agent.exe", "overseas-client.exe", "credential-provisioner.exe", "installer-verifier.exe", "install-client.ps1", "PROVISIONING.md", "sing-box.exe", "sing-box.manifest.json", "libcronet.dll", "wintun.dll", "agent.yaml", "agent.yaml.p7s", "client-sbom.json", "SHA256SUMS", "sing-box-LICENSE.txt", "wintun-LICENSE.txt"}
	files := make([]fixtureconfig.PayloadFile, len(names))
	for index, name := range names {
		destination := "program-files"
		if name == "agent.yaml" || name == "agent.yaml.p7s" || name == "client-sbom.json" || name == "SHA256SUMS" {
			destination = "program-data"
		}
		files[index] = fixtureconfig.PayloadFile{Name: name, Destination: destination, SHA256: strings.Repeat(string("0123456789abcdef"[index]), 64)}
	}
	return fixtureconfig.PayloadManifest{SchemaVersion: 1, ProductVersion: "0.1.0", SourceCommit: strings.Repeat("a", 40), Mode: "release", SignerThumbprints: []string{strings.Repeat("a", 40)}, Files: files}
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
	return actionRequest{ProtocolVersion: 4, RequestNonce: "nonce-1", RunID: "run-1", Scenario: "scenario-1", Action: action, EvidenceDirectory: `C:\evidence\run`, BaselinePath: `C:\evidence\run\baseline.json`, BaselineSHA256: strings.Repeat("a", 64)}
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
