package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"corp.example/overseas-access-gateway/tests/integration/fixtureconfig"
)

var supportedActions = []string{"case-setup", "fake-upstream-start", "fake-upstream-stop", "core-crash", "ui-start", "ui-exit", "agent-crash", "agent-start", "stage-machine-recovery", "machine-recover", "uninstall", "case-cleanup", "restore"}

type actionRequest struct {
	ProtocolVersion   int    `json:"protocol_version"`
	RequestNonce      string `json:"request_nonce"`
	RunID             string `json:"run_id"`
	Scenario          string `json:"scenario"`
	Action            string `json:"action"`
	EvidenceDirectory string `json:"evidence_directory"`
	BaselinePath      string `json:"baseline_path"`
	BaselineSHA256    string `json:"baseline_sha256"`
}

type actionResult struct {
	ProtocolVersion int               `json:"protocol_version"`
	RequestNonce    string            `json:"request_nonce"`
	RunID           string            `json:"run_id"`
	Scenario        string            `json:"scenario"`
	Action          string            `json:"action"`
	Facts           map[string]string `json:"facts"`
}

type lifecycleBackend interface {
	Execute(context.Context, actionRequest) (map[string]string, error)
}

type runtimeConfig = fixtureconfig.ActionConfig

type serverPlan struct {
	ServiceName, ServiceSource, ServicePath, ServiceSHA256 string
	CoreSource, CorePath, CoreSHA256                       string
	ConfigSource, ConfigPath, ConfigSHA256                 string
	ListenerEndpoint                                       string
}

func runCaseSetup(operation string, requireClean, install func(string) error, provision, startAgent func() error) error {
	if requireClean == nil || install == nil || provision == nil || startAgent == nil {
		return errors.New("case setup step is absent")
	}
	if err := requireClean(operation); err != nil {
		return err
	}
	if err := install(operation); err != nil {
		return err
	}
	if err := provision(); err != nil {
		return err
	}
	if err := startAgent(); err != nil {
		return err
	}
	return nil
}

func productionServerPlan(manifest fixtureconfig.Manifest, configPath, configSHA256, listenerEndpoint string) (serverPlan, error) {
	service, serviceOK := manifest.Artifacts["server-service"]
	core, coreOK := manifest.Artifacts["core"]
	if !serviceOK || !coreOK || !filepath.IsAbs(service.Path) || !filepath.IsAbs(core.Path) || !filepath.IsAbs(configPath) || len(configSHA256) != 64 || strings.TrimSpace(listenerEndpoint) == "" {
		return serverPlan{}, errors.New("production server ownership inputs are incomplete")
	}
	return serverPlan{
		ServiceName: "RegenBioOverseasAccessServer", ServiceSource: service.Path, ServicePath: `C:\Program Files\RegenBio\OverseasAccessServer\overseas-server-service.exe`, ServiceSHA256: service.SHA256,
		CoreSource: core.Path, CorePath: `C:\Program Files\RegenBio\OverseasAccessServer\sing-box.exe`, CoreSHA256: core.SHA256,
		ConfigSource: configPath, ConfigPath: `C:\ProgramData\RegenBio\OverseasAccessServer\config.json`, ConfigSHA256: configSHA256, ListenerEndpoint: listenerEndpoint,
	}, nil
}

func SupportedActions() []string { return append([]string(nil), supportedActions...) }

func dispatch(ctx context.Context, request actionRequest, backend lifecycleBackend) (actionResult, error) {
	if err := request.Validate(); err != nil {
		return actionResult{}, err
	}
	if backend == nil {
		return actionResult{}, errors.New("lifecycle backend is absent")
	}
	facts, err := backend.Execute(ctx, request)
	if err != nil {
		return actionResult{}, err
	}
	if len(facts) == 0 {
		return actionResult{}, errors.New("action-local evidence is absent")
	}
	if facts["verified"] != "true" {
		return actionResult{}, errors.New("action-local post-state verify failed")
	}
	return actionResult{ProtocolVersion: request.ProtocolVersion, RequestNonce: request.RequestNonce, RunID: request.RunID, Scenario: request.Scenario, Action: request.Action, Facts: facts}, nil
}

func (r actionRequest) Validate() error {
	if r.ProtocolVersion != 4 || strings.TrimSpace(r.RequestNonce) == "" || strings.TrimSpace(r.RunID) == "" || strings.TrimSpace(r.Scenario) == "" {
		return errors.New("action request binding is invalid")
	}
	found := false
	for _, action := range supportedActions {
		if r.Action == action {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unsupported lifecycle action %q", r.Action)
	}
	if !filepath.IsAbs(r.EvidenceDirectory) || filepath.Clean(r.EvidenceDirectory) != r.EvidenceDirectory || !filepath.IsAbs(r.BaselinePath) || filepath.Clean(r.BaselinePath) != r.BaselinePath {
		return errors.New("action evidence/baseline path is invalid")
	}
	if len(r.BaselineSHA256) != 64 || r.BaselineSHA256 != strings.ToLower(r.BaselineSHA256) {
		return errors.New("baseline hash is invalid")
	}
	if _, err := hex.DecodeString(r.BaselineSHA256); err != nil {
		return errors.New("baseline hash is invalid")
	}
	return nil
}

func installerCommand(config runtimeConfig, operation string) (string, []string, error) {
	expectedPowerShell := filepath.Join(filepath.Clean(os.Getenv("SystemRoot")), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if !filepath.IsAbs(config.PowerShellPath) || filepath.Clean(os.Getenv("SystemRoot")) == "." || !strings.EqualFold(filepath.Clean(config.PowerShellPath), expectedPowerShell) {
		return "", nil, errors.New("PowerShell must be the exact System32 executable")
	}
	if !filepath.IsAbs(config.InstallerScriptPath) {
		return "", nil, errors.New("installer script path is invalid")
	}
	base := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", config.InstallerScriptPath, "-Mode"}
	switch operation {
	case "install":
		return config.PowerShellPath, append(base, "Install", "-BundlePath", config.BundlePath, "-PayloadManifestPath", config.PayloadManifestPath), nil
	case "repair":
		return config.PowerShellPath, append(base, "Repair", "-BundlePath", config.BundlePath, "-PayloadManifestPath", config.PayloadManifestPath), nil
	case "uninstall":
		return config.PowerShellPath, append(base, "Uninstall", "-Confirm:$false"), nil
	default:
		return "", nil, fmt.Errorf("unsupported installer operation %q", operation)
	}
}

func verifyInstalledArtifactHashes(manifest fixtureconfig.Manifest, roles []string, hashFile func(string) (string, error)) error {
	if hashFile == nil {
		return errors.New("installed artifact hasher is absent")
	}
	for _, role := range roles {
		artifact, ok := manifest.Artifacts[role]
		if !ok || artifact.InstalledPath == "" {
			return fmt.Errorf("installed artifact %s is not declared", role)
		}
		actual, err := hashFile(artifact.InstalledPath)
		if err != nil || actual != artifact.SHA256 {
			return fmt.Errorf("installed artifact %s hash mismatch", role)
		}
	}
	return nil
}

func verifyInstalledArtifactsAbsent(manifest fixtureconfig.Manifest, roles []string, exists func(string) bool) error {
	if exists == nil {
		return errors.New("installed artifact existence check is absent")
	}
	for _, role := range roles {
		artifact, ok := manifest.Artifacts[role]
		if !ok || artifact.InstalledPath == "" {
			return fmt.Errorf("installed artifact %s is not declared", role)
		}
		if exists(artifact.InstalledPath) {
			return fmt.Errorf("installed artifact %s residue remains", role)
		}
	}
	return nil
}

func provisionerPlan(config runtimeConfig, clientConfig []byte, payload fixtureconfig.PayloadManifest) (string, string, fixtureconfig.ProvisioningDetails, error) {
	installed, err := payload.InstalledFiles()
	if err != nil {
		return "", "", fixtureconfig.ProvisioningDetails{}, err
	}
	var executable string
	for _, file := range installed {
		if file.Name == "credential-provisioner.exe" {
			executable = file.Path
			break
		}
	}
	if executable == "" {
		return "", "", fixtureconfig.ProvisioningDetails{}, errors.New("credential provisioner is absent from the payload manifest")
	}
	metadata, err := fixtureconfig.ProvisioningMetadata(clientConfig)
	if err != nil {
		return "", "", fixtureconfig.ProvisioningDetails{}, err
	}
	if !filepath.IsAbs(config.CredentialSourcePath) || filepath.Clean(config.CredentialSourcePath) != config.CredentialSourcePath {
		return "", "", fixtureconfig.ProvisioningDetails{}, errors.New("credential source path is invalid")
	}
	return executable, config.CredentialSourcePath, metadata, nil
}

func verifyInstalledPayloadHashes(manifest fixtureconfig.PayloadManifest, hashFile func(string) (string, error)) error {
	if hashFile == nil {
		return errors.New("installed payload hasher is absent")
	}
	installed, err := manifest.InstalledFiles()
	if err != nil {
		return err
	}
	for _, file := range installed {
		actual, hashErr := hashFile(file.Path)
		if hashErr != nil || actual != file.SHA256 {
			return fmt.Errorf("installed payload %s hash mismatch", file.Name)
		}
	}
	return nil
}

func verifyInstalledPayloadAbsent(manifest fixtureconfig.PayloadManifest, exists func(string) bool) error {
	if exists == nil {
		return errors.New("installed payload existence check is absent")
	}
	installed, err := manifest.InstalledFiles()
	if err != nil {
		return err
	}
	for _, file := range installed {
		if exists(file.Path) {
			return fmt.Errorf("installed payload %s residue remains", file.Name)
		}
	}
	return nil
}
