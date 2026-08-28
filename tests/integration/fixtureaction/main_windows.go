//go:build windows

package main

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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"corp.example/overseas-access-gateway/tests/integration/fixtureconfig"
	"corp.example/overseas-access-gateway/tests/integration/winjob"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	actionConfigEnvironment  = "OVERSEAS_ACCESS_FIXTURE_ACTION_CONFIG"
	actionRequestEnvironment = "OVERSEAS_FIXTURE_REQUEST_JSON"
	agentServiceName         = "RegenBioOverseasAccessAgent"
	actionTimeout            = 40 * time.Second
)

type windowsBackend struct {
	config   runtimeConfig
	manifest fixtureconfig.Manifest
}

func main() {
	if len(os.Args) > 1 {
		if len(os.Args) >= 6 && os.Args[1] == "supervise" {
			runSupervisorService(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6:])
			return
		}
		os.Exit(64)
	}
	if err := runAction(); err != nil {
		os.Exit(1)
	}
}

func runAction() error {
	config, manifest, err := loadRuntimeConfig()
	if err != nil {
		return err
	}
	requestData := []byte(os.Getenv(actionRequestEnvironment))
	if len(requestData) == 0 {
		requestData, err = io.ReadAll(io.LimitReader(os.Stdin, 256*1024+1))
	}
	if err != nil || len(requestData) == 0 || len(requestData) > 256*1024 {
		return errors.New("action request unavailable or oversized")
	}
	var request actionRequest
	decoder := json.NewDecoder(bytes.NewReader(requestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	result, err := dispatch(ctx, request, &windowsBackend{config: config, manifest: manifest})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func loadRuntimeConfig() (runtimeConfig, fixtureconfig.Manifest, error) {
	path := os.Getenv(actionConfigEnvironment)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return runtimeConfig{}, fixtureconfig.Manifest{}, errors.New("action config path is invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return runtimeConfig{}, fixtureconfig.Manifest{}, err
	}
	config, err := fixtureconfig.ParseActionConfig(data)
	if err != nil {
		return config, fixtureconfig.Manifest{}, err
	}
	manifestData, err := os.ReadFile(config.FixtureManifestPath)
	if err != nil {
		return config, fixtureconfig.Manifest{}, err
	}
	manifest, err := fixtureconfig.ParseManifest(manifestData)
	if err != nil {
		return config, manifest, err
	}
	if err := config.Validate(manifest, config.FakeDataEndpoint, config.FakeControlEndpoint, config.PublicDataEndpoint, config.FakeIdentity, config.PayloadManifestPath); err != nil {
		return config, manifest, err
	}
	for role, artifact := range manifest.Artifacts {
		actual, err := hashFile(artifact.Path)
		if err != nil || actual != artifact.SHA256 {
			return config, manifest, fmt.Errorf("artifact %s changed", role)
		}
	}
	return config, manifest, nil
}

func (b *windowsBackend) Execute(ctx context.Context, request actionRequest) (map[string]string, error) {
	var err error
	switch request.Action {
	case "case-setup":
		operation := "install"
		if serviceExists(agentServiceName) {
			operation = "repair"
		}
		err = b.runInstaller(ctx, operation)
	case "fake-upstream-start":
		err = b.startFakeService(ctx, request.RunID)
	case "fake-upstream-stop":
		err = deleteOwnedService(fakeServiceName(request.RunID), b.manifest.Artifacts["action-helper"].Path)
	case "core-crash":
		err = killExactImage(installedArtifact(b.manifest.Artifacts["core"]))
	case "ui-start":
		err = b.startUISupervisor(ctx, request.RunID)
	case "ui-exit":
		err = deleteOwnedService(uiServiceName(request.RunID), b.manifest.Artifacts["action-helper"].Path)
	case "agent-crash":
		err = killExactImage(installedArtifact(b.manifest.Artifacts["agent"]))
	case "agent-start":
		err = startExistingService(agentServiceName)
	case "stage-machine-recovery":
		err = killExactImage(installedArtifact(b.manifest.Artifacts["agent"]))
		if err == nil {
			err = writeRecoveryMarker(request)
		}
	case "machine-recover":
		if _, statErr := os.Stat(recoveryMarker(request)); statErr != nil {
			err = errors.New("machine recovery was not staged")
		} else {
			err = b.runInstaller(ctx, "repair")
		}
		if err == nil {
			err = startExistingService(agentServiceName)
		}
		if err == nil {
			err = os.Remove(recoveryMarker(request))
		}
	case "uninstall":
		err = b.runInstaller(ctx, "uninstall")
		if err == nil {
			err = errors.Join(deleteOwnedService(fakeServiceName(request.RunID), b.manifest.Artifacts["action-helper"].Path), deleteOwnedService(uiServiceName(request.RunID), b.manifest.Artifacts["action-helper"].Path), removeIfExists(recoveryMarker(request)))
		}
	case "case-cleanup":
		err = errors.Join(deleteOwnedService(fakeServiceName(request.RunID), b.manifest.Artifacts["action-helper"].Path), deleteOwnedService(uiServiceName(request.RunID), b.manifest.Artifacts["action-helper"].Path), removeIfExists(recoveryMarker(request)))
	case "restore":
		if err = requireCleanBaseline(request.BaselinePath); err == nil {
			err = b.runInstaller(ctx, "uninstall")
		}
		if err == nil {
			err = errors.Join(deleteOwnedService(fakeServiceName(request.RunID), b.manifest.Artifacts["action-helper"].Path), deleteOwnedService(uiServiceName(request.RunID), b.manifest.Artifacts["action-helper"].Path), removeIfExists(recoveryMarker(request)))
		}
	default:
		return nil, errors.New("unsupported action")
	}
	if err != nil {
		return nil, err
	}
	if err := b.verify(request); err != nil {
		return nil, err
	}
	return map[string]string{"verified": "true", "action": request.Action, "run_id": request.RunID}, nil
}

func (b *windowsBackend) runInstaller(ctx context.Context, operation string) error {
	executable, args, err := installerCommand(b.config, operation)
	if err != nil {
		return err
	}
	if actual, err := hashFile(executable); err != nil || actual != b.manifest.Artifacts["powershell"].SHA256 {
		return errors.New("pinned System PowerShell changed")
	}
	if actual, err := hashFile(b.config.InstallerScriptPath); err != nil || actual != b.manifest.Artifacts["installer"].SHA256 {
		return errors.New("pinned installer script changed")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func (b *windowsBackend) startFakeService(ctx context.Context, runID string) error {
	name := fakeServiceName(runID)
	sentinel := b.manifest.Artifacts["sentinel"]
	args := []string{"supervise", name, sentinel.Path, sentinel.SHA256, "fake-upstream", "-mode", "fake-upstream", "-listen", b.config.FakeDataEndpoint, "-control-listen", b.config.FakeControlEndpoint, "-identity", b.config.FakeIdentity, "-target", b.config.PublicDataEndpoint}
	if err := createOwnedService(name, b.manifest.Artifacts["action-helper"].Path, args); err != nil {
		return err
	}
	return waitUntil(ctx, func() bool {
		for _, endpoint := range []string{b.config.FakeDataEndpoint, b.config.FakeControlEndpoint} {
			connection, err := net.DialTimeout("tcp4", endpoint, 100*time.Millisecond)
			if err != nil {
				return false
			}
			_ = connection.Close()
		}
		return exactImageRunning(b.manifest.Artifacts["sentinel"])
	}, "fake listener readiness")
}

func (b *windowsBackend) startUISupervisor(ctx context.Context, runID string) error {
	ui := installedArtifact(b.manifest.Artifacts["ui"])
	args := []string{"supervise", uiServiceName(runID), ui.Path, ui.SHA256, "ui"}
	if err := createOwnedService(uiServiceName(runID), b.manifest.Artifacts["action-helper"].Path, args); err != nil {
		return err
	}
	return waitUntil(ctx, func() bool { return exactImageRunning(ui) }, "UI child readiness")
}

func waitUntil(ctx context.Context, ready func() bool, description string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %w", description, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (b *windowsBackend) verify(request actionRequest) error {
	switch request.Action {
	case "case-setup", "agent-start", "machine-recover":
		if !serviceRunning(agentServiceName) {
			return errors.New("agent service post-state is not running")
		}
		if err := verifyInstalledArtifactHashes(b.manifest, []string{"agent", "core", "ui"}, hashFile); err != nil {
			return err
		}
	case "fake-upstream-start":
		if !serviceRunning(fakeServiceName(request.RunID)) {
			return errors.New("fake service post-state is not running")
		}
	case "fake-upstream-stop":
		if serviceExists(fakeServiceName(request.RunID)) {
			return errors.New("fake service residue remains")
		}
	case "core-crash":
		if exactImageRunning(installedArtifact(b.manifest.Artifacts["core"])) {
			return errors.New("core image remains")
		}
	case "ui-start":
		if !serviceRunning(uiServiceName(request.RunID)) {
			return errors.New("UI supervisor is not running")
		}
		if !exactImageRunning(installedArtifact(b.manifest.Artifacts["ui"])) {
			return errors.New("UI supervisor does not own the manifest-bound image")
		}
	case "ui-exit":
		if serviceExists(uiServiceName(request.RunID)) {
			return errors.New("UI supervisor residue remains")
		}
	case "agent-crash":
		if exactImageRunning(installedArtifact(b.manifest.Artifacts["agent"])) {
			return errors.New("agent image remains")
		}
	case "stage-machine-recovery":
		if _, err := os.Stat(recoveryMarker(request)); err != nil {
			return errors.New("recovery marker absent")
		}
	case "uninstall", "restore":
		if serviceExists(agentServiceName) {
			return errors.New("agent service residue remains")
		}
		if err := verifyInstalledArtifactsAbsent(b.manifest, []string{"agent", "core", "ui"}, fileExists); err != nil {
			return err
		}
		for _, path := range []string{`C:\ProgramData\RegenBio\OverseasAccess\credential.bin`, `C:\ProgramData\RegenBio\OverseasAccess\sing-box.json`, `C:\ProgramData\RegenBio\OverseasAccess\runtime-owned.json`} {
			if fileExists(path) {
				return fmt.Errorf("product runtime residue remains: %s", path)
			}
		}
		if serviceExists(fakeServiceName(request.RunID)) || serviceExists(uiServiceName(request.RunID)) {
			return errors.New("fixture product residue remains")
		}
		for _, role := range []string{"agent", "core", "ui", "server-service"} {
			if exactImageRunning(installedArtifact(b.manifest.Artifacts[role])) {
				return fmt.Errorf("product process residue remains: %s", role)
			}
		}
	case "case-cleanup":
		if serviceExists(fakeServiceName(request.RunID)) || serviceExists(uiServiceName(request.RunID)) {
			return errors.New("fixture service residue remains")
		}
	}
	return nil
}

func installedArtifact(artifact fixtureconfig.Artifact) fixtureconfig.Artifact {
	artifact.Path = artifact.InstalledPath
	return artifact
}
func fakeServiceName(runID string) string { return "RegenBioFixture-" + safeRunID(runID) + "-Fake" }
func uiServiceName(runID string) string   { return "RegenBioFixture-" + safeRunID(runID) + "-UI" }
func safeRunID(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > 32 {
		result = result[:32]
	}
	return result
}

func createOwnedService(name, executable string, args []string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	if existing, err := manager.OpenService(name); err == nil {
		existing.Close()
		return errors.New("owned fixture service already exists")
	}
	service, err := manager.CreateService(name, executable, mgr.Config{DisplayName: name, StartType: mgr.StartManual}, args...)
	if err != nil {
		return err
	}
	defer service.Close()
	if err := service.Start(); err != nil {
		_ = service.Delete()
		return err
	}
	return waitService(service, svc.Running)
}

func deleteOwnedService(name, expectedExecutable string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(config.BinaryPathName), filepath.Clean(expectedExecutable)) && !strings.HasPrefix(strings.ToLower(config.BinaryPathName), strings.ToLower(`"`+expectedExecutable+`" `)) {
		return errors.New("refuse unowned fixture service")
	}
	_, _ = service.Control(svc.Stop)
	_ = waitService(service, svc.Stopped)
	return service.Delete()
}

func startExistingService(name string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if err != nil {
		return err
	}
	defer service.Close()
	status, _ := service.Query()
	if status.State != svc.Running {
		if err := service.Start(); err != nil {
			return err
		}
	}
	return waitService(service, svc.Running)
}
func serviceExists(name string) bool {
	manager, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if err != nil {
		return false
	}
	service.Close()
	return true
}
func serviceRunning(name string) bool {
	manager, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if err != nil {
		return false
	}
	defer service.Close()
	status, err := service.Query()
	return err == nil && status.State == svc.Running
}
func waitService(service *mgr.Service, state svc.State) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == state {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("service transition timed out")
}

func killExactImage(artifact fixtureconfig.Artifact) error {
	pids, err := matchingProcesses(artifact)
	if err != nil {
		return err
	}
	if len(pids) != 1 {
		return fmt.Errorf("expected exactly one owned process, got %d", len(pids))
	}
	process, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pids[0])
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	if err := windows.TerminateProcess(process, 77); err != nil {
		return err
	}
	_, err = windows.WaitForSingleObject(process, 15000)
	return err
}
func exactImageRunning(artifact fixtureconfig.Artifact) bool {
	pids, err := matchingProcesses(artifact)
	return err == nil && len(pids) > 0
}
func matchingProcesses(artifact fixtureconfig.Artifact) ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err = windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}
	var result []uint32
	for {
		handle, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if openErr == nil {
			buffer := make([]uint16, 32768)
			size := uint32(len(buffer))
			if windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size) == nil {
				path := windows.UTF16ToString(buffer[:size])
				if strings.EqualFold(filepath.Clean(path), filepath.Clean(artifact.Path)) {
					hash, _ := hashFile(path)
					if hash == artifact.SHA256 {
						result = append(result, entry.ProcessID)
					}
				}
			}
			windows.CloseHandle(handle)
		}
		if err = windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, err
		}
	}
	return result, nil
}

func recoveryMarker(request actionRequest) string {
	return filepath.Join(`C:\ProgramData\RegenBio\OverseasAccess`, "fixture-recovery-"+safeRunID(request.RunID)+".json")
}
func writeRecoveryMarker(request actionRequest) error {
	data, _ := json.Marshal(map[string]string{"run_id": request.RunID, "request_nonce": request.RequestNonce})
	file, err := os.OpenFile(recoveryMarker(request), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}
func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func requireCleanBaseline(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snapshot struct {
		MSI     []struct{ Present bool } `json:"msi_registrations"`
		Files   []struct{ Present bool } `json:"installed_files"`
		Runtime []struct{ Present bool } `json:"runtime_files"`
	}
	if err = json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	for _, v := range snapshot.MSI {
		if v.Present {
			return errors.New("restore requires a clean disposable baseline")
		}
	}
	for _, v := range append(snapshot.Files, snapshot.Runtime...) {
		if v.Present {
			return errors.New("restore requires a clean disposable baseline")
		}
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
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

type supervisorHandler struct {
	targetPath, targetHash, role string
	args                         []string
}

func runSupervisorService(serviceName, targetPath, targetHash, role string, args []string) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		os.Exit(64)
	}
	if err := svc.Run(serviceName, &supervisorHandler{targetPath: targetPath, targetHash: targetHash, role: role, args: append([]string(nil), args...)}); err != nil {
		os.Exit(1)
	}
}
func (h *supervisorHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	actual, err := hashFile(h.targetPath)
	if err != nil || actual != h.targetHash {
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	done := make(chan error, 1)
	go func() { _, runErr := winjob.Run(ctx, h.targetPath, h.args, os.Environ(), nil); done <- runErr }()
	for {
		select {
		case request := <-requests:
			if request.Cmd == svc.Stop || request.Cmd == svc.Shutdown {
				statuses <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				statuses <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-done:
			statuses <- svc.Status{State: svc.Stopped}
			return false, 3
		}
	}
}
