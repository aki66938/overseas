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
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"corp.example/overseas-access-gateway/internal/coreverify"
	"corp.example/overseas-access-gateway/tests/integration/fixtureproto"
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
	SchemaVersion        int                         `json:"schema_version"`
	HostIdentity         string                      `json:"host_identity"`
	EvidenceRoot         string                      `json:"evidence_root"`
	PayloadPath          string                      `json:"payload_path"`
	GeneratedConfigPath  string                      `json:"generated_config_path"`
	Binding              fixtureproto.FixtureBinding `json:"binding"`
	PublicSentinel       string                      `json:"public_sentinel"`
	PublicSentinelHealth string                      `json:"public_sentinel_health"`
	CorporateSentinel    string                      `json:"corporate_sentinel"`
	FakeUpstreamControl  string                      `json:"fake_upstream_control"`
	Commands             map[string][]string         `json:"commands"`
	CommandSHA256        map[string]string           `json:"command_sha256"`
	CommandSigners       map[string][]string         `json:"command_signers"`
}

type dependencies struct {
	runCommand       func(context.Context, []string, fixtureproto.Request) error
	capture          func(context.Context, string) (fixtureproto.Snapshot, error)
	probeIdentity    func(context.Context, string, string, bool) error
	hashFile         func(string) (string, error)
	validateEvidence func(string, string) error
	verifyCommand    func(string, []string) (io.Closer, error)
	lockInput        func(string, string) (io.Closer, error)
}

func (c fixtureConfig) Validate() error {
	if c.SchemaVersion != 1 || strings.TrimSpace(c.HostIdentity) == "" {
		return errors.New("fixture schema and host identity are required")
	}
	for name, value := range map[string]string{
		"payload path": c.PayloadPath, "generated config path": c.GeneratedConfigPath, "evidence root": c.EvidenceRoot,
		"public sentinel": c.PublicSentinel, "public sentinel health": c.PublicSentinelHealth, "corporate sentinel": c.CorporateSentinel,
		"fake upstream control": c.FakeUpstreamControl,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	for name, value := range map[string]string{"payload path": c.PayloadPath, "generated config path": c.GeneratedConfigPath, "evidence root": c.EvidenceRoot} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be absolute and clean", name)
		}
	}
	for name, value := range map[string]string{"payload hash": c.Binding.PayloadSHA256, "config hash": c.Binding.ConfigSHA256} {
		if !isSHA256(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if c.Binding.FakeUpstreamIdentity == "" || c.Binding.PublicSentinelIdentity == "" || c.Binding.CorporateSentinelIdentity == "" {
		return errors.New("all fixture identities are required")
	}
	if c.Binding.FakeUpstreamIdentity == c.Binding.PublicSentinelIdentity || c.Binding.FakeUpstreamIdentity == c.Binding.CorporateSentinelIdentity || c.Binding.PublicSentinelIdentity == c.Binding.CorporateSentinelIdentity {
		return errors.New("fixture identities must be distinct")
	}
	if c.Binding.PublicSentinelEndpoint != c.PublicSentinel || c.Binding.PublicSentinelHealthEndpoint != c.PublicSentinelHealth || c.Binding.CorporateSentinelEndpoint != c.CorporateSentinel || c.Binding.FakeUpstreamControlEndpoint != c.FakeUpstreamControl {
		return errors.New("fixture binding endpoints do not match configured endpoints")
	}
	for _, action := range mutatingActions {
		command := c.Commands[action]
		if len(command) == 0 || !filepath.IsAbs(command[0]) || filepath.Clean(command[0]) != command[0] || !strings.EqualFold(filepath.Ext(command[0]), ".exe") {
			return fmt.Errorf("action %s requires an absolute .exe command", action)
		}
		if !isSHA256(c.CommandSHA256[action]) || len(c.CommandSigners[action]) == 0 {
			return fmt.Errorf("action %s requires a command hash and signer allowlist", action)
		}
	}
	if len(c.Commands) != len(mutatingActions) || len(c.CommandSHA256) != len(mutatingActions) || len(c.CommandSigners) != len(mutatingActions) {
		return errors.New("fixture commands contain an unsupported action")
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
			return captureWindows(ctx, nonce)
		},
		probeIdentity:    probeFixtureIdentity,
		hashFile:         hashFile,
		validateEvidence: validateEvidenceDirectory,
		verifyCommand:    config.verifyAndLockCommand,
		lockInput:        lockPinnedInput,
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
	if deps.hashFile == nil {
		deps.hashFile = func(path string) (string, error) {
			switch path {
			case config.PayloadPath:
				return config.Binding.PayloadSHA256, nil
			case config.GeneratedConfigPath:
				return config.Binding.ConfigSHA256, nil
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
		if err := deps.probeIdentity(ctx, config.FakeUpstreamControl, config.Binding.FakeUpstreamIdentity, true); err != nil {
			return fixtureproto.Response{}, fmt.Errorf("fake upstream: %w", err)
		}
	case "capture":
	default:
		command, exists := config.Commands[request.Action]
		if !exists {
			return fixtureproto.Response{}, errors.New("unsupported action")
		}
		if deps.verifyCommand == nil {
			return fixtureproto.Response{}, errors.New("command verifier is absent")
		}
		lockedCommand, err := deps.verifyCommand(request.Action, command)
		if err != nil {
			return fixtureproto.Response{}, fmt.Errorf("configured command refused: %w", err)
		}
		defer lockedCommand.Close()
		if err := deps.runCommand(ctx, command, request); err != nil {
			return fixtureproto.Response{}, err
		}
	}

	snapshot, err := deps.capture(ctx, request.RequestNonce)
	if err != nil {
		return fixtureproto.Response{}, err
	}
	if err := snapshot.Validate(request.RequestNonce); err != nil {
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

func (c fixtureConfig) verifyAndLockCommand(action string, command []string) (io.Closer, error) {
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
	if err := coreverify.Verify(command[0], c.CommandSHA256[action], c.CommandSigners[action]); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
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
	for _, service := range snapshot.Services {
		if service.Name == agentServiceName {
			servicePresent = service.Present
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
		"owned_firewall_absent":  !firewallPresent,
		"owned_firewall_present": firewallPresent,
		"tun_absent":             !tunPresent,
	} {
		facts[name] = fmt.Sprintf("%t", value)
	}
	if request.Action == "restore" {
		facts["restore_input_sha256"] = request.BaselineSHA256
		facts["state_restored"] = fmt.Sprintf("%t", digestBytes(state) == request.BaselineSHA256)
	}
	return facts
}

func runConfiguredCommand(ctx context.Context, command []string, request fixtureproto.Request) error {
	if len(command) == 0 {
		return errors.New("empty command")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	environment := withoutEnvironmentKeys(os.Environ(), "OVERSEAS_FIXTURE_RUN_ID", "OVERSEAS_FIXTURE_SCENARIO", "OVERSEAS_FIXTURE_ACTION", "OVERSEAS_FIXTURE_BASELINE_PATH", "OVERSEAS_FIXTURE_BASELINE_SHA256")
	environment = append(environment,
		"OVERSEAS_FIXTURE_RUN_ID="+request.RunID,
		"OVERSEAS_FIXTURE_SCENARIO="+request.Scenario,
		"OVERSEAS_FIXTURE_ACTION="+request.Action,
		"OVERSEAS_FIXTURE_BASELINE_PATH="+request.BaselinePath,
		"OVERSEAS_FIXTURE_BASELINE_SHA256="+request.BaselineSHA256,
	)
	commandLine := make([]string, len(command))
	for index, argument := range command {
		commandLine[index] = syscall.EscapeArg(argument)
	}
	application, err := windows.UTF16PtrFromString(command[0])
	if err != nil {
		return err
	}
	commandLineUTF16, err := windows.UTF16PtrFromString(strings.Join(commandLine, " "))
	if err != nil {
		return err
	}
	environmentUTF16 := makeEnvironmentBlock(environment)
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var process windows.ProcessInformation
	if err := windows.CreateProcess(application, commandLineUTF16, nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, &environmentUTF16[0], nil, &startup, &process); err != nil {
		return fmt.Errorf("start configured action: %w", err)
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		_ = windows.TerminateProcess(process.Process, 1)
		return err
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		return err
	}
	done := make(chan error, 1)
	go func() {
		_, waitErr := windows.WaitForSingleObject(process.Process, windows.INFINITE)
		if waitErr != nil {
			done <- waitErr
			return
		}
		var exitCode uint32
		if err := windows.GetExitCodeProcess(process.Process, &exitCode); err != nil {
			done <- err
			return
		}
		if exitCode != 0 {
			done <- fmt.Errorf("exit code %d", exitCode)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("configured action failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		_ = windows.TerminateJobObject(job, 1)
		<-done
		return ctx.Err()
	}
}

func makeEnvironmentBlock(environment []string) []uint16 {
	values := append([]string(nil), environment...)
	sort.Slice(values, func(i, j int) bool { return strings.ToUpper(values[i]) < strings.ToUpper(values[j]) })
	return utf16.Encode([]rune(strings.Join(values, "\x00") + "\x00\x00"))
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
$adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop|ForEach-Object{[ordered]@{interface_index=[int]$_.ifIndex;interface_guid=[string]$_.InterfaceGuid;interface_alias=[string]$_.InterfaceAlias;status=[string]$_.Status}}|Sort-Object interface_guid)
$routes=@(Get-NetRoute -ErrorAction Stop|ForEach-Object{[ordered]@{destination_prefix=[string]$_.DestinationPrefix;interface_index=[int]$_.InterfaceIndex;next_hop=[string]$_.NextHop;route_metric=[int]$_.RouteMetric}}|Sort-Object destination_prefix,interface_index,next_hop,route_metric)
$dns=@(Get-DnsClientServerAddress -ErrorAction Stop|Where-Object{@($_.ServerAddresses).Count -gt 0}|ForEach-Object{[ordered]@{interface_index=[int]$_.InterfaceIndex;interface_alias=[string]$_.InterfaceAlias;server_addresses=@($_.ServerAddresses|ForEach-Object{[string]$_}|Sort-Object)}}|Sort-Object interface_index)
$svc=Get-CimInstance Win32_Service -Filter "Name='RegenBioOverseasAccessAgent'" -ErrorAction SilentlyContinue
$servicePath=if($null-eq $svc){''}else{([string]$svc.PathName).Trim('"')}
$services=@([ordered]@{name='RegenBioOverseasAccessAgent';present=[bool]($null-ne $svc);status=$(if($null-eq $svc){'Absent'}else{[string]$svc.State});start_mode=$(if($null-eq $svc){'Absent'}else{[string]$svc.StartMode});path_sha256=$(Hash-File $servicePath)})
$roles=[ordered]@{agent='overseas-agent';core='sing-box';ui='overseas-client';'fake-upstream'='fixture-sentinel'}
$processes=@(foreach($entry in $roles.GetEnumerator()){if($entry.Key -eq 'fake-upstream'){$items=@(Get-CimInstance Win32_Process -Filter "Name='fixture-sentinel.exe'" -ErrorAction SilentlyContinue|Where-Object{$_.CommandLine -match '(?:^|\s)-mode(?:\s+|=)fake-upstream(?:\s|$)'}|Sort-Object ProcessId)}else{$items=@(Get-Process -Name $entry.Value -ErrorAction SilentlyContinue|Sort-Object Id)};if($items.Count -eq 0){[ordered]@{role=[string]$entry.Key;present=$false;pid=0;image_sha256=''}}elseif($items.Count -eq 1){if($entry.Key -eq 'fake-upstream'){$path=[string]$items[0].ExecutablePath;$pidValue=[int]$items[0].ProcessId}else{$path=[string]$items[0].Path;$pidValue=[int]$items[0].Id};[ordered]@{role=[string]$entry.Key;present=$true;pid=$pidValue;image_sha256=$(Hash-File $path)}}else{throw "ambiguous process role $($entry.Key)"}})
$names=@('RegenBioOverseasAccess.BlockPublicTCP','RegenBioOverseasAccess.BlockQUIC','RegenBioOverseasAccess.BlockPublicUDP','RegenBioOverseasAccess.BlockUnapprovedDNSUDP','RegenBioOverseasAccess.BlockUnapprovedDNSTCP','RegenBioOverseasAccess.BlockPublicEmergency','RegenBioOverseasAccess-AllowAgent-Out','RegenBioOverseasAccess-AllowCoreTCP-Out','RegenBioOverseasAccess-AllowCoreUDP-Out')
$firewall=@(foreach($name in $names){$rules=@(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue);if($rules.Count -eq 0){[ordered]@{name=$name;present=$false;definition_sha256=('0'*64)}}elseif($rules.Count -eq 1){$rule=$rules[0];$definition=[ordered]@{rule=$rule|Select-Object Name,DisplayName,Group,Direction,Action,Enabled,Profile,PolicyStoreSourceType;port=$rule|Get-NetFirewallPortFilter|Select-Object Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget;address=$rule|Get-NetFirewallAddressFilter|Select-Object LocalAddress,RemoteAddress;application=$rule|Get-NetFirewallApplicationFilter|Select-Object Program,Package;service=$rule|Get-NetFirewallServiceFilter|Select-Object Service;interface=$rule|Get-NetFirewallInterfaceFilter|Select-Object InterfaceAlias;interface_type=$rule|Get-NetFirewallInterfaceTypeFilter|Select-Object InterfaceType;security=$rule|Get-NetFirewallSecurityFilter|Select-Object Authentication,Encryption,RemoteMachine,RemoteUser,LocalUser}|ConvertTo-Json -Compress -Depth 6;[ordered]@{name=$name;present=$true;definition_sha256=$(Hash-Text $definition)}}else{throw "ambiguous firewall rule $name"}})
[ordered]@{observation_nonce=$env:FIXTURE_OBSERVATION_NONCE;adapters=$adapters;routes=$routes;dns=$dns;services=$services;processes=$processes;owned_firewall_rules=$firewall}|ConvertTo-Json -Compress -Depth 8`

func captureWindows(ctx context.Context, nonce string) (fixtureproto.Snapshot, error) {
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsCaptureScript)
	command.Env = append(os.Environ(), "FIXTURE_OBSERVATION_NONCE="+nonce)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fixtureproto.Snapshot{}, fmt.Errorf("capture Windows state: %w", err)
	}
	var snapshot fixtureproto.Snapshot
	decoder := json.NewDecoder(&output)
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
