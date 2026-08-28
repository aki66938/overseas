//go:build windows

package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

var fakeConnectEXE string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fakeconnect-test-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	fakeConnectEXE = filepath.Join(dir, "fakeconnect.exe")
	_, sourceFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go.exe"), "build", "-o", fakeConnectEXE, "./tests/integration/fakeconnect")
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build fakeconnect: %v\n%s", err, output)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestReadyTimeoutTerminatesProcess(t *testing.T) {
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "hang-on-stop", "suppress_ready": true})
	p := verifiedProcess(&Process{ReadyTimeout: 150 * time.Millisecond, StopTimeout: 50 * time.Millisecond, ReadyProbe: fileProbe(ready)})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}

	err := p.Ready(context.Background())
	if !errors.Is(err, ErrReadyTimeout) {
		t.Fatalf("Ready error = %v, want ErrReadyTimeout", err)
	}
	if err := p.Wait(); err != nil {
		t.Fatalf("Wait after supervisor termination = %v, want nil", err)
	}
}

func TestExitBeforeReadyReturnsTypedFailure(t *testing.T) {
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "exit-before-ready"})
	p := verifiedProcess(&Process{ReadyTimeout: time.Second, ReadyProbe: fileProbe(ready)})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}

	err := p.Ready(context.Background())
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Ready error = %T %v, want *ExitError", err, err)
	}
	if exitErr.Code != 23 || !exitErr.BeforeReady {
		t.Fatalf("ExitError = %+v, want code 23 before readiness", exitErr)
	}
	if err := p.Wait(); !errors.As(err, &exitErr) {
		t.Fatalf("Wait error = %T %v, want *ExitError", err, err)
	}
}

func TestStopEscalatesAndKillsDescendants(t *testing.T) {
	childPIDFile := filepath.Join(t.TempDir(), "child.pid")
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "hang-on-stop", "child_pid_file": childPIDFile})
	p := verifiedProcess(&Process{ReadyTimeout: time.Second, StopTimeout: 100 * time.Millisecond, ReadyProbe: fileProbe(ready)})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	childPID := waitPIDFile(t, childPIDFile)
	t.Cleanup(func() {
		if process, err := os.FindProcess(int(childPID)); err == nil {
			_ = process.Kill()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	startedStop := time.Now()
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedStop); elapsed < 80*time.Millisecond {
		t.Fatalf("Stop returned after %v without waiting for graceful timeout", elapsed)
	}
	if !waitProcessExit(childPID, time.Second) {
		t.Fatalf("descendant PID %d survived job termination", childPID)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop = %v, want idempotent success", err)
	}
}

func TestLogsRedactSecretsAndStayBounded(t *testing.T) {
	const secret = "credential-value-never-log"
	var logs bytes.Buffer
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "write-secret", "secret": secret, "log_repeat": 200})
	p := verifiedProcess(&Process{
		ReadyTimeout: time.Second,
		StopTimeout:  100 * time.Millisecond,
		ReadyProbe:   fileProbe(ready),
		LogWriter:    &logs,
		Secrets:      []string{secret},
		MaxLogBytes:  1024,
	})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("captured logs contain configured secret")
	}
	if !strings.Contains(logs.String(), "[REDACTED]") {
		t.Fatalf("captured logs do not contain redaction marker: %q", logs.String())
	}
	if logs.Len() > 1024 {
		t.Fatalf("captured %d log bytes, limit is 1024", logs.Len())
	}
}

func TestSecondStartIsRejected(t *testing.T) {
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "ready"})
	p := verifiedProcess(&Process{ReadyTimeout: time.Second, StopTimeout: 100 * time.Millisecond, ReadyProbe: fileProbe(ready)})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start error = %v, want ErrAlreadyStarted", err)
	}
}

func TestStartRequiresAbsoluteRegularPaths(t *testing.T) {
	p := verifiedProcess(&Process{})
	if err := p.Start(context.Background(), "fakeconnect.exe", `relative\config.json`); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Start error = %v, want ErrUnsafePath", err)
	}
}

func TestStartRequiresExecutableVerifier(t *testing.T) {
	cfg, _ := writeFakeConfig(t, map[string]any{"mode": "ready"})
	p := &Process{}
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); !errors.Is(err, ErrVerifierRequired) {
		t.Fatalf("Start error = %v, want ErrVerifierRequired", err)
	}
}

func TestStartRejectsFailedExecutableVerificationBeforeLaunch(t *testing.T) {
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "ready"})
	verificationErr := errors.New("verification rejected executable")
	p := &Process{VerifyExecutable: func(string) error { return verificationErr }}
	err := p.Start(context.Background(), fakeConnectEXE, cfg)
	if !errors.Is(err, verificationErr) {
		t.Fatalf("Start error = %v, want verification failure", err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(ready); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("process executed despite verifier failure: %v", err)
	}
}

func TestVerifierRunsInsideSuspendedLaunchBoundary(t *testing.T) {
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "ready"})
	verificationCalled := false
	ops := defaultProcessOps
	realLaunch := ops.launchSuspended
	ops.launchSuspended = func(exe, config string, output io.Writer, verify func(string) error) (*nativeProcess, error) {
		if verificationCalled {
			return nil, errors.New("verifier ran before entering native launch boundary")
		}
		proc, err := realLaunch(exe, config, output, verify)
		if err == nil && !verificationCalled {
			return nil, errors.New("native launch did not invoke verifier")
		}
		return proc, err
	}
	p := &Process{
		VerifyExecutable: func(string) error {
			verificationCalled = true
			return nil
		},
		ReadyTimeout: time.Second,
		StopTimeout:  50 * time.Millisecond,
		ReadyProbe:   fileProbe(ready),
		ops:          &ops,
	}
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAssignFailureCannotExecuteRootOrEscapingDescendant(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	escaped := filepath.Join(dir, "escaped")
	cfg, _ := writeFakeConfig(t, map[string]any{
		"mode":         "escape-immediately",
		"started_file": started,
		"escaped_file": escaped,
	})
	assignErr := errors.New("injected assign failure")
	ops := defaultProcessOps
	ops.assignProcessToJob = func(windows.Handle, windows.Handle) error { return assignErr }
	p := verifiedProcess(&Process{ops: &ops})

	if err := p.Start(context.Background(), fakeConnectEXE, cfg); !errors.Is(err, assignErr) {
		t.Fatalf("Start error = %v, want assign failure", err)
	}
	assertFilesRemainAbsent(t, started, escaped)
}

func TestResumeFailureCannotExecuteRootOrEscapingDescendant(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	escaped := filepath.Join(dir, "escaped")
	cfg, _ := writeFakeConfig(t, map[string]any{
		"mode":         "escape-immediately",
		"started_file": started,
		"escaped_file": escaped,
	})
	resumeErr := errors.New("injected resume failure")
	ops := defaultProcessOps
	ops.resumeThread = func(windows.Handle) error { return resumeErr }
	p := verifiedProcess(&Process{ops: &ops})

	if err := p.Start(context.Background(), fakeConnectEXE, cfg); !errors.Is(err, resumeErr) {
		t.Fatalf("Start error = %v, want resume failure", err)
	}
	assertFilesRemainAbsent(t, started, escaped)
}

func TestResumeCleanupClosesJobBeforeWaitWhenTerminateFails(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	cfg, _ := writeFakeConfig(t, map[string]any{"mode": "escape-immediately", "started_file": started})
	resumeErr := errors.New("injected resume failure")
	terminateErr := errors.New("injected terminate failure")
	waitErr := errors.New("injected wait before fallback")
	var events []string
	var eventsMu sync.Mutex
	record := func(event string) {
		eventsMu.Lock()
		events = append(events, event)
		eventsMu.Unlock()
	}
	ops := defaultProcessOps
	realClose := ops.closeJob
	ops.resumeThread = func(windows.Handle) error { return resumeErr }
	ops.terminateJob = func(windows.Handle, uint32) error {
		record("terminate")
		return terminateErr
	}
	ops.closeJob = func(job windows.Handle) error {
		record("close")
		return realClose(job)
	}
	ops.waitProcess = func(windows.Handle, time.Duration) error {
		record("wait")
		return waitErr
	}
	p := verifiedProcess(&Process{ops: &ops})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); !errors.Is(err, resumeErr) {
		t.Fatalf("Start error = %v, want resume failure", err)
	}
	assertFilesRemainAbsent(t, started)
	eventsMu.Lock()
	got := strings.Join(events, ",")
	eventsMu.Unlock()
	if !strings.HasPrefix(got, "terminate,close,wait") {
		t.Fatalf("cleanup order = %q, want terminate,close,wait", got)
	}
}

func TestUnexpectedExitClosesJobBeforeWaitingForDescendantLogs(t *testing.T) {
	childPIDFile := filepath.Join(t.TempDir(), "child.pid")
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "exit-with-descendant", "child_pid_file": childPIDFile})
	p := verifiedProcess(&Process{ReadyTimeout: time.Second, ReadyProbe: fileProbe(ready)})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	childPID := waitPIDFile(t, childPIDFile)
	t.Cleanup(func() {
		if process, err := os.FindProcess(int(childPID)); err == nil {
			_ = process.Kill()
		}
	})
	result := make(chan error, 1)
	go func() { result <- p.Ready(context.Background()) }()
	select {
	case err := <-result:
		var exitErr *ExitError
		if !errors.As(err, &exitErr) || exitErr.Code != 31 {
			t.Fatalf("Ready error = %T %v, want exit code 31", err, err)
		}
	case <-time.After(time.Second):
		forceCloseJob(p)
		t.Fatal("unexpected-exit handling waited on descendant-held logs before closing the job")
	}
	if !waitProcessExit(childPID, time.Second) {
		t.Fatalf("descendant PID %d survived unexpected-root cleanup", childPID)
	}
}

func TestReadyTimeoutIsBoundedWhenProbeIgnoresContext(t *testing.T) {
	cfg, _ := writeFakeConfig(t, map[string]any{"mode": "hang-on-stop"})
	probeEntered := make(chan struct{})
	p := verifiedProcess(&Process{
		ReadyTimeout: 100 * time.Millisecond,
		StopTimeout:  50 * time.Millisecond,
		ReadyProbe: func(context.Context) error {
			close(probeEntered)
			select {}
		},
	})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- p.Ready(context.Background()) }()
	select {
	case <-probeEntered:
	case <-time.After(time.Second):
		t.Fatal("readiness probe did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrReadyTimeout) {
			t.Fatalf("Ready error = %v, want ErrReadyTimeout", err)
		}
	case <-time.After(time.Second):
		_ = p.Stop(context.Background())
		t.Fatal("Ready blocked on a context-ignoring probe")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Stop(stopCtx); err != nil {
		t.Fatalf("Stop after readiness cleanup = %v", err)
	}
}

func TestReadyReportsTerminateFailureAfterCloseFallback(t *testing.T) {
	terminateErr := errors.New("injected terminate-job failure")
	ops := defaultProcessOps
	ops.terminateJob = func(windows.Handle, uint32) error { return terminateErr }
	p := startCleanupFaultProcess(t, &ops)

	err := readyResultWithin(t, p, time.Second)
	assertCleanupError(t, err, terminateErr)
	assertStopReturnsCleanupError(t, p, terminateErr)
}

func TestReadyReportsJobCloseFailure(t *testing.T) {
	closeErr := errors.New("injected close-job failure")
	ops := defaultProcessOps
	ops.closeJob = func(job windows.Handle) error {
		_ = windows.CloseHandle(job)
		return closeErr
	}
	p := startCleanupFaultProcess(t, &ops)

	err := readyResultWithin(t, p, time.Second)
	assertCleanupError(t, err, closeErr)
	assertStopReturnsCleanupError(t, p, closeErr)
}

func TestReadyReportsTerminationWaitFailure(t *testing.T) {
	waitErr := errors.New("injected bounded-wait failure")
	ops := defaultProcessOps
	realWait := ops.waitProcess
	ops.waitProcess = func(process windows.Handle, timeout time.Duration) error {
		if timeout >= 0 {
			return waitErr
		}
		return realWait(process, timeout)
	}
	p := startCleanupFaultProcess(t, &ops)

	err := readyResultWithin(t, p, time.Second)
	assertCleanupError(t, err, waitErr)
	assertStopReturnsCleanupError(t, p, waitErr)
}

func TestReadyReportsTreeConfirmationFailure(t *testing.T) {
	treeWaitErr := errors.New("injected job-empty wait failure")
	ops := defaultProcessOps
	ops.waitJobEmpty = func(windows.Handle, time.Duration) error { return treeWaitErr }
	p := startCleanupFaultProcess(t, &ops)

	err := readyResultWithin(t, p, time.Second)
	assertCleanupError(t, err, treeWaitErr)
	assertStopReturnsCleanupError(t, p, treeWaitErr)
}

func TestStopReportsTerminateFailureAfterCloseFallback(t *testing.T) {
	terminateErr := errors.New("injected stop terminate-job failure")
	ops := defaultProcessOps
	ops.terminateJob = func(windows.Handle, uint32) error { return terminateErr }
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "hang-on-stop"})
	p := verifiedProcess(&Process{
		ReadyTimeout: time.Second,
		StopTimeout:  20 * time.Millisecond,
		ReadyProbe:   fileProbe(ready),
		ops:          &ops,
	})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopResult := make(chan error, 1)
	go func() { stopResult <- p.Stop(context.Background()) }()
	select {
	case err := <-stopResult:
		var cleanupErr *CleanupError
		if !errors.As(err, &cleanupErr) || !errors.Is(err, terminateErr) {
			t.Fatalf("Stop error = %T %v, want typed terminate cleanup failure", err, err)
		}
	case <-time.After(time.Second):
		forceCloseJob(p)
		t.Fatal("Stop did not use close fallback after terminate failure")
	}
}

func TestGracefulStopReportsJobCloseFailureAndKillsDescendant(t *testing.T) {
	closeErr := errors.New("injected graceful close-job failure")
	ops := defaultProcessOps
	realClose := ops.closeJob
	ops.closeJob = func(job windows.Handle) error {
		_ = realClose(job)
		return closeErr
	}
	p, childPID := startGracefulDescendantProcess(t, &ops)

	err := p.Stop(context.Background())
	var cleanupErr *CleanupError
	if !errors.As(err, &cleanupErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Stop error = %T %v, want typed close-job failure", err, err)
	}
	if !waitProcessExit(childPID, time.Second) {
		t.Fatalf("descendant PID %d survived graceful root exit", childPID)
	}
}

func TestGracefulStopReportsJobTreeConfirmationFailure(t *testing.T) {
	treeErr := errors.New("injected graceful job-empty failure")
	ops := defaultProcessOps
	ops.waitJobEmpty = func(windows.Handle, time.Duration) error { return treeErr }
	p, _ := startGracefulDescendantProcess(t, &ops)

	err := p.Stop(context.Background())
	var cleanupErr *CleanupError
	if !errors.As(err, &cleanupErr) || !errors.Is(err, treeErr) {
		t.Fatalf("Stop error = %T %v, want typed job-empty failure", err, err)
	}
}

func TestWaitObservesCleanupStartedAfterWaitBlocks(t *testing.T) {
	treeErr := errors.New("injected delayed job-empty failure")
	treeWaitEntered := make(chan struct{})
	releaseTreeWait := make(chan struct{})
	ops := defaultProcessOps
	ops.waitJobEmpty = func(windows.Handle, time.Duration) error {
		close(treeWaitEntered)
		<-releaseTreeWait
		return treeErr
	}
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "hang-on-stop", "suppress_ready": true})
	p := verifiedProcess(&Process{
		ReadyTimeout: 50 * time.Millisecond,
		StopTimeout:  20 * time.Millisecond,
		ReadyProbe:   fileProbe(ready),
		ops:          &ops,
	})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- p.Wait() }()
	readyResult := make(chan error, 1)
	go func() { readyResult <- p.Ready(context.Background()) }()
	select {
	case <-treeWaitEntered:
	case <-time.After(time.Second):
		t.Fatal("readiness cleanup did not reach job-empty confirmation")
	}
	select {
	case err := <-waitResult:
		close(releaseTreeWait)
		t.Fatalf("Wait returned before in-flight cleanup completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseTreeWait)
	if err := <-readyResult; !errors.Is(err, treeErr) {
		t.Fatalf("Ready error = %v, want delayed cleanup error", err)
	}
	select {
	case err := <-waitResult:
		if !errors.Is(err, treeErr) {
			t.Fatalf("Wait error = %v, want delayed cleanup error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait remained blocked after cleanup completed")
	}
}

func verifiedProcess(p *Process) *Process {
	p.VerifyExecutable = func(string) error { return nil }
	return p
}

func assertFilesRemainAbsent(t *testing.T, paths ...string) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("suspended process executed outside the job: %s: %v", path, err)
		}
	}
}

func startCleanupFaultProcess(t *testing.T, ops *processOps) *Process {
	t.Helper()
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "hang-on-stop", "suppress_ready": true})
	p := verifiedProcess(&Process{
		ReadyTimeout: 50 * time.Millisecond,
		StopTimeout:  20 * time.Millisecond,
		ReadyProbe:   fileProbe(ready),
		ops:          ops,
	})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { forceCloseJob(p) })
	return p
}

func readyResultWithin(t *testing.T, p *Process, timeout time.Duration) error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- p.Ready(context.Background()) }()
	select {
	case err := <-result:
		return err
	case <-time.After(timeout):
		forceCloseJob(p)
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatal("Ready did not return within its cleanup bound")
		return nil
	}
}

func assertCleanupError(t *testing.T, err, cause error) {
	t.Helper()
	if !errors.Is(err, ErrReadyTimeout) {
		t.Fatalf("Ready error = %v, want ErrReadyTimeout", err)
	}
	var cleanupErr *CleanupError
	if !errors.As(err, &cleanupErr) {
		t.Fatalf("Ready error = %T %v, want *CleanupError", err, err)
	}
	if !errors.Is(cleanupErr, cause) {
		t.Fatalf("CleanupError = %v, want cause %v", cleanupErr, cause)
	}
}

func assertStopReturnsCleanupError(t *testing.T, p *Process, cause error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := p.Stop(ctx); !errors.Is(err, cause) {
		t.Fatalf("Stop after failed readiness cleanup = %v, want cleanup cause", err)
	}
}

func forceCloseJob(p *Process) {
	p.mu.Lock()
	job := p.job
	p.job = 0
	p.mu.Unlock()
	if job != 0 {
		_ = windows.CloseHandle(job)
	}
}

func startGracefulDescendantProcess(t *testing.T, ops *processOps) (*Process, uint32) {
	t.Helper()
	childPIDFile := filepath.Join(t.TempDir(), "child.pid")
	cfg, ready := writeFakeConfig(t, map[string]any{
		"mode":           "graceful-with-descendant",
		"child_pid_file": childPIDFile,
	})
	p := verifiedProcess(&Process{
		ReadyTimeout: time.Second,
		StopTimeout:  500 * time.Millisecond,
		ReadyProbe:   fileProbe(ready),
		ops:          ops,
	})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	childPID := waitPIDFile(t, childPIDFile)
	t.Cleanup(func() {
		if process, err := os.FindProcess(int(childPID)); err == nil {
			_ = process.Kill()
		}
		forceCloseJob(p)
	})
	return p, childPID
}

func writeFakeConfig(t *testing.T, values map[string]any) (string, string) {
	t.Helper()
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	values["ready_file"] = ready
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, ready
}

func fileProbe(path string) func(context.Context) error {
	return func(context.Context) error {
		_, err := os.Stat(path)
		return err
	}
}

func waitPIDFile(t *testing.T, path string) uint32 {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			return uint32(pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for PID file %s", path)
	return 0
}

func processRunning(pid uint32) bool {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	result, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && result == uint32(windows.WAIT_TIMEOUT)
}

func waitProcessExit(pid uint32, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processRunning(pid) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return !processRunning(pid)
}
