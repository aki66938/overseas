//go:build windows

package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
	p := &Process{ReadyTimeout: 150 * time.Millisecond, StopTimeout: 50 * time.Millisecond, ReadyProbe: fileProbe(ready)}
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
	p := &Process{ReadyTimeout: time.Second, ReadyProbe: fileProbe(ready)}
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
	p := &Process{ReadyTimeout: time.Second, StopTimeout: 100 * time.Millisecond, ReadyProbe: fileProbe(ready)}
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
	p := &Process{
		ReadyTimeout: time.Second,
		StopTimeout:  100 * time.Millisecond,
		ReadyProbe:   fileProbe(ready),
		LogWriter:    &logs,
		Secrets:      []string{secret},
		MaxLogBytes:  1024,
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
	p := &Process{ReadyTimeout: time.Second, StopTimeout: 100 * time.Millisecond, ReadyProbe: fileProbe(ready)}
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start error = %v, want ErrAlreadyStarted", err)
	}
}

func TestStartRequiresAbsoluteRegularPaths(t *testing.T) {
	p := &Process{}
	if err := p.Start(context.Background(), "fakeconnect.exe", `relative\config.json`); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Start error = %v, want ErrUnsafePath", err)
	}
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
