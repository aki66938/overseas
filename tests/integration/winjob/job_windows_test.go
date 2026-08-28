//go:build windows

package winjob

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestRunKillsAndQuiescesCompleteDescendantTreeOnTimeout(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_, err := Run(ctx, os.Args[0], []string{"-test.run=TestWinJobHelperProcess"}, append(os.Environ(), "WINJOB_HELPER=parent", "WINJOB_PID_FILE="+pidFile), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		debug, _ := os.ReadFile(pidFile)
		t.Fatalf("Run() = %v, want deadline (helper=%s)", err, debug)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(string(data))
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	status, err := windows.WaitForSingleObject(handle, 2_000)
	if err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("descendant still alive after Run return: wait=%d err=%v", status, err)
	}
}

func TestWinJobHelperProcess(t *testing.T) {
	mode := os.Getenv("WINJOB_HELPER")
	if mode == "" {
		return
	}
	if mode == "parent" {
		_ = os.Setenv("WINJOB_HELPER", "child")
		command := exec.Command(os.Args[0], "-test.run=TestWinJobHelperProcess")
		if err := command.Start(); err != nil {
			_ = os.WriteFile(os.Getenv("WINJOB_PID_FILE"), []byte(err.Error()), 0600)
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("WINJOB_PID_FILE"), []byte(strconv.Itoa(command.Process.Pid)), 0600); err != nil {
			os.Exit(3)
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}
