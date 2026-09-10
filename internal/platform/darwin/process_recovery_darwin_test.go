//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCoreGateEOFNeverExecutes(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w.Close()
	executed := false
	if err := awaitCoreGate(r, func() error { executed = true; return nil }); err == nil {
		t.Fatal("EOF accepted")
	}
	if executed {
		t.Fatal("core executed after parent death")
	}
}
func TestCoreGateRequiresExactRelease(t *testing.T) {
	for _, value := range []byte{0, 'G'} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte{value})
		w.Close()
		executed := false
		err = awaitCoreGate(r, func() error { executed = true; return nil })
		r.Close()
		if (value == 'G') != executed || (err == nil) != (value == 'G') {
			t.Fatalf("release=%d executed=%v err=%v", value, executed, err)
		}
	}
}
func TestRecoveryNeverSignalsDifferentBootOrIdentity(t *testing.T) {
	record := coreOwnership{Version: 1, Boot: "old", PID: 123, StartSec: 42, StartUsec: 1, CoreSHA256: PinnedCoreSHA256}
	calls := 0
	ops := recoveryOperations{boot: func() (string, error) { return "new", nil }, identity: func(int) (*coreOwnership, error) { t.Fatal("inspected PID from another boot"); return nil, nil }, empty: func(int) (bool, error) { t.Fatal("inspected group from another boot"); return false, nil }, signal: func(int) error { calls++; return nil }}
	if err := recoverCore(context.Background(), record, ops); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("signaled another boot")
	}
	ops.boot = func() (string, error) { return "old", nil }
	ops.identity = func(int) (*coreOwnership, error) { other := record; other.StartSec++; return &other, nil }
	if err := recoverCore(context.Background(), record, ops); err == nil {
		t.Fatal("accepted reused PID")
	}
	if calls != 0 {
		t.Fatal("signaled reused PID")
	}
}
func TestMissingLeaderWithLiveGroupFailsClosed(t *testing.T) {
	record := coreOwnership{Version: 1, Boot: "boot", PID: 123, StartSec: 42, CoreSHA256: PinnedCoreSHA256}
	calls := 0
	ops := recoveryOperations{boot: func() (string, error) { return "boot", nil }, identity: func(int) (*coreOwnership, error) { return nil, nil }, empty: func(int) (bool, error) { return false, nil }, signal: func(int) error { calls++; return nil }}
	if err := recoverCore(context.Background(), record, ops); err == nil {
		t.Fatal("accepted orphan live group")
	}
	if calls != 0 {
		t.Fatal("signaled group without leader identity")
	}
}

func TestCoreGateSubprocess(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "core-gate-fixture" {
		return
	}
	gate := os.NewFile(3, "gate")
	err := awaitCoreGate(gate, func() error { fmt.Fprintln(os.Stdout, "released"); time.Sleep(30 * time.Second); return nil })
	if err != nil {
		os.Exit(0)
	}
	os.Exit(0)
}

func TestCoreGateCrashParent(t *testing.T) {
	if os.Args[len(os.Args)-1] != "core-parent-fixture" {
		return
	}
	r, w, err := os.Pipe()
	if err != nil {
		os.Exit(2)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoreGateSubprocess$", "core-gate-fixture")
	cmd.ExtraFiles = []*os.File{r}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if cmd.Start() != nil {
		os.Exit(2)
	}
	r.Close()
	fmt.Fprintln(os.Stdout, cmd.Process.Pid)
	time.Sleep(30 * time.Second)
	w.Close()
	os.Exit(0)
}

func TestActualParentCrashClosesUnreleasedGate(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoreGateCrashParent$", "core-parent-fixture")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for {
		empty, err := groupEmptyOfLiveProcesses(pid)
		if err != nil {
			t.Fatal(err)
		}
		if empty {
			return
		}
		if time.Now().After(deadline) {
			unix.Kill(-pid, unix.SIGKILL)
			t.Fatal("unreleased child survived actual parent death")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPersistentGateRecordsBeforeReleaseAndRemovesAfterProof(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root owned journal fixture")
	}
	for _, registrationFails := range []bool{false, true} {
		t.Run(fmt.Sprint(registrationFails), func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			os.Chmod(directory, 0700)
			binary, err := os.ReadFile(os.Args[0])
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(binary)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			outputR, outputW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer outputR.Close()
			defer outputW.Close()
			s, _ := NewProcessSupervisorForVerifiedCore(hex.EncodeToString(digest[:]))
			s.command = func(string, string) *exec.Cmd {
				c := exec.Command(os.Args[0], "-test.run=^TestCoreGateSubprocess$", "core-gate-fixture")
				c.ExtraFiles = []*os.File{r}
				c.Stdout = outputW
				return c
			}
			s.afterStart = func(c *exec.Cmd) error {
				if registrationFails {
					return errors.New("injected durable registration failure")
				}
				boot, err := bootID()
				if err != nil {
					return err
				}
				v, err := unix.SysctlKinfoProc("kern.proc.pid", c.Process.Pid)
				if err != nil {
					return err
				}
				record := coreOwnership{Version: 1, Boot: boot, PID: c.Process.Pid, StartSec: v.Proc.P_starttime.Sec, StartUsec: int64(v.Proc.P_starttime.Usec), CoreSHA256: PinnedCoreSHA256}
				if err = saveCoreRecord(directory, &record); err != nil {
					return err
				}
				if saved, err := loadCoreRecord(directory); err != nil || saved == nil {
					return errors.New("ownership not durable before release")
				}
				_, err = w.Write([]byte{'G'})
				return err
			}
			s.afterProvenStop = func() error { return removeCoreRecord(directory) }
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			p, result := s.Start(ctx, os.Args[0], "/unused-fixture-config")
			if registrationFails {
				if result.Err == nil || !result.TerminationProven {
					t.Fatalf("registration failure result: %+v", result)
				}
				outputW.Close()
				data, _ := io.ReadAll(outputR)
				if len(data) != 0 {
					t.Fatalf("unregistered helper executed: %s", data)
				}
			} else {
				if result.Err != nil {
					t.Fatal(result.Err)
				}
				line, err := bufio.NewReader(outputR).ReadString('\n')
				if err != nil || line != "released\n" {
					t.Fatalf("release=%q err=%v", line, err)
				}
				if stopped := p.Stop(ctx); !stopped.Proven {
					t.Fatalf("stop unproven: %+v", stopped)
				}
			}
			if record, err := loadCoreRecord(directory); err != nil || record != nil {
				t.Fatalf("journal retained after proof: %+v %v", record, err)
			}
		})
	}
}
