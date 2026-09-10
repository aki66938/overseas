//go:build darwin

package darwin

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestProcessHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-3] != "--group-helper" {
		return
	}
	mode, path := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	if mode == "ignore" {
		signal.Ignore(syscall.SIGTERM)
	}
	child := exec.Command("/bin/sleep", "30")
	if e := child.Start(); e != nil {
		os.Exit(2)
	}
	if e := os.WriteFile(path, []byte(strconv.Itoa(child.Process.Pid)), 0600); e != nil {
		os.Exit(3)
	}
	if mode == "exit" {
		os.Exit(0)
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestAttestedProcessGroupIncludesChildren(t *testing.T) {
	for _, mode := range []string{"wait", "exit", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			data, e := os.ReadFile(exe)
			if e != nil {
				t.Fatal(e)
			}
			s, e := NewProcessSupervisorForVerifiedCore(fmt.Sprintf("%x", sha256.Sum256(data)))
			if e != nil {
				t.Fatal(e)
			}
			pidfile := filepath.Join(t.TempDir(), "pid")
			s.command = func(string, string) *exec.Cmd {
				return exec.Command(exe, "-test.run=^TestProcessHelper$", "--", "--group-helper", mode, pidfile)
			}
			p, r := s.Start(context.Background(), exe, "/tmp/config")
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			defer p.Stop(ctx)
			var childPID int
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				data, e := os.ReadFile(pidfile)
				if e == nil {
					childPID, _ = strconv.Atoi(string(data))
					if childPID > 0 {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if childPID == 0 {
				t.Fatal("helper did not start child")
			}
			if mode != "exit" {
				out := p.Stop(ctx)
				if !out.Proven {
					t.Fatalf("group not proven empty: %+v", out)
				}
			} else {
				select {
				case out := <-p.Done():
					if !out.Proven {
						t.Fatalf("leader exit child cleanup unproven: %+v", out)
					}
				case <-ctx.Done():
					t.Fatal("leader exit timed out")
				}
			}
			if alive, e := leaderAlive(childPID); e == nil && alive {
				t.Fatal("owned child survived cleanup")
			}
		})
	}
}

func TestAttestedHashMismatchRejectsLaunch(t *testing.T) {
	s, e := NewProcessSupervisorForVerifiedCore(fmt.Sprintf("%064d", 0))
	if e != nil {
		t.Fatal(e)
	}
	p, r := s.Start(context.Background(), "/bin/sleep", "/tmp/config")
	if p != nil || r.Err == nil || !r.TerminationProven {
		t.Fatal("hash mismatch launched child")
	}
}

func TestProcessCanceledStartCreatesNothing(t *testing.T) {
	s := NewProcessSupervisor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, r := s.Start(ctx, "/bin/sleep", "/tmp/config")
	if p != nil || r.Err == nil || !r.TerminationProven {
		t.Fatalf("%v %+v", p, r)
	}
}
func TestProcessStopIdempotentAndContextIndependent(t *testing.T) {
	s := NewProcessSupervisor()
	s.command = func(string, string) *exec.Cmd { return exec.Command("/bin/sleep", "30") }
	ctx, cancel := context.WithCancel(context.Background())
	p, r := s.Start(ctx, "/bin/sleep", "/tmp/config")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	cancel()
	if e := p.Ready(context.Background()); e != nil {
		t.Fatal(e)
	}
	stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	a := p.Stop(stopCtx)
	b := p.Stop(stopCtx)
	if a.Proven || b.Proven {
		t.Fatal("unattested process tree claimed proven")
	}
	select {
	case <-p.Done():
	case <-time.After(time.Second):
		t.Fatal("no terminal result")
	}
	if _, ok := <-p.Done(); ok {
		t.Fatal("multiple terminal results")
	}
}
func TestProcessExitBeforeReady(t *testing.T) {
	s := NewProcessSupervisor()
	s.command = func(string, string) *exec.Cmd { return exec.Command("/usr/bin/true") }
	p, r := s.Start(context.Background(), "/usr/bin/true", "/tmp/config")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	select {
	case outcome := <-p.Done():
		if outcome.Proven {
			t.Fatal("unattested proof")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exit not observed")
	}
	if e := p.Ready(context.Background()); e == nil {
		t.Fatal("exited child ready")
	}
}
