//go:build darwin

package darwin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"corp.example/overseas-access-gateway/internal/agent"
	"golang.org/x/sys/unix"
)

// ProcessSupervisor launches a child in a fresh process group. The default
// constructor deliberately cannot attest that an arbitrary binary's descendants
// remain in that group, and therefore never claims process-tree termination.
type ProcessSupervisor struct {
	command         func(string, string) *exec.Cmd
	groupSHA256     string
	afterStart      func(*exec.Cmd) error
	afterProvenStop func() error
}

var _ agent.ProcessSupervisor = (*ProcessSupervisor)(nil)

func NewProcessSupervisor() *ProcessSupervisor {
	return &ProcessSupervisor{command: func(exe, config string) *exec.Cmd { return exec.Command(exe, "run", "-c", config) }}
}

// NewProcessSupervisorForVerifiedCore is an explicit deployment attestation:
// the supplied SHA256 identifies the reviewed fixed sing-box build AND its
// reviewed system helpers never detach/escape the inherited process group.
// The caller must establish that source contract before using this constructor.
// This is not a generic guarantee for arbitrary executables or plugins.
func NewProcessSupervisorForVerifiedCore(digest string) (*ProcessSupervisor, error) {
	v, e := hex.DecodeString(digest)
	if e != nil || len(v) != sha256.Size {
		return nil, errors.New("expected fixed core SHA256")
	}
	s := NewProcessSupervisor()
	s.groupSHA256 = hex.EncodeToString(v)
	return s, nil
}
func (s *ProcessSupervisor) Start(ctx context.Context, exe, config string) (agent.ProcessInstance, agent.ProcessStartResult) {
	fail := func(e error) (agent.ProcessInstance, agent.ProcessStartResult) {
		return nil, agent.ProcessStartResult{Err: e, TerminationProven: true}
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	if !filepath.IsAbs(exe) || !filepath.IsAbs(config) {
		return fail(errors.New("absolute verified executable/config paths required"))
	}
	if s.groupSHA256 != "" {
		f, e := os.Open(exe)
		if e != nil {
			return fail(e)
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		f.Close()
		if e != nil {
			return fail(e)
		}
		if hex.EncodeToString(h.Sum(nil)) != s.groupSHA256 {
			return fail(errors.New("core does not match attested process-group build"))
		}
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	cmd := s.command(exe, config)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if e := cmd.Start(); e != nil {
		return fail(e)
	}
	p := &processInstance{cmd: cmd, pid: cmd.Process.Pid, attested: s.groupSHA256 != "", afterProvenStop: s.afterProvenStop, stop: make(chan struct{}), finished: make(chan struct{}), done: make(chan agent.ProcessTermination, 1)}
	var registrationErr error
	if s.afterStart != nil {
		registrationErr = s.afterStart(cmd)
	}
	go p.supervise()
	if registrationErr != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		r := p.Stop(cleanup)
		return p, agent.ProcessStartResult{Err: errors.Join(registrationErr, r.Err), TerminationProven: r.Proven}
	}
	if e := ctx.Err(); e != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		r := p.Stop(cleanup)
		return p, agent.ProcessStartResult{Err: errors.Join(e, r.Err), TerminationProven: r.Proven}
	}
	return p, agent.ProcessStartResult{}
}

type processInstance struct {
	cmd             *exec.Cmd
	pid             int
	attested        bool
	stop            chan struct{}
	finished        chan struct{}
	done            chan agent.ProcessTermination
	once            sync.Once
	result          agent.ProcessTermination
	mu              sync.Mutex
	reaping         bool
	afterProvenStop func() error
}

func (p *processInstance) Done() <-chan agent.ProcessTermination { return p.done }

// Darwin SZOMB is 5 (sys/proc.h). A zombie cannot execute or fork. The child
// remains unreaped until all signaling and group inspection finish, reserving
// its PID and hence this generation's PGID against reuse by unrelated jobs.
const darwinZombie = 5

func leaderAlive(pid int) (bool, error) {
	v, e := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if e != nil {
		return false, fmt.Errorf("inspect owned leader: %w", e)
	}
	if v.Proc.P_pid != int32(pid) {
		return false, errors.New("owned process identity missing")
	}
	return v.Proc.P_stat != darwinZombie, nil
}
func groupEmptyOfLiveProcesses(pid int) (bool, error) {
	members, e := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pid)
	if e != nil {
		return false, fmt.Errorf("inspect owned process group: %w", e)
	}
	for _, v := range members {
		if v.Proc.P_stat != darwinZombie {
			return false, nil
		}
	}
	return true, nil
}
func (p *processInstance) Ready(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	if p.reaping {
		return errors.New("core terminating")
	}
	select {
	case <-p.finished:
		return errors.New("core exited")
	default:
	}
	alive, e := leaderAlive(p.pid)
	if e != nil {
		return e
	}
	if !alive {
		return errors.New("core exited before readiness")
	}
	return nil
}
func (p *processInstance) Stop(ctx context.Context) agent.ProcessTermination {
	p.once.Do(func() { close(p.stop) })
	select {
	case <-p.finished:
		return p.result
	case <-ctx.Done():
		return agent.ProcessTermination{Err: ctx.Err(), Proven: false}
	}
}
func (p *processInstance) supervise() {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	var monitorErr error
	watching := true
	for watching {
		select {
		case <-p.stop:
			watching = false
		case <-tick.C:
			alive, e := leaderAlive(p.pid)
			if e != nil {
				monitorErr = e
				watching = false
			} else if !alive {
				watching = false
			}
		}
	}
	signal := func(sig unix.Signal) error {
		e := unix.Kill(-p.pid, sig)
		if errors.Is(e, unix.ESRCH) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("signal owned process group %s: %w", sig, e)
		}
		return nil
	}
	emptyBeforeTerm, _ := groupEmptyOfLiveProcesses(p.pid)
	var termErr error
	if !emptyBeforeTerm {
		termErr = signal(unix.SIGTERM)
	}
	// Keep the leader unreaped even on natural exit; helpers must also terminate.
	grace := time.NewTimer(500 * time.Millisecond)
	<-grace.C
	// Darwin can return EPERM when signaling a group containing only zombies.
	// Inspect first rather than sending an unnecessary escalation or treating
	// an error as proof. An audit error still leads to a termination attempt.
	emptyBeforeKill, _ := groupEmptyOfLiveProcesses(p.pid)
	var killErr error
	if !emptyBeforeKill {
		killErr = signal(unix.SIGKILL)
	}
	deadline := time.Now().Add(2 * time.Second)
	empty := false
	var auditErr error
	for {
		empty, auditErr = groupEmptyOfLiveProcesses(p.pid)
		if auditErr != nil || empty || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !empty && auditErr == nil {
		auditErr = errors.New("owned process group still has live members")
	}
	// Wait normally completes immediately after the audit. A pathological kernel
	// process state cannot stall Stop indefinitely: publish no proof at the bound.
	p.mu.Lock()
	p.reaping = true
	p.mu.Unlock()
	wait := make(chan error, 1)
	go func() { wait <- p.cmd.Wait() }()
	var waitErr error
	waited := false
	select {
	case waitErr = <-wait:
		waited = true
	case <-time.After(500 * time.Millisecond):
		waitErr = errors.New("owned core reap timeout")
	}
	p.result = agent.ProcessTermination{Err: errors.Join(monitorErr, termErr, killErr, auditErr, waitErr), Proven: p.attested && empty && auditErr == nil && termErr == nil && killErr == nil && waited}
	if p.result.Proven && p.afterProvenStop != nil {
		if err := p.afterProvenStop(); err != nil {
			p.result.Proven = false
			p.result.Err = errors.Join(p.result.Err, err)
		}
	}
	if !p.attested {
		p.result.Err = errors.Join(p.result.Err, fmt.Errorf("process-group containment not attested for this executable"))
	}
	p.done <- p.result
	close(p.done)
	close(p.finished)
}
