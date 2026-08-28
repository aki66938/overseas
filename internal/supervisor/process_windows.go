//go:build windows

// Package supervisor provides fail-closed Windows child-process supervision.
package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ErrUnsupported      = errors.New("process supervision is unsupported on this platform")
	ErrAlreadyStarted   = errors.New("process has already been started")
	ErrNotStarted       = errors.New("process has not been started")
	ErrReadyTimeout     = errors.New("process readiness timed out")
	ErrUnsafePath       = errors.New("executable and config paths must be absolute, regular, and non-reparse")
	ErrNoReadinessProbe = errors.New("configuration has no deterministic readiness probe")
)

// ExitError reports an unexpected child exit without including command-line,
// configuration, or log content.
type ExitError struct {
	Code        int
	BeforeReady bool
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("supervised process exited unexpectedly with code %d", e.Code)
}

// Process supervises one process tree. A Process is single-use; this prevents
// stale state from one tunnel lifecycle being reused for another.
type Process struct {
	ReadyTimeout time.Duration
	StopTimeout  time.Duration
	ReadyProbe   func(context.Context) error
	LogWriter    io.Writer
	Secrets      []string
	MaxLogBytes  int

	mu       sync.Mutex
	cmd      *exec.Cmd
	job      windows.Handle
	done     chan struct{}
	waitErr  error
	started  bool
	ready    bool
	stopping bool
	redactor *streamRedactor
}

// Start launches exe directly with exactly "run -c <absolute-config>". It
// never invokes a shell. The executable must have been verified by the caller
// before Start; Start additionally rejects ambiguous or reparse-point paths.
func (p *Process) Start(ctx context.Context, exe, config string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return ErrAlreadyStarted
	}
	if err := validateLaunchPath(exe); err != nil {
		return ErrUnsafePath
	}
	if err := validateLaunchPath(config); err != nil {
		return ErrUnsafePath
	}

	probe := p.ReadyProbe
	if probe == nil {
		probe = interfaceProbeFromConfig(config)
		p.ReadyProbe = probe
	}
	logLimit := p.MaxLogBytes
	if logLimit <= 0 {
		logLimit = 64 * 1024
	}
	p.redactor = newStreamRedactor(p.LogWriter, p.Secrets, logLimit)

	job, err := createKillOnCloseJob()
	if err != nil {
		return fmt.Errorf("start supervised process: create job: %w", err)
	}
	cmd := exec.Command(exe, "run", "-c", config)
	cmd.Stdout = p.redactor
	cmd.Stderr = p.redactor
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		p.redactor.Flush()
		return fmt.Errorf("start supervised process: launch: %w", err)
	}
	processHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, processHandle)
		_ = windows.CloseHandle(processHandle)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = windows.CloseHandle(job)
		p.redactor.Flush()
		return fmt.Errorf("start supervised process: assign job: %w", err)
	}

	p.cmd = cmd
	p.job = job
	p.done = make(chan struct{})
	p.started = true
	go p.waitLoop()
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = p.Stop(context.Background())
			case <-p.done:
			}
		}()
	}
	return nil
}

// Ready waits for the configured local readiness probe. If readiness is not
// established in time, it terminates the whole job before returning.
func (p *Process) Ready(ctx context.Context) error {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return ErrNotStarted
	}
	if p.ready {
		p.mu.Unlock()
		return nil
	}
	probe := p.ReadyProbe
	done := p.done
	timeout := p.ReadyTimeout
	p.mu.Unlock()
	if probe == nil {
		p.terminateForFailure()
		return ErrNoReadinessProbe
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		if err := probe(readyCtx); err == nil {
			p.mu.Lock()
			select {
			case <-done:
				err := p.waitErr
				p.mu.Unlock()
				return err
			default:
				p.ready = true
				p.mu.Unlock()
				return nil
			}
		}
		select {
		case <-done:
			return p.Wait()
		case <-readyCtx.Done():
			p.terminateForFailure()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrReadyTimeout
		case <-ticker.C:
		}
	}
}

// Stop requests a console control break, then escalates to terminating the
// kill-on-close job after StopTimeout. It is idempotent after a controlled stop.
func (p *Process) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return nil
	}
	done := p.done
	if p.stopping {
		p.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-done:
		err := p.waitErr
		p.mu.Unlock()
		return err
	default:
	}
	p.stopping = true
	pid := p.cmd.Process.Pid
	grace := p.StopTimeout
	p.mu.Unlock()
	if grace <= 0 {
		grace = 3 * time.Second
	}

	_ = windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid))
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		p.terminateJob()
	case <-ctx.Done():
		p.terminateJob()
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return errors.New("supervised process did not exit after job termination")
	}
}

// Wait waits for the supervised process and reports an unexpected exit as an
// ExitError. Controlled termination returns nil.
func (p *Process) Wait() error {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return ErrNotStarted
	}
	done := p.done
	p.mu.Unlock()
	<-done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waitErr
}

func (p *Process) waitLoop() {
	err := p.cmd.Wait()
	p.redactor.Flush()

	p.mu.Lock()
	job := p.job
	p.job = 0
	if !p.stopping {
		code := 0
		if p.cmd.ProcessState != nil {
			code = p.cmd.ProcessState.ExitCode()
		}
		p.waitErr = &ExitError{Code: code, BeforeReady: !p.ready}
	} else {
		p.waitErr = nil
	}
	_ = err // ExitError deliberately exposes only sanitized exit state.
	close(p.done)
	p.mu.Unlock()
	if job != 0 {
		_ = windows.CloseHandle(job)
	}
}

func (p *Process) terminateForFailure() {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return
	}
	p.stopping = true
	done := p.done
	p.mu.Unlock()
	p.terminateJob()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

func (p *Process) terminateJob() {
	p.mu.Lock()
	job := p.job
	p.mu.Unlock()
	if job != 0 {
		_ = windows.TerminateJobObject(job, 1)
	}
}

func createKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func validateLaunchPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUnsafePath
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrUnsafePath
	}
	attributes, err := windows.GetFileAttributes(pathUTF16)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUnsafePath
	}
	return nil
}

func interfaceProbeFromConfig(path string) func(context.Context) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg struct {
		Inbounds []struct {
			Type          string `json:"type"`
			InterfaceName string `json:"interface_name"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return nil
	}
	name := ""
	for _, inbound := range cfg.Inbounds {
		if inbound.Type == "tun" && inbound.InterfaceName != "" {
			name = inbound.InterfaceName
			break
		}
	}
	if name == "" {
		return nil
	}
	return func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range interfaces {
			if iface.Name == name {
				return nil
			}
		}
		return errors.New("expected tunnel interface is not present")
	}
}

type streamRedactor struct {
	mu        sync.Mutex
	dst       io.Writer
	secrets   [][]byte
	pending   []byte
	written   int
	maxOutput int
}

func newStreamRedactor(dst io.Writer, secrets []string, maxOutput int) *streamRedactor {
	if dst == nil {
		dst = io.Discard
	}
	r := &streamRedactor{dst: dst, maxOutput: maxOutput}
	for _, secret := range secrets {
		if secret != "" {
			r.secrets = append(r.secrets, []byte(secret))
		}
	}
	return r
}

func (r *streamRedactor) Write(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = append(r.pending, data...)
	r.process(false)
	return len(data), nil
}

func (r *streamRedactor) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.process(true)
}

func (r *streamRedactor) process(final bool) {
	var output []byte
	for len(r.pending) != 0 {
		matched := false
		for _, secret := range r.secrets {
			if bytes.HasPrefix(r.pending, secret) {
				output = append(output, "[REDACTED]"...)
				r.pending = r.pending[len(secret):]
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if !final && r.couldStartSecret(r.pending) {
			break
		}
		output = append(output, r.pending[0])
		r.pending = r.pending[1:]
	}
	r.emit(output)
}

func (r *streamRedactor) couldStartSecret(data []byte) bool {
	for _, secret := range r.secrets {
		if len(data) < len(secret) && bytes.HasPrefix(secret, data) {
			return true
		}
	}
	return false
}

func (r *streamRedactor) emit(data []byte) {
	remaining := r.maxOutput - r.written
	if remaining <= 0 {
		return
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	_, _ = r.dst.Write(data)
	r.written += len(data)
}
