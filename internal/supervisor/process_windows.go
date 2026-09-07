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
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ErrUnsupported      = errors.New("process supervision is unsupported on this platform")
	ErrVerifierRequired = errors.New("executable verifier is required")
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

// CleanupError reports that fail-closed teardown encountered one or more
// native failures. It never contains child output or configuration content.
type CleanupError struct {
	Err error
}

func (e *CleanupError) Error() string { return "supervised process cleanup failed: " + e.Err.Error() }
func (e *CleanupError) Unwrap() error { return e.Err }

type nativeProcess struct {
	process windows.Handle
	thread  windows.Handle
	pid     uint32
	logDone chan struct{}
}

type processOps struct {
	createKillOnCloseJob func() (windows.Handle, error)
	launchSuspended      func(string, string, io.Writer, func(string) error) (*nativeProcess, error)
	assignProcessToJob   func(windows.Handle, windows.Handle) error
	resumeThread         func(windows.Handle) error
	terminateProcess     func(windows.Handle, uint32) error
	terminateJob         func(windows.Handle, uint32) error
	closeJob             func(windows.Handle) error
	closeHandle          func(windows.Handle) error
	waitProcess          func(windows.Handle, time.Duration) error
	waitJobEmpty         func(windows.Handle, time.Duration) error
	exitCode             func(windows.Handle) (int, error)
	sendBreak            func(uint32) error
}

var defaultProcessOps = processOps{
	createKillOnCloseJob: createKillOnCloseJob,
	launchSuspended:      launchSuspendedProcess,
	assignProcessToJob:   windows.AssignProcessToJobObject,
	resumeThread: func(thread windows.Handle) error {
		_, err := windows.ResumeThread(thread)
		return err
	},
	terminateProcess: windows.TerminateProcess,
	terminateJob:     windows.TerminateJobObject,
	closeJob:         windows.CloseHandle,
	closeHandle:      windows.CloseHandle,
	waitProcess:      waitForProcess,
	waitJobEmpty:     waitForJobEmpty,
	exitCode:         processExitCode,
	sendBreak: func(pid uint32) error {
		return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid)
	},
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
	// DisableDiagnosticTail lets an opt-in collector own all diagnostic memory.
	DisableDiagnosticTail bool
	// VerifyExecutable must perform the caller's pinned hash and signer checks.
	// Start invokes it immediately before native process creation.
	VerifyExecutable func(string) error

	mu          sync.Mutex
	proc        *nativeProcess
	job         windows.Handle
	done        chan struct{}
	waitErr     error
	started     bool
	ready       bool
	rootExited  bool
	stopping    bool
	redactor    *streamRedactor
	diagnostic  *boundedTailWriter
	ops         *processOps
	cleanupDone chan struct{}
	cleanupErr  error

	nativeCreated      bool
	terminationProven  bool
	failedStart        bool
	failedStartCleanup error
}

// Start launches exe directly with exactly "run -c <absolute-config>". It
// never invokes a shell. Start requires VerifyExecutable and invokes it inside
// the suspended-launch boundary immediately before CreateProcess. It also
// rejects ambiguous or reparse-point paths.
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
	if p.VerifyExecutable == nil {
		return ErrVerifierRequired
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
	p.configureOutput(logLimit)

	ops := p.ops
	if ops == nil {
		ops = &defaultProcessOps
	}
	job, err := ops.createKillOnCloseJob()
	if err != nil {
		return fmt.Errorf("start supervised process: create job: %w", err)
	}
	proc, err := ops.launchSuspended(exe, config, p.redactor, p.VerifyExecutable)
	if err != nil {
		_ = ops.closeJob(job)
		p.redactor.Flush()
		return fmt.Errorf("start supervised process: launch: %w", err)
	}
	p.nativeCreated = true
	if err := ops.assignProcessToJob(job, proc.process); err != nil {
		cleanupErr, proven := abortSuspendedProcess(ops, job, proc, false)
		p.rememberFailedStart(proc, ops, cleanupErr, proven)
		p.redactor.Flush()
		return errors.Join(fmt.Errorf("start supervised process: assign job: %w", err), cleanupErr)
	}
	if err := ops.resumeThread(proc.thread); err != nil {
		cleanupErr, proven := abortSuspendedProcess(ops, job, proc, true)
		p.rememberFailedStart(proc, ops, cleanupErr, proven)
		p.redactor.Flush()
		return errors.Join(fmt.Errorf("start supervised process: resume: %w", err), cleanupErr)
	}
	_ = ops.closeHandle(proc.thread)
	proc.thread = 0

	p.proc = proc
	p.job = job
	p.ops = ops
	p.done = make(chan struct{})
	p.started = true
	p.terminationProven = false
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
		return errors.Join(ErrNoReadinessProbe, p.terminateForFailure())
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	probeResult := make(chan error, 1)
	probeInFlight := false
	startProbe := func() {
		probeInFlight = true
		go func() {
			probeResult <- probe(readyCtx)
		}()
	}
	startProbe()

	for {
		select {
		case err := <-probeResult:
			probeInFlight = false
			if err != nil {
				continue
			}
			p.mu.Lock()
			if p.rootExited {
				p.mu.Unlock()
				return p.Wait()
			}
			p.ready = true
			p.mu.Unlock()
			return nil
		case <-done:
			return p.Wait()
		case <-readyCtx.Done():
			cleanupErr := p.terminateForFailure()
			if ctx.Err() != nil {
				return errors.Join(ctx.Err(), cleanupErr)
			}
			return errors.Join(ErrReadyTimeout, cleanupErr)
		case <-ticker.C:
			if !probeInFlight {
				startProbe()
			}
		}
	}
}

// Stop requests a console control break, then escalates to terminating the
// kill-on-close job after StopTimeout. It is idempotent after a controlled stop.
func (p *Process) Stop(ctx context.Context) error {
	p.mu.Lock()
	if p.failedStart {
		p.mu.Unlock()
		return p.retryFailedStartCleanup(ctx)
	}
	if !p.started {
		p.mu.Unlock()
		return nil
	}
	done := p.done
	if p.stopping {
		cleanupDone := p.cleanupDone
		p.mu.Unlock()
		if cleanupDone != nil {
			select {
			case <-done:
				return p.terminalError()
			case <-cleanupDone:
				p.mu.Lock()
				err := p.cleanupErr
				p.mu.Unlock()
				if err != nil {
					// A failed cleanup may be unable to drive the root process to
					// its terminal state. Do not leave later Stop calls blocked on
					// a done channel that can never close.
					select {
					case <-done:
						return p.terminalError()
					default:
						return err
					}
				}
				select {
				case <-done:
					return p.terminalError()
				case <-ctx.Done():
					return ctx.Err()
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		select {
		case <-done:
			return p.terminalError()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-done:
		err := errors.Join(p.waitErr, p.cleanupErr)
		p.mu.Unlock()
		return err
	default:
	}
	p.stopping = true
	pid := p.proc.pid
	grace := p.StopTimeout
	p.mu.Unlock()
	if grace <= 0 {
		grace = 3 * time.Second
	}

	_ = p.ops.sendBreak(pid)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
		return p.terminalError()
	case <-timer.C:
		return p.terminateForFailure()
	case <-ctx.Done():
		return errors.Join(ctx.Err(), p.terminateForFailure())
	}
}

// TerminationProven reports whether no native process created by this Process
// can remain and, when a job was assigned, its process tree was observed empty.
// It is intentionally independent of ExitError and non-proof cleanup errors.
func (p *Process) TerminationProven() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.nativeCreated || p.terminationProven
}

// DiagnosticTail returns the bounded, already-redacted tail of child output.
// It never reads the configuration or returns raw pipe data.
func (p *Process) DiagnosticTail() string {
	p.mu.Lock()
	diagnostic := p.diagnostic
	p.mu.Unlock()
	if diagnostic == nil {
		return ""
	}
	return diagnostic.String()
}

// rememberFailedStart is called with p.mu held. Cleanup that could not prove
// termination retains the native process handle so Stop can retry proof.
func (p *Process) rememberFailedStart(proc *nativeProcess, ops *processOps, cleanupErr error, proven bool) {
	p.failedStartCleanup = cleanupErr
	p.terminationProven = proven
	if proven {
		return
	}
	p.proc = proc
	p.ops = ops
	p.done = make(chan struct{})
	p.started = true
	p.failedStart = true
}

func (p *Process) retryFailedStartCleanup(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	p.mu.Lock()
	proc := p.proc
	ops := p.ops
	previous := p.failedStartCleanup
	p.mu.Unlock()
	var retryFailures []error
	if err := ops.terminateProcess(proc.process, 1); err != nil {
		retryFailures = append(retryFailures, fmt.Errorf("retry terminate failed-start process: %w", err))
	}
	if err := ops.waitProcess(proc.process, 5*time.Second); err != nil {
		retryFailures = append(retryFailures, fmt.Errorf("retry confirm failed-start termination: %w", err))
		return errors.Join(previous, &CleanupError{Err: errors.Join(retryFailures...)})
	}
	if err := ops.closeHandle(proc.process); err != nil {
		retryFailures = append(retryFailures, fmt.Errorf("close failed-start process handle: %w", err))
	}
	p.mu.Lock()
	p.terminationProven = true
	p.failedStart = false
	p.started = false
	if p.done != nil {
		close(p.done)
	}
	p.mu.Unlock()
	if len(retryFailures) == 0 {
		return previous
	}
	return errors.Join(previous, &CleanupError{Err: errors.Join(retryFailures...)})
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
	return p.terminalError()
}

func (p *Process) waitLoop() {
	err := p.ops.waitProcess(p.proc.process, -1)
	code, codeErr := p.ops.exitCode(p.proc.process)
	if codeErr != nil {
		err = errors.Join(err, codeErr)
	}
	p.mu.Lock()
	p.rootExited = true
	p.mu.Unlock()

	cleanupDone, job, _, ops, cleanupOwner := p.acquireCleanup(false)
	if cleanupOwner {
		cleanupErr, proven := cleanupJobAfterRootExit(ops, job)
		p.finishCleanup(cleanupDone, cleanupErr, proven)
	} else {
		<-cleanupDone
	}
	var logErr error
	if p.proc.logDone != nil {
		select {
		case <-p.proc.logDone:
		case <-time.After(time.Second):
			logErr = errors.New("log capture did not close after process job cleanup")
		}
	}
	p.redactor.Flush()
	p.mu.Lock()
	stopping := p.stopping
	beforeReady := !p.ready
	p.mu.Unlock()
	var waitErr error
	if !stopping {
		waitErr = &ExitError{Code: code, BeforeReady: beforeReady}
	}
	if err != nil {
		waitErr = errors.Join(waitErr, fmt.Errorf("wait for supervised process: %w", err))
	}
	if logErr != nil {
		waitErr = errors.Join(waitErr, &CleanupError{Err: errors.Join(
			logErr,
		)})
	}
	if closeErr := p.ops.closeHandle(p.proc.process); closeErr != nil {
		waitErr = errors.Join(waitErr, &CleanupError{Err: fmt.Errorf("close process handle: %w", closeErr)})
	}
	p.mu.Lock()
	p.waitErr = waitErr
	close(p.done)
	p.mu.Unlock()
}

func (p *Process) terminateForFailure() error {
	cleanupDone, job, proc, ops, cleanupOwner := p.acquireCleanup(true)
	if cleanupDone == nil {
		return nil
	}
	if !cleanupOwner {
		<-cleanupDone
		p.mu.Lock()
		err := p.cleanupErr
		p.mu.Unlock()
		return err
	}

	var cleanupFailures []error
	jobClosed := false
	jobTerminated := false
	rootTerminated := false
	jobEmpty := false
	if job == 0 {
		cleanupFailures = append(cleanupFailures, errors.New("process job handle was unavailable during teardown"))
	} else if err := ops.terminateJob(job, 1); err != nil {
		cleanupFailures = append(cleanupFailures, fmt.Errorf("terminate process job: %w", err))
		if closeErr := ops.closeJob(job); closeErr != nil {
			cleanupFailures = append(cleanupFailures, fmt.Errorf("close process job fallback: %w", closeErr))
		}
		jobClosed = true
	} else {
		jobTerminated = true
	}
	if err := ops.waitProcess(proc.process, 5*time.Second); err != nil {
		cleanupFailures = append(cleanupFailures, fmt.Errorf("confirm root process termination: %w", err))
	} else {
		rootTerminated = true
	}
	if jobTerminated {
		if err := ops.waitJobEmpty(job, 5*time.Second); err != nil {
			cleanupFailures = append(cleanupFailures, fmt.Errorf("confirm process job is empty: %w", err))
		} else {
			jobEmpty = true
		}
	}
	if job != 0 && !jobClosed {
		if err := ops.closeJob(job); err != nil {
			cleanupFailures = append(cleanupFailures, fmt.Errorf("close terminated process job: %w", err))
		}
	}
	var cleanupErr error
	if len(cleanupFailures) != 0 {
		cleanupErr = &CleanupError{Err: errors.Join(cleanupFailures...)}
	}
	p.finishCleanup(cleanupDone, cleanupErr, rootTerminated && jobEmpty)
	return cleanupErr
}

// acquireCleanup serializes all teardown paths. The owner removes the job
// handle from Process and is solely responsible for finishing cleanupDone.
// Every observer waits for that same result before publishing terminal state.
func (p *Process) acquireCleanup(markStopping bool) (chan struct{}, windows.Handle, *nativeProcess, *processOps, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return nil, 0, nil, nil, false
	}
	if markStopping {
		p.stopping = true
	}
	if p.cleanupDone != nil {
		return p.cleanupDone, 0, p.proc, p.ops, false
	}
	p.cleanupDone = make(chan struct{})
	job := p.job
	p.job = 0
	return p.cleanupDone, job, p.proc, p.ops, true
}

func (p *Process) finishCleanup(done chan struct{}, cleanupErr error, terminationProven bool) {
	p.mu.Lock()
	p.cleanupErr = errors.Join(p.cleanupErr, cleanupErr)
	if terminationProven {
		p.terminationProven = true
	}
	close(done)
	p.mu.Unlock()
}

func (p *Process) terminalError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return errors.Join(p.waitErr, p.cleanupErr)
}

// cleanupJobAfterRootExit handles the important case where the root exits but
// descendants still own inherited handles. The whole job is terminated and
// observed empty before its kill-on-close handle is released.
func cleanupJobAfterRootExit(ops *processOps, job windows.Handle) (error, bool) {
	var cleanupFailures []error
	jobClosed := false
	jobEmpty := false
	if job == 0 {
		cleanupFailures = append(cleanupFailures, errors.New("process job handle was unavailable after root exit"))
	} else if err := ops.terminateJob(job, 1); err != nil {
		cleanupFailures = append(cleanupFailures, fmt.Errorf("terminate process job after root exit: %w", err))
		if closeErr := ops.closeJob(job); closeErr != nil {
			cleanupFailures = append(cleanupFailures, fmt.Errorf("close process job fallback after root exit: %w", closeErr))
		}
		jobClosed = true
	} else if err := ops.waitJobEmpty(job, 5*time.Second); err != nil {
		cleanupFailures = append(cleanupFailures, fmt.Errorf("confirm process job is empty after root exit: %w", err))
	} else {
		jobEmpty = true
	}
	if job != 0 && !jobClosed {
		if err := ops.closeJob(job); err != nil {
			cleanupFailures = append(cleanupFailures, fmt.Errorf("close process job after root exit: %w", err))
		}
	}
	if len(cleanupFailures) == 0 {
		return nil, jobEmpty
	}
	return &CleanupError{Err: errors.Join(cleanupFailures...)}, jobEmpty
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

func launchSuspendedProcess(exe, config string, output io.Writer, verify func(string) error) (*nativeProcess, error) {
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = pipeR.Close()
		_ = pipeW.Close()
		return nil, err
	}
	closeFiles := func() {
		_ = pipeR.Close()
		_ = pipeW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
	}
	if err := windows.SetHandleInformation(windows.Handle(pipeW.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		closeFiles()
		return nil, err
	}
	if err := windows.SetHandleInformation(windows.Handle(stderrW.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		closeFiles()
		return nil, err
	}
	nul, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		closeFiles()
		return nil, err
	}
	defer nul.Close()
	if err := windows.SetHandleInformation(windows.Handle(nul.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		closeFiles()
		return nil, err
	}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		closeFiles()
		return nil, err
	}
	defer attributes.Delete()
	handles := []windows.Handle{windows.Handle(pipeW.Fd()), windows.Handle(nul.Fd()), windows.Handle(stderrW.Fd())}
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		closeFiles()
		return nil, err
	}
	si := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  handles[1],
			StdOutput: handles[0],
			StdErr:    handles[2],
		},
		ProcThreadAttributeList: attributes.List(),
	}
	exeUTF16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		closeFiles()
		return nil, err
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{exe, "run", "-c", config}))
	if err != nil {
		closeFiles()
		return nil, err
	}
	var info windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := verify(exe); err != nil {
		closeFiles()
		return nil, fmt.Errorf("verify executable: %w", err)
	}
	if err := windows.CreateProcess(exeUTF16, commandLine, nil, nil, true, flags, nil, nil, &si.StartupInfo, &info); err != nil {
		closeFiles()
		return nil, err
	}
	_ = pipeW.Close()
	_ = stderrW.Close()
	logDone := make(chan struct{})
	var readers sync.WaitGroup
	for _, reader := range []*os.File{pipeR, stderrR} {
		destination := output
		if provider, ok := output.(interface{ NewOutputStream() io.Writer }); ok {
			destination = provider.NewOutputStream()
		}
		readers.Add(1)
		go func() {
			defer readers.Done()
			_, _ = io.Copy(destination, reader)
			_ = reader.Close()
			if closer, ok := destination.(io.Closer); ok {
				_ = closer.Close()
			}
		}()
	}
	go func() {
		readers.Wait()
		close(logDone)
	}()
	return &nativeProcess{process: info.Process, thread: info.Thread, pid: info.ProcessId, logDone: logDone}, nil
}

func abortSuspendedProcess(ops *processOps, job windows.Handle, proc *nativeProcess, assigned bool) (error, bool) {
	var errs []error
	jobClosed := false
	terminationProven := false
	if assigned {
		if err := ops.terminateJob(job, 1); err != nil {
			errs = append(errs, fmt.Errorf("terminate suspended job: %w", err))
			if closeErr := ops.closeJob(job); closeErr != nil {
				errs = append(errs, fmt.Errorf("close suspended job fallback: %w", closeErr))
			}
			jobClosed = true
		}
	} else if err := ops.terminateProcess(proc.process, 1); err != nil {
		errs = append(errs, fmt.Errorf("terminate suspended process: %w", err))
	}
	if err := ops.waitProcess(proc.process, 5*time.Second); err != nil {
		errs = append(errs, fmt.Errorf("wait for suspended process termination: %w", err))
	} else {
		terminationProven = true
	}
	if proc.thread != 0 {
		if err := ops.closeHandle(proc.thread); err != nil {
			errs = append(errs, fmt.Errorf("close suspended thread: %w", err))
		}
		proc.thread = 0
	}
	if terminationProven {
		if err := ops.closeHandle(proc.process); err != nil {
			errs = append(errs, fmt.Errorf("close suspended process: %w", err))
		}
	}
	if !jobClosed {
		if err := ops.closeJob(job); err != nil {
			errs = append(errs, fmt.Errorf("close suspended job: %w", err))
		}
	}
	if proc.logDone != nil {
		select {
		case <-proc.logDone:
		case <-time.After(time.Second):
			errs = append(errs, errors.New("log capture did not close after suspended-process cleanup"))
		}
	}
	return errors.Join(errs...), terminationProven
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func waitForProcess(process windows.Handle, timeout time.Duration) error {
	waitMillis := uint32(windows.INFINITE)
	if timeout >= 0 {
		if timeout <= 0 {
			waitMillis = 0
		} else if timeout >= time.Duration(^uint32(0)-1)*time.Millisecond {
			waitMillis = uint32(windows.INFINITE - 1)
		} else {
			waitMillis = uint32((timeout + time.Millisecond - 1) / time.Millisecond)
		}
	}
	result, err := windows.WaitForSingleObject(process, waitMillis)
	if err != nil {
		return err
	}
	if result == uint32(windows.WAIT_TIMEOUT) {
		return context.DeadlineExceeded
	}
	if result != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("unexpected wait result %d", result)
	}
	return nil
}

func processExitCode(process windows.Handle) (int, error) {
	var code uint32
	if err := windows.GetExitCodeProcess(process, &code); err != nil {
		return 0, err
	}
	return int(code), nil
}

type jobBasicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

func waitForJobEmpty(job windows.Handle, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var info jobBasicAccountingInformation
		if err := windows.QueryInformationJobObject(
			job,
			windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
			nil,
		); err != nil {
			return err
		}
		if info.ActiveProcesses == 0 {
			return nil
		}
		if timeout <= 0 || time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		time.Sleep(10 * time.Millisecond)
	}
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

func (p *Process) configureOutput(logLimit int) {
	if p.DisableDiagnosticTail {
		// The destination owns both its collection window and output bounds.
		// A lifetime prefix limit here would exhaust during disabled periods.
		p.redactor = newStreamRedactor(p.LogWriter, p.Secrets, 0)
		return
	}
	external := &boundedPrefixWriter{dst: p.LogWriter, max: logLimit}
	p.diagnostic = newBoundedTailWriter(logLimit)
	p.redactor = newStreamRedactor(io.MultiWriter(external, p.diagnostic), p.Secrets, 0)
}

type streamRedactor struct {
	mu        sync.Mutex
	dst       io.Writer
	secrets   [][]byte
	pending   []byte
	written   int
	maxOutput int
}

// Only opt-in destinations provide independent framing. Legacy destinations
// retain the single shared redactor and bounded prefix/tail behavior.
func (r *streamRedactor) NewOutputStream() io.Writer {
	provider, ok := r.dst.(interface{ NewOutputStream() io.Writer })
	if !ok {
		return r
	}
	destination := provider.NewOutputStream()
	child := &streamRedactor{dst: destination, secrets: r.secrets, maxOutput: r.maxOutput}
	return &ownedOutputStream{streamRedactor: child}
}

type ownedOutputStream struct{ *streamRedactor }

func (s *ownedOutputStream) Close() error {
	s.Flush()
	if closer, ok := s.dst.(io.Closer); ok {
		return closer.Close()
	}
	return nil
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
	if r.maxOutput > 0 {
		remaining := r.maxOutput - r.written
		if remaining <= 0 {
			return
		}
		if len(data) > remaining {
			data = data[:remaining]
		}
	}
	_, _ = r.dst.Write(data)
	r.written += len(data)
}

type boundedPrefixWriter struct {
	mu      sync.Mutex
	dst     io.Writer
	written int
	max     int
}

func (w *boundedPrefixWriter) Write(data []byte) (int, error) {
	original := len(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dst == nil || w.max <= w.written {
		return original, nil
	}
	remaining := w.max - w.written
	if len(data) > remaining {
		data = data[:remaining]
	}
	_, err := w.dst.Write(data)
	w.written += len(data)
	return original, err
}

type boundedTailWriter struct {
	mu   sync.Mutex
	data []byte
	max  int
}

func newBoundedTailWriter(max int) *boundedTailWriter {
	return &boundedTailWriter{max: max}
}

func (w *boundedTailWriter) Write(data []byte) (int, error) {
	original := len(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.max <= 0 {
		return original, nil
	}
	if len(data) >= w.max {
		w.data = append(w.data[:0], data[len(data)-w.max:]...)
		return original, nil
	}
	w.data = append(w.data, data...)
	if excess := len(w.data) - w.max; excess > 0 {
		copy(w.data, w.data[excess:])
		w.data = w.data[:w.max]
	}
	return original, nil
}

func (w *boundedTailWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(append([]byte(nil), w.data...))
}
