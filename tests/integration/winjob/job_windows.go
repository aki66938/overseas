//go:build windows

package winjob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Run starts an absolute executable suspended, assigns it to a kill-on-close
// Job Object before the first instruction executes, and does not return until
// the entire job is quiescent. Stderr is intentionally discarded.
func Run(ctx context.Context, executable string, args, environment []string, stdin []byte) ([]byte, error) {
	if !strings.Contains(executable, `\`) && !strings.Contains(executable, `/`) {
		return nil, errors.New("job executable must be an absolute path")
	}
	input, err := os.CreateTemp("", "fixture-job-stdin-*.tmp")
	if err != nil {
		return nil, err
	}
	inputName := input.Name()
	defer os.Remove(inputName)
	defer input.Close()
	output, err := os.CreateTemp("", "fixture-job-stdout-*.tmp")
	if err != nil {
		return nil, err
	}
	outputName := output.Name()
	defer os.Remove(outputName)
	defer output.Close()
	if _, err = input.Write(stdin); err != nil {
		return nil, err
	}
	if _, err = input.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	for _, file := range []*os.File{input, output} {
		if err := windows.SetHandleInformation(windows.Handle(file.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return nil, err
		}
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, err
	}
	application, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	commandLine := append([]string{executable}, args...)
	for index := range commandLine {
		commandLine[index] = syscall.EscapeArg(commandLine[index])
	}
	commandLinePtr, err := windows.UTF16PtrFromString(strings.Join(commandLine, " "))
	if err != nil {
		return nil, err
	}
	environmentBlock := makeEnvironmentBlock(environment)
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Flags: windows.STARTF_USESTDHANDLES, StdInput: windows.Handle(input.Fd()), StdOutput: windows.Handle(output.Fd()), StdErr: windows.Handle(output.Fd())}
	var process windows.ProcessInformation
	if err = windows.CreateProcess(application, commandLinePtr, nil, nil, true, windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, &environmentBlock[0], nil, &startup, &process); err != nil {
		return nil, fmt.Errorf("create contained process: %w", err)
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	if err = windows.AssignProcessToJobObject(job, process.Process); err != nil {
		_ = windows.TerminateProcess(process.Process, 1)
		return nil, err
	}
	if _, err = windows.ResumeThread(process.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = waitJobQuiescent(job, 5*time.Second)
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		_, waitErr := windows.WaitForSingleObject(process.Process, windows.INFINITE)
		if waitErr != nil {
			done <- waitErr
			return
		}
		var code uint32
		if err := windows.GetExitCodeProcess(process.Process, &code); err != nil {
			done <- err
			return
		}
		if code != 0 {
			done <- fmt.Errorf("contained process exit code %d", code)
			return
		}
		done <- nil
	}()
	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		runErr = ctx.Err()
		_ = windows.TerminateJobObject(job, 1)
		<-done
	}
	// A successful main process is not permission for descendants to escape.
	_ = windows.TerminateJobObject(job, 1)
	if err := waitJobQuiescent(job, 5*time.Second); err != nil {
		return nil, errors.Join(runErr, err)
	}
	if err := output.Sync(); err != nil {
		return nil, errors.Join(runErr, err)
	}
	data, readErr := os.ReadFile(outputName)
	return data, errors.Join(runErr, readErr)
}

func waitJobQuiescent(job windows.Handle, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var info jobBasicAccountingInformation
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
			return err
		}
		if info.ActiveProcesses == 0 {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("contained process tree did not quiesce")
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

func makeEnvironmentBlock(environment []string) []uint16 {
	values := append([]string(nil), environment...)
	sort.Slice(values, func(i, j int) bool { return strings.ToUpper(values[i]) < strings.ToUpper(values[j]) })
	return utf16.Encode([]rune(strings.Join(values, "\x00") + "\x00\x00"))
}
