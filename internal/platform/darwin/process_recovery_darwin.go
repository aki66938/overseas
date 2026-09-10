//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"corp.example/overseas-access-gateway/internal/agent"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const coreJournalName = "owned-core.json"

type coreOwnership struct {
	Version    int    `json:"version"`
	Boot       string `json:"boot"`
	PID        int    `json:"pid"`
	StartSec   int64  `json:"start_sec"`
	StartUsec  int64  `json:"start_usec"`
	CoreSHA256 string `json:"core_sha256"`
}
type recoveryOperations struct {
	boot     func() (string, error)
	identity func(int) (*coreOwnership, error)
	empty    func(int) (bool, error)
	signal   func(int) error
}

func bootID() (string, error) {
	v, e := unix.Sysctl("kern.bootsessionuuid")
	return strings.TrimSpace(v), e
}

func inspectCore(pid int) (*coreOwnership, error) {
	value, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if errors.Is(err, unix.ESRCH) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if value.Proc.P_pid == 0 {
		return nil, nil
	}
	if value.Proc.P_pid != int32(pid) {
		return nil, errors.New("unexpected core PID")
	}
	group, err := unix.Getpgid(pid)
	if err != nil {
		return nil, err
	}
	if group != pid {
		return nil, errors.New("owned core group changed")
	}
	// procargs2 begins with argc followed by the executable's absolute path.
	// Do not trust the truncated process name or caller-provided argv[0].
	args, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	if len(args) < 5 {
		return nil, errors.New("core executable identity unavailable")
	}
	end := bytes.IndexByte(args[4:], 0)
	if end < 0 {
		return nil, errors.New("invalid core executable identity")
	}
	path := string(args[4 : 4+end])
	if path != CorePath && path != ServicePath {
		return nil, errors.New("unrecognized owned executable")
	}
	checked, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || checked.Proc.P_pid != value.Proc.P_pid || checked.Proc.P_starttime != value.Proc.P_starttime {
		return nil, errors.New("core identity changed while inspecting executable")
	}
	boot, err := bootID()
	if err != nil {
		return nil, err
	}
	return &coreOwnership{Version: 1, Boot: boot, PID: pid, StartSec: value.Proc.P_starttime.Sec, StartUsec: int64(value.Proc.P_starttime.Usec), CoreSHA256: PinnedCoreSHA256}, nil
}

func recoverCore(ctx context.Context, record coreOwnership, ops recoveryOperations) error {
	boot, err := ops.boot()
	if err != nil {
		return err
	}
	if boot != record.Boot {
		return nil
	} // Never inspect a recycled PID from a previous boot.
	identity, err := ops.identity(record.PID)
	if err != nil {
		return err
	}
	if identity == nil {
		empty, err := ops.empty(record.PID)
		if err != nil {
			return err
		}
		if !empty {
			return errors.New("core leader missing but live process group remains")
		}
		return nil
	}
	if *identity != record {
		return errors.New("core ownership identity changed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Recheck immediately before signaling; ambiguity never authorizes a kill.
	identity, err = ops.identity(record.PID)
	if err != nil {
		return err
	}
	if identity == nil || *identity != record {
		return errors.New("core changed before recovery signal")
	}
	if err = ops.signal(record.PID); err != nil {
		return err
	}
	for {
		empty, err := ops.empty(record.PID)
		if err != nil {
			return err
		}
		if empty {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func loadCoreRecord(directory string) (*coreOwnership, error) {
	dir, err := (fileJournal{directory}).openDirectory()
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), coreJournalName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), coreJournalName)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != 0 || st.Mode&0777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size > 4096 {
		return nil, errors.New("unsafe owned core journal")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var record coreOwnership
	if err = dec.Decode(&record); err != nil {
		return nil, err
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing core ownership data")
	}
	if record.Version != 1 || record.PID <= 1 || record.Boot == "" || record.StartSec <= 0 || record.CoreSHA256 != PinnedCoreSHA256 {
		return nil, errors.New("invalid core ownership record")
	}
	return &record, nil
}
func saveCoreRecord(directory string, record *coreOwnership) error {
	dir, err := (fileJournal{directory}).openDirectory()
	if err != nil {
		return err
	}
	defer dir.Close()
	if existing, err := loadCoreRecord(directory); err != nil || existing != nil {
		return errors.Join(err, errors.New("unresolved owned core journal"))
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(directory, ".core-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(directory, coreJournalName)); err != nil {
		return err
	}
	return dir.Sync()
}
func removeCoreRecord(directory string) error {
	dir, err := (fileJournal{directory}).openDirectory()
	if err != nil {
		return err
	}
	defer dir.Close()
	err = unix.Unlinkat(int(dir.Fd()), coreJournalName, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	return dir.Sync()
}

func RecoverOwnedCore(ctx context.Context) error {
	record, err := loadCoreRecord(StateDirectory)
	if err != nil || record == nil {
		return err
	}
	ops := recoveryOperations{boot: bootID, identity: inspectCore, empty: groupEmptyOfLiveProcesses, signal: func(pid int) error { return unix.Kill(-pid, unix.SIGKILL) }}
	if err = recoverCore(ctx, *record, ops); err != nil {
		return err
	}
	return removeCoreRecord(StateDirectory)
}

func awaitCoreGate(gate io.Reader, execute func() error) error {
	var release [1]byte
	if _, err := io.ReadFull(gate, release[:]); err != nil {
		return err
	}
	if release[0] != 'G' {
		return errors.New("invalid core gate release")
	}
	return execute()
}

// This fixed internal entry point receives only inherited fd3. EOF means the
// parent died before it durably registered ownership and must never start TUN.
func RunCoreHelper() error {
	if os.Geteuid() != 0 {
		return errors.New("core helper requires root")
	}
	gate := os.NewFile(3, "core-start-gate")
	if gate == nil {
		return errors.New("missing core gate")
	}
	defer gate.Close()
	if err := VerifyInstalledLaunch(CorePath, RenderedConfigPath); err != nil {
		return err
	}
	return awaitCoreGate(gate, func() error {
		if err := gate.Close(); err != nil {
			return err
		}
		if err := VerifyInstalledLaunch(CorePath, RenderedConfigPath); err != nil {
			return err
		}
		return syscall.Exec(CorePath, []string{CorePath, "run", "-c", RenderedConfigPath}, []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"})
	})
}

type PersistentProcessSupervisor struct{}

func NewPersistentProcessSupervisor() *PersistentProcessSupervisor {
	return &PersistentProcessSupervisor{}
}
func (s *PersistentProcessSupervisor) Start(ctx context.Context, exe, config string) (agent.ProcessInstance, agent.ProcessStartResult) {
	fail := func(err error) (agent.ProcessInstance, agent.ProcessStartResult) {
		return nil, agent.ProcessStartResult{Err: err, TerminationProven: true}
	}
	if err := VerifyInstalledLaunch(exe, config); err != nil {
		return fail(err)
	}
	if err := protectedPath(ServicePath, false, 0755); err != nil {
		return fail(err)
	}
	if record, err := loadCoreRecord(StateDirectory); err != nil || record != nil {
		return fail(errors.Join(err, errors.New("unresolved core ownership")))
	}
	read, write, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	defer read.Close()
	defer write.Close()
	inner, _ := NewProcessSupervisorForVerifiedCore(PinnedCoreSHA256)
	inner.command = func(string, string) *exec.Cmd {
		cmd := exec.Command(ServicePath, "--core-helper")
		cmd.ExtraFiles = []*os.File{read}
		return cmd
	}
	inner.afterStart = func(cmd *exec.Cmd) error {
		read.Close()
		identity, err := inspectCore(cmd.Process.Pid)
		if err != nil {
			return err
		}
		if identity == nil {
			return errors.New("core helper exited before ownership capture")
		}
		if err = saveCoreRecord(StateDirectory, identity); err != nil {
			return err
		}
		_, err = write.Write([]byte{'G'})
		write.Close()
		return err
	}
	inner.afterProvenStop = func() error { return removeCoreRecord(StateDirectory) }
	return inner.Start(ctx, exe, config)
}
