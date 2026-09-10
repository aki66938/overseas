//go:build darwin

package darwin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func protectedPath(path string, directory bool, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err = unix.Lstat(path, &stat); err != nil {
		return err
	}
	if stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm() != mode {
		return errors.New("unsafe protected service path")
	}
	return nil
}

func protectedAncestors(path string) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		if err = unix.Lstat(dir, &stat); err != nil {
			return err
		}
		// Darwin ships /private/var/run root:daemon 0775. This one fixed
		// system ancestor is trusted; the application child stays root:wheel0755.
		trustedRuntime := dir == "/private/var/run" && stat.Gid == 1 && info.Mode().Perm() == 0775
		if !info.IsDir() || stat.Uid != 0 || (info.Mode().Perm()&0022 != 0 && !trustedRuntime) {
			return errors.New("unsafe installation ancestor")
		}
		if dir == "/" {
			return nil
		}
	}
}

func LoadInstalledServiceConfig() (ServiceConfig, error) {
	var c ServiceConfig
	if os.Geteuid() != 0 {
		return c, errors.New("service requires root")
	}
	if err := protectedAncestors(InstallDirectory); err != nil {
		return c, err
	}
	for _, dir := range []struct {
		path string
		mode os.FileMode
	}{{InstallDirectory, 0755}, {StateDirectory, 0700}} {
		if err := protectedPath(dir.path, true, dir.mode); err != nil {
			return c, err
		}
	}
	if err := protectedPath(ServiceConfigPath, false, 0600); err != nil {
		return c, err
	}
	if err := protectedPath(ServicePath, false, 0755); err != nil {
		return c, err
	}
	data, err := os.ReadFile(ServiceConfigPath)
	if err != nil {
		return c, err
	}
	c, err = ParseServiceConfig(data)
	if err != nil {
		return c, err
	}
	if err = validateOwnerUID(c.OwnerUID); err != nil {
		return c, err
	}
	if err = VerifyInstalledCore(CorePath); err != nil {
		return c, err
	}
	return c, nil
}

func VerifyInstalledCore(path string) error {
	if path != CorePath {
		return errors.New("unexpected core path")
	}
	if err := protectedAncestors(path); err != nil {
		return err
	}
	return verifyCoreFile(path, PinnedCoreSHA256)
}

func verifyCoreFile(path, expectedDigest string) error {
	if err := protectedPath(path, false, 0755); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != expectedDigest {
		return errors.New("installed core hash mismatch")
	}
	return nil
}

func VerifyInstalledLaunch(executable, config string) error {
	if config != RenderedConfigPath {
		return errors.New("unexpected core config")
	}
	if err := VerifyInstalledCore(executable); err != nil {
		return err
	}
	if err := protectedAncestors(config); err != nil {
		return err
	}
	return protectedPath(config, false, 0600)
}

func WriteInstalledConfig(path string, data []byte) error {
	if path != RenderedConfigPath {
		return errors.New("unexpected rendered config path")
	}
	if err := protectedAncestors(path); err != nil {
		return err
	}
	if err := protectedPath(StateDirectory, true, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err = protectedPath(path, false, 0600); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(StateDirectory, ".config-")
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
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(StateDirectory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func lockDaemon(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = protectedPath(path, false, 0600); err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Hold for the entire recovery/listen/cleanup lifetime. The lock is never unlinked.
func AcquireDaemonLock() (*os.File, error) {
	const runtimeDirectory = "/private/var/run/regen-access"
	if os.Geteuid() != 0 {
		return nil, errors.New("service requires root")
	}
	if err := protectedAncestors(runtimeDirectory); err != nil {
		return nil, err
	}
	if err := protectedPath(runtimeDirectory, true, 0755); err != nil {
		return nil, err
	}
	return lockDaemon(runtimeDirectory + "/daemon.lock")
}

// Caller must hold the exclusive daemon lock. Only ECONNREFUSED proves stale.
func RemoveStaleServiceSocket(ownerUID int) error {
	if err := socketParent(SocketPath); err != nil {
		return err
	}
	info, err := os.Lstat(SocketPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err = unix.Lstat(SocketPath, &stat); err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || stat.Uid != uint32(ownerUID) || stat.Gid != 0 {
		return errors.New("untrusted stale socket")
	}
	conn, err := net.DialTimeout("unix", SocketPath, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		return errors.New("live service socket")
	}
	if !errors.Is(err, unix.ECONNREFUSED) {
		return errors.New("socket liveness unproven")
	}
	current, err := os.Lstat(SocketPath)
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) {
		return errors.New("socket changed during stale check")
	}
	return os.Remove(SocketPath)
}
