package linux

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	CorePath            = "/usr/lib/regen-access/sing-box"
	CoreSHA256          = "7e9dcd7239c49478a576d79f272751e5ed1c2aba7cc08ab1b2bd69c00c904ba1"
	CronetPath          = "/usr/lib/regen-access/libcronet.so"
	CronetSHA256        = "9d43c2ee2410a54262e394c09da14b402e872d919ea66280c6b1f54414ab5f6a"
	maxTrustedFileBytes = 256 << 20
)

// openTrustedAt walks from a verified directory descriptor. Every component
// must be root-owned and non-writable by other users; symlinks are never followed.
// Production uses root="/". Private native tests supply their protected root.
func openTrustedAt(root, relative, digest string) (*os.File, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return nil, errors.New("invalid protected relative path")
	}
	parts := strings.Split(relative, string(filepath.Separator))
	for _, part := range parts {
		if part == "." || part == ".." || part == "" {
			return nil, errors.New("invalid protected path component")
		}
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			unix.Close(fd)
		}
	}()
	if err = trustedStat(fd, true); err != nil {
		return nil, err
	}
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		directory := i < len(parts)-1
		if directory {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		if openErr != nil {
			return nil, openErr
		}
		unix.Close(fd)
		fd = next
		if err = trustedStat(fd, directory); err != nil {
			return nil, err
		}
	}
	file := os.NewFile(uintptr(fd), relative)
	fd = -1
	okay := false
	defer func() {
		if !okay {
			file.Close()
		}
	}()
	if digest != "" {
		expected, err := hex.DecodeString(digest)
		if err != nil || len(expected) != sha256.Size {
			return nil, errors.New("invalid pinned digest")
		}
		before, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if before.Size() > maxTrustedFileBytes {
			return nil, errors.New("protected file exceeds bound")
		}
		hash := sha256.New()
		if _, err = io.Copy(hash, io.LimitReader(file, maxTrustedFileBytes+1)); err != nil {
			return nil, err
		}
		after, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(digest) {
			return nil, errors.New("protected file digest mismatch or concurrent change")
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
	}
	okay = true
	return file, nil
}

func trustedStat(fd int, directory bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	want := uint32(unix.S_IFREG)
	if directory {
		want = unix.S_IFDIR
	}
	if stat.Mode&unix.S_IFMT != want || stat.Uid != 0 || stat.Mode&0022 != 0 {
		return errors.New("unsafe protected file ownership or mode")
	}
	if !directory && stat.Nlink != 1 {
		return errors.New("protected file has multiple links")
	}
	return nil
}
