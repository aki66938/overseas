//go:build !windows

package runtimeowner

import (
	"errors"
	"io"
	"os"
	"sync"
)

var runtimeOwnershipMutex sync.Mutex

func lockRuntimeOwnership() (func(), error) {
	runtimeOwnershipMutex.Lock()
	return runtimeOwnershipMutex.Unlock, nil
}

func replaceFile(source, destination string) error { return os.Rename(source, destination) }

func publishFile(source, destination, backup string) (bool, error) {
	if _, err := os.Stat(destination); errors.Is(err, os.ErrNotExist) {
		return false, os.Rename(source, destination)
	} else if err != nil {
		return false, err
	}
	if err := copyFile(destination, backup); err != nil {
		return true, err
	}
	return true, os.Rename(source, destination)
}

func restoreFile(backup, destination, replaced string) error {
	if err := os.Rename(destination, replaced); err != nil {
		return err
	}
	return os.Rename(backup, destination)
}

func copyFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
