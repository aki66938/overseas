//go:build windows

package runtimeowner

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const replaceFileWriteThrough = 0x1

var replaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

func lockRuntimeOwnership() (func(), error) {
	runtime.LockOSThread()
	name, err := windows.UTF16PtrFromString(`Global\RegenBioOverseasAccess.RuntimeOwner`)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		runtime.UnlockOSThread()
		return nil, err
	}
	status, err := windows.WaitForSingleObject(handle, windows.INFINITE)
	if err != nil || (status != windows.WAIT_OBJECT_0 && status != windows.WAIT_ABANDONED) {
		_ = windows.CloseHandle(handle)
		runtime.UnlockOSThread()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("could not acquire runtime ownership mutex")
	}
	return func() {
		_ = windows.ReleaseMutex(handle)
		_ = windows.CloseHandle(handle)
		runtime.UnlockOSThread()
	}, nil
}

func replaceFile(source, destination string) error {
	return windows.MoveFileEx(windows.StringToUTF16Ptr(source), windows.StringToUTF16Ptr(destination), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func publishFile(source, destination, backup string) (bool, error) {
	if _, err := os.Stat(destination); errors.Is(err, os.ErrNotExist) {
		return false, replaceFile(source, destination)
	} else if err != nil {
		return false, err
	}
	return true, callReplaceFile(destination, source, backup)
}

func restoreFile(backup, destination, replaced string) error {
	return callReplaceFile(destination, backup, replaced)
}

func callReplaceFile(destination, replacement, backup string) error {
	destinationPtr, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	replacementPtr, err := windows.UTF16PtrFromString(replacement)
	if err != nil {
		return err
	}
	backupPtr, err := windows.UTF16PtrFromString(backup)
	if err != nil {
		return err
	}
	result, _, callErr := replaceFileW.Call(uintptr(unsafe.Pointer(destinationPtr)), uintptr(unsafe.Pointer(replacementPtr)), uintptr(unsafe.Pointer(backupPtr)), replaceFileWriteThrough, 0, 0)
	if result == 0 {
		return callErr
	}
	return nil
}
