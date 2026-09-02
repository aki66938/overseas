//go:build windows

package coreverify

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fileBasicInformation struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

func readFileIdentity(path string) (FileIdentity, error) {
	file, err := openRegularFileNoReparse(path)
	if err != nil {
		return FileIdentity{}, err
	}
	defer file.Close()
	return fileIdentityFromOpenFile(file)
}

func fileIdentityFromOpenFile(file *os.File) (FileIdentity, error) {
	if file == nil {
		return FileIdentity{}, errors.New("open executable is required")
	}
	handle := syscall.Handle(file.Fd())
	var handleInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		return FileIdentity{}, err
	}
	var basic fileBasicInformation
	if err := windows.GetFileInformationByHandleEx(windows.Handle(handle), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return FileIdentity{}, err
	}
	return FileIdentity{
		VolumeSerialNumber: handleInfo.VolumeSerialNumber,
		FileIndex:          uint64(handleInfo.FileIndexHigh)<<32 | uint64(handleInfo.FileIndexLow),
		Size:               int64(uint64(handleInfo.FileSizeHigh)<<32 | uint64(handleInfo.FileSizeLow)),
		LastWriteTime:      basic.LastWriteTime, ChangeTime: basic.ChangeTime,
		FileAttributes: basic.FileAttributes,
	}, nil
}
