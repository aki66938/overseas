//go:build windows

// Package secret stores machine-scoped secrets using Windows DPAPI.
package secret

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const machineEntropy = "RegenBio/OverseasAccess/v1"

const machineSecretSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// ErrUnsupported is part of the portable package contract. Windows methods do
// not return it, but keeping it defined on every platform simplifies callers.
var ErrUnsupported = errors.New("machine secret storage is unsupported on this platform")

// StoreMachine DPAPI-encrypts plaintext for the local machine and atomically
// replaces path. The caller's plaintext buffer is zeroed before return.
func StoreMachine(path string, plaintext []byte) error {
	defer zero(plaintext)
	if path == "" {
		return errors.New("store machine secret: empty path")
	}

	ciphertext, err := protectMachine(plaintext)
	if err != nil {
		return fmt.Errorf("store machine secret: protect data: %w", err)
	}
	defer zero(ciphertext)

	dir := filepath.Dir(path)
	tempPath, file, err := createRestrictedTemp(dir)
	if err != nil {
		return fmt.Errorf("store machine secret: create temporary file: %w", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()

	if _, err := file.Write(ciphertext); err != nil {
		return fmt.Errorf("store machine secret: write temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("store machine secret: flush temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("store machine secret: close temporary file: %w", err)
	}
	if err := windows.Rename(tempPath, path); err != nil {
		return fmt.Errorf("store machine secret: replace destination: %w", err)
	}
	keep = true
	return nil
}

// LoadMachine decrypts a local-machine DPAPI blob. Callers are responsible for
// zeroing the returned plaintext as soon as it is no longer needed.
func LoadMachine(path string) ([]byte, error) {
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load machine secret: read file: %w", err)
	}
	defer zero(ciphertext)

	plaintext, err := unprotectMachine(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("load machine secret: unprotect data: %w", err)
	}
	return plaintext, nil
}

func protectMachine(plaintext []byte) ([]byte, error) {
	in := blob(plaintext)
	entropyBytes := []byte(machineEntropy)
	defer zero(entropyBytes)
	entropy := blob(entropyBytes)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		return nil, err
	}
	return copyAndFree(out), nil
}

func unprotectMachine(ciphertext []byte) ([]byte, error) {
	in := blob(ciphertext)
	entropyBytes := []byte(machineEntropy)
	defer zero(entropyBytes)
	entropy := blob(entropyBytes)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	return copyAndFree(out), nil
}

func blob(data []byte) windows.DataBlob {
	b := windows.DataBlob{Size: uint32(len(data))}
	if len(data) != 0 {
		b.Data = &data[0]
	}
	return b
}

func copyAndFree(blob windows.DataBlob) []byte {
	if blob.Data == nil {
		return []byte{}
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data))) //nolint:errcheck -- freeing process-local memory cannot be recovered from here
	source := unsafe.Slice(blob.Data, int(blob.Size))
	out := append([]byte(nil), source...)
	zero(source)
	return out
}

func createRestrictedTemp(dir string) (string, *os.File, error) {
	sd, err := windows.SecurityDescriptorFromString(machineSecretSDDL)
	if err != nil {
		return "", nil, err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}

	for range 32 {
		var random [16]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return "", nil, err
		}
		path := filepath.Join(dir, ".credential-"+hex.EncodeToString(random[:])+".tmp")
		pathUTF16, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return "", nil, err
		}
		handle, err := windows.CreateFile(
			pathUTF16,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			sa,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if err == nil {
			return path, os.NewFile(uintptr(handle), path), nil
		}
		if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return "", nil, err
		}
	}
	return "", nil, errors.New("could not allocate unique temporary file")
}

func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
