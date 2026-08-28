//go:build !windows

// Package secret stores machine-scoped secrets on supported platforms.
package secret

import "errors"

// ErrUnsupported reports that machine-scoped DPAPI storage is Windows-only.
var ErrUnsupported = errors.New("machine secret storage is unsupported on this platform")

func StoreMachine(_ string, plaintext []byte) error {
	for i := range plaintext {
		plaintext[i] = 0
	}
	return ErrUnsupported
}

func StoreMachineExact(_ string, plaintext []byte) error {
	for i := range plaintext {
		plaintext[i] = 0
	}
	return ErrUnsupported
}

func LoadMachine(_ string) ([]byte, error) {
	return nil, ErrUnsupported
}
