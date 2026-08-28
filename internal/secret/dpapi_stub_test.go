//go:build !windows

package secret

import (
	"errors"
	"testing"
)

func TestMachineStoreAndLoadAreUnsupported(t *testing.T) {
	plaintext := []byte("secret")
	if err := StoreMachine("credential.bin", plaintext); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("StoreMachine error = %v, want ErrUnsupported", err)
	}
	if _, err := LoadMachine("credential.bin"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("LoadMachine error = %v, want ErrUnsupported", err)
	}
}
