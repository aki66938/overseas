//go:build windows

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestLiveWindowsPowerShellProtectionTransaction(t *testing.T) {
	if os.Getenv("OVERSEAS_ACCESS_NETWORK_GATE") != "1" {
		t.Skip("live gate disabled")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if got := user.User.Sid.String(); got != "S-1-5-18" {
		t.Fatalf("gate is not LocalSystem: %s", got)
	}

	statePath := filepath.Join(t.TempDir(), "network-state.json")
	manager, err := newWindowsNetworkManager(validPolicy(), statePath, powerShellNetworkRunner{}, fileSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	snapshot, err := manager.Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored := false
	defer func() {
		if restored {
			return
		}
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if restoreErr := manager.Restore(cleanupContext, snapshot); restoreErr != nil {
			t.Errorf("cleanup restore: %v", restoreErr)
		}
	}()

	if _, err := manager.InstallPublicTCPBlock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	restored = true
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state residue: %v", err)
	}
}
