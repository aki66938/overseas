//go:build windows

package agent

import (
	"context"
	"errors"
	"testing"
)

// The PoC fast path: sing-box auto_route owns routes and tun DNS; the
// product prepares in-memory, arms nothing, flushes the resolver cache,
// and proves the tun gone on restore.

func TestPocPrepareReturnsInMemoryGeneration(t *testing.T) {
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{validPreparedBaseline()}}))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Generation != 1 || prepared.RuleCount != 0 {
		t.Fatalf("prepared = %+v", prepared)
	}
}

func TestPocPrepareRefusesForeignTunnel(t *testing.T) {
	baseline := validPreparedBaseline()
	baseline.Adapters = append(baseline.Adapters, WindowsNativeAdapter{
		InterfaceIndex: 9, InterfaceGuid: "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
		InterfaceAlias: "Clash", Description: "Wintun Userspace Tunnel",
	})
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(&scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Prepare(context.Background()); !errors.Is(err, errVPNConflict) {
		t.Fatalf("Prepare() error = %v, want vpn conflict", err)
	}
}

func TestPocCaptureMatchesFingerprintAndWaitsForTun(t *testing.T) {
	baseline := validPreparedBaseline()
	reader := &scriptedNativeReader{baselines: []WindowsNetworkBaseline{baseline}, tun: validTUNIdentity(), tunReady: true}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Capture(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	_ = snapshot
	if err := manager.EnableProtection(context.Background(), prepared); err != nil {
		t.Fatalf("EnableProtection() = %v, want no-op success", err)
	}
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	reader.mu.Lock()
	reader.tunReady = false
	reader.mu.Unlock()
	residue, err := manager.Residue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !residue.IsZero() {
		t.Fatalf("residue after restore = %#v, want zero", residue)
	}
}

func TestPocWaitTUNRejectsForeignIdentity(t *testing.T) {
	reader := &scriptedNativeReader{baselines: []WindowsNetworkBaseline{validPreparedBaseline()}, tunReady: true}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{},
		withWindowsNativeNetworkReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	prepared, _ := manager.Prepare(context.Background())
	if _, err := manager.Capture(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	reader.mu.Lock()
	foreign := validTUNIdentity()
	foreign.InterfaceAlias = "Ethernet"
	reader.tun = foreign
	reader.mu.Unlock()
	if err := manager.WaitTUNReady(context.Background()); !errors.Is(err, errTUNIdentityMismatch) {
		t.Fatalf("WaitTUNReady() = %v, want identity mismatch", err)
	}
}
