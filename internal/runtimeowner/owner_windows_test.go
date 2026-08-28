//go:build windows

package runtimeowner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPublishSerializesTwoProcessesAcrossTheWholeLedgerTransaction(t *testing.T) {
	if role := os.Getenv("RUNTIMEOWNER_CHILD_ROLE"); role != "" {
		dir := os.Getenv("RUNTIMEOWNER_CHILD_DIR")
		name := map[string]string{"first": "credential.bin", "second": "sing-box.json"}[role]
		err := publishAt(filepath.Join(dir, "runtime-owned.json"), filepath.Join(dir, name), func(path string) error {
			if err := os.WriteFile(filepath.Join(dir, role+".started"), []byte("started"), 0o600); err != nil {
				return err
			}
			deadline := time.Now().Add(10 * time.Second)
			for !fileExists(filepath.Join(dir, role+".release")) {
				if time.Now().After(deadline) {
					t.Fatal("timed out waiting for parent release")
				}
				time.Sleep(10 * time.Millisecond)
			}
			return os.WriteFile(path, []byte(role+"-sensitive"), 0o600)
		}, defaultOwnerOps())
		if err != nil {
			_ = os.WriteFile(filepath.Join(dir, role+".error"), []byte(err.Error()), 0o600)
			t.Fatal(err)
		}
		return
	}

	dir := t.TempDir()
	start := func(role string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPublishSerializesTwoProcessesAcrossTheWholeLedgerTransaction$")
		cmd.Env = append(os.Environ(), "RUNTIMEOWNER_CHILD_ROLE="+role, "RUNTIMEOWNER_CHILD_DIR="+dir)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	first := start("first")
	waitForFile(t, filepath.Join(dir, "first.started"))
	second := start("second")
	time.Sleep(250 * time.Millisecond)
	if fileExists(filepath.Join(dir, "second.started")) {
		t.Fatal("second writer entered while first process held the ownership transaction")
	}
	if err := os.WriteFile(filepath.Join(dir, "first.release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err != nil {
		t.Fatal(err)
	}
	waitForEither(t, filepath.Join(dir, "second.started"), filepath.Join(dir, "second.error"))
	if contents, err := os.ReadFile(filepath.Join(dir, "second.error")); err == nil {
		t.Fatalf("second child failed: %s", contents)
	}
	if err := os.WriteFile(filepath.Join(dir, "second.release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := second.Wait(); err != nil {
		t.Fatal(err)
	}
	ledger, err := readLedger(filepath.Join(dir, "runtime-owned.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Intents) != 0 || len(ledger.Finalized) != 2 {
		t.Fatalf("serialized ledger = %#v", ledger)
	}
}

func TestCrashAtPublicationBoundariesLeavesEveryResidueInStructuredIntent(t *testing.T) {
	if mode := os.Getenv("RUNTIMEOWNER_CRASH_MODE"); mode != "" {
		dir := os.Getenv("RUNTIMEOWNER_CRASH_DIR")
		ledgerPath := filepath.Join(dir, "runtime-owned.json")
		targetPath := filepath.Join(dir, "sing-box.json")
		ops := defaultOwnerOps()
		if mode == "published" {
			realPublish := ops.publish
			ops.publish = func(source, destination, backup string) (bool, error) {
				hadPrevious, err := realPublish(source, destination, backup)
				if err == nil {
					os.Exit(97)
				}
				return hadPrevious, err
			}
		}
		if mode == "finalized" {
			realWrite := ops.writeLedger
			ops.writeLedger = func(path string, ledger ownershipLedger) error {
				if err := realWrite(path, ledger); err != nil {
					return err
				}
				if len(ledger.Intents) == 1 && ledger.Intents[0].Phase == "published" && len(ledger.Finalized) == 1 {
					os.Exit(98)
				}
				return nil
			}
		}
		err := publishAt(ledgerPath, targetPath, func(path string) error {
			if err := os.WriteFile(path, []byte("new-sensitive-config"), 0o600); err != nil {
				return err
			}
			if mode == "temporary" {
				os.Exit(96)
			}
			return nil
		}, ops)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("crash injection did not terminate the child")
	}

	for _, mode := range []string{"temporary", "published", "finalized"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if mode != "temporary" {
				if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte("old-config"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := writeLedgerAtomic(filepath.Join(dir, "runtime-owned.json"), ownershipLedger{SchemaVersion: 2, Finalized: []string{"sing-box.json"}}); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashAtPublicationBoundariesLeavesEveryResidueInStructuredIntent$")
			cmd.Env = append(os.Environ(), "RUNTIMEOWNER_CRASH_MODE="+mode, "RUNTIMEOWNER_CRASH_DIR="+dir)
			if err := cmd.Run(); err == nil {
				t.Fatal("crash child unexpectedly succeeded")
			}
			ledger, err := readLedger(filepath.Join(dir, "runtime-owned.json"))
			if err != nil || len(ledger.Intents) != 1 {
				t.Fatalf("crash ledger = %#v, err = %v", ledger, err)
			}
			intent := ledger.Intents[0]
			owned := map[string]bool{"runtime-owned.json": true, intent.Target: true, intent.Temporary: true, intent.Backup: true, intent.Replaced: true}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !owned[entry.Name()] {
					t.Fatalf("untracked crash residue %q for intent %#v", entry.Name(), intent)
				}
			}
		})
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !fileExists(path) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForEither(t *testing.T, paths ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, path := range paths {
			if fileExists(path) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %v", paths)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
