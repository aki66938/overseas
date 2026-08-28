package runtimeowner

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPublishRecordsIntentBeforeTemporaryPublicationAndFinalizes(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "runtime-owned.json")
	targetPath := filepath.Join(dir, "credential.bin")
	writerObservedIntent := false

	err := publishAt(ledgerPath, targetPath, func(temporaryPath string) error {
		got, err := readLedger(ledgerPath)
		if err != nil {
			return err
		}
		writerObservedIntent = len(got.Intents) == 1 && got.Intents[0].Target == "credential.bin" &&
			filepath.Join(dir, got.Intents[0].Temporary) == temporaryPath && got.Intents[0].Phase == "prepared" &&
			got.Intents[0].Backup != "" && got.Intents[0].Replaced != "" && len(got.Finalized) == 0
		return os.WriteFile(temporaryPath, []byte("encrypted-credential"), 0o600)
	}, defaultOwnerOps())
	if err != nil {
		t.Fatal(err)
	}
	if !writerObservedIntent {
		t.Fatal("writer ran before the ownership intent was durable")
	}
	got, err := readLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 2 || len(got.Intents) != 0 || !reflect.DeepEqual(got.Finalized, []string{"credential.bin"}) {
		t.Fatalf("ledger = %#v, want one finalized credential and no intent", got)
	}
	if contents, err := os.ReadFile(targetPath); err != nil || string(contents) != "encrypted-credential" {
		t.Fatalf("published contents = %q, err = %v", contents, err)
	}
	assertOnlyFiles(t, dir, "credential.bin", "runtime-owned.json")
}

func TestPublishRevertsExistingFileAndCompensatesIntentWhenFinalizeFails(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "runtime-owned.json")
	targetPath := filepath.Join(dir, "sing-box.json")
	if err := os.WriteFile(targetPath, []byte("old-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeLedgerAtomic(ledgerPath, ownershipLedger{SchemaVersion: 2, Finalized: []string{"sing-box.json"}}); err != nil {
		t.Fatal(err)
	}

	ops := defaultOwnerOps()
	realWriteLedger := ops.writeLedger
	failedFinalize := false
	ops.writeLedger = func(path string, value ownershipLedger) error {
		if !failedFinalize && len(value.Intents) == 1 && reflect.DeepEqual(value.Finalized, []string{"sing-box.json"}) {
			failedFinalize = true
			return errors.New("injected finalize failure")
		}
		return realWriteLedger(path, value)
	}
	err := publishAt(ledgerPath, targetPath, func(temporaryPath string) error {
		return os.WriteFile(temporaryPath, []byte("new-config"), 0o600)
	}, ops)
	if err == nil || !failedFinalize {
		t.Fatalf("publish error = %v, finalize injection observed = %v", err, failedFinalize)
	}
	contents, err := os.ReadFile(targetPath)
	if err != nil || string(contents) != "old-config" {
		t.Fatalf("reverted contents = %q, err = %v", contents, err)
	}
	got, err := readLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Intents) != 0 || !reflect.DeepEqual(got.Finalized, []string{"sing-box.json"}) {
		t.Fatalf("compensated ledger = %#v", got)
	}
	assertOnlyFiles(t, dir, "runtime-owned.json", "sing-box.json")
}

func TestPublishFailureRemovesNewIntentAndEveryTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "runtime-owned.json")
	targetPath := filepath.Join(dir, "credential.bin")
	errInjected := errors.New("injected writer failure")

	err := publishAt(ledgerPath, targetPath, func(temporaryPath string) error {
		if err := os.WriteFile(temporaryPath, []byte("partial-ciphertext"), 0o600); err != nil {
			return err
		}
		return errInjected
	}, defaultOwnerOps())
	if !errors.Is(err, errInjected) {
		t.Fatalf("publish error = %v, want injected error", err)
	}
	if _, err := os.Stat(targetPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination survived failed publication: %v", err)
	}
	if _, err := os.Stat(ledgerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty ownership ledger survived compensation: %v", err)
	}
	assertOnlyFiles(t, dir)
}

func TestPublishRetainsIntentWhenPostPublishSecureCompensationFails(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "runtime-owned.json")
	targetPath := filepath.Join(dir, "credential.bin")
	ops := defaultOwnerOps()
	realWriteLedger := ops.writeLedger
	failedFinalize := false
	ops.writeLedger = func(path string, value ownershipLedger) error {
		if !failedFinalize && len(value.Intents) == 1 && reflect.DeepEqual(value.Finalized, []string{"credential.bin"}) {
			failedFinalize = true
			return errors.New("injected finalize failure")
		}
		return realWriteLedger(path, value)
	}
	realWipe := ops.wipe
	ops.wipe = func(path string) error {
		if path == targetPath {
			return errors.New("injected secure wipe failure")
		}
		return realWipe(path)
	}
	err := publishAt(ledgerPath, targetPath, func(temporaryPath string) error {
		return os.WriteFile(temporaryPath, []byte("new-ciphertext"), 0o600)
	}, ops)
	if err == nil || !failedFinalize {
		t.Fatalf("publish error = %v, finalize injection observed = %v", err, failedFinalize)
	}
	got, readErr := readLedger(ledgerPath)
	if readErr != nil {
		t.Fatalf("ownership intent was lost after compensation failure: %v", readErr)
	}
	if len(got.Intents) != 1 || got.Intents[0].Target != "credential.bin" || len(got.Finalized) != 0 {
		t.Fatalf("ledger = %#v, want retained credential intent", got)
	}
	if _, statErr := os.Stat(targetPath); statErr != nil {
		t.Fatalf("injected wipe failure did not preserve test residue: %v", statErr)
	}
}

func TestPublishRetainsEveryTransientWhenBackupWipeFails(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "runtime-owned.json")
	targetPath := filepath.Join(dir, "sing-box.json")
	if err := os.WriteFile(targetPath, []byte("old-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeLedgerAtomic(ledgerPath, ownershipLedger{SchemaVersion: 2, Finalized: []string{"sing-box.json"}}); err != nil {
		t.Fatal(err)
	}
	ops := defaultOwnerOps()
	realWipe := ops.wipe
	ops.wipe = func(path string) error {
		if filepath.Base(path) != "" && len(filepath.Base(path)) > 20 && filepath.Ext(path) == ".tmp" &&
			containsText(filepath.Base(path), ".backup-") {
			return errors.New("injected backup wipe failure")
		}
		return realWipe(path)
	}
	err := publishAt(ledgerPath, targetPath, func(path string) error { return os.WriteFile(path, []byte("new-config"), 0o600) }, ops)
	if err == nil {
		t.Fatal("publish succeeded despite backup wipe failure")
	}
	got, readErr := readLedger(ledgerPath)
	if readErr != nil || len(got.Intents) != 1 || got.Intents[0].Phase != "published" || !reflect.DeepEqual(got.Finalized, []string{"sing-box.json"}) {
		t.Fatalf("ledger after backup wipe failure = %#v, err = %v", got, readErr)
	}
	intent := got.Intents[0]
	if _, statErr := os.Stat(filepath.Join(dir, intent.Backup)); statErr != nil {
		t.Fatalf("recorded backup is absent: %v", statErr)
	}
	if _, statErr := os.Stat(targetPath); statErr != nil {
		t.Fatalf("recorded canonical file is absent: %v", statErr)
	}
}

func containsText(value, fragment string) bool {
	return len(value) >= len(fragment) && strings.Contains(value, fragment)
}

func assertOnlyFiles(t *testing.T, dir string, expected ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	if len(got) != len(expected) || (len(got) != 0 && !reflect.DeepEqual(got, expected)) {
		t.Fatalf("directory entries = %v, want %v", got, expected)
	}
}
