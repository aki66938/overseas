// Package runtimeowner atomically publishes sensitive runtime files while a
// durable ledger owns every canonical and transient pathname.
package runtimeowner

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const LedgerPath = `C:\ProgramData\RegenBio\OverseasAccess\runtime-owned.json`

type ownershipIntent struct {
	Target    string `json:"target"`
	Temporary string `json:"temporary"`
	Backup    string `json:"backup"`
	Replaced  string `json:"replaced"`
	Phase     string `json:"phase"`
}
type ownershipLedger struct {
	SchemaVersion int               `json:"schema_version"`
	Intents       []ownershipIntent `json:"intents"`
	Finalized     []string          `json:"finalized"`
}
type ownerOps struct {
	writeLedger func(string, ownershipLedger) error
	publish     func(source, destination, backup string) (bool, error)
	restore     func(backup, destination, replaced string) error
	wipe        func(string) error
	lock        func() (func(), error)
}
type intentPaths struct{ temporary, backup, replaced string }

func Publish(path string, writeTemporary func(string) error) error {
	return publishAt(LedgerPath, path, writeTemporary, defaultOwnerOps())
}

func publishAt(ledgerPath, path string, writeTemporary func(string) error, ops ownerOps) error {
	unlock, err := ops.lock()
	if err != nil {
		return fmt.Errorf("lock runtime ownership transaction: %w", err)
	}
	defer unlock()
	name := filepath.Base(path)
	if !supported(name) || filepath.Clean(filepath.Dir(path)) != filepath.Clean(filepath.Dir(ledgerPath)) {
		return errors.New("unsupported runtime-owned file")
	}
	previous, ledgerExisted, err := loadLedger(ledgerPath)
	if err != nil {
		return err
	}
	if hasIntent(previous.Intents, name) {
		return errors.New("unresolved runtime ownership intent")
	}
	intent, paths, err := newIntent(path)
	if err != nil {
		return err
	}
	intended := cloneLedger(previous)
	intended.Intents = append(intended.Intents, intent)
	intended = normalizeLedger(intended)
	if err := ops.writeLedger(ledgerPath, intended); err != nil {
		return fmt.Errorf("record runtime ownership intent: %w", err)
	}
	if err := writeTemporary(paths.temporary); err != nil {
		return compensateBeforePublish(ledgerPath, paths, previous, ledgerExisted, err, ops)
	}
	info, err := os.Lstat(paths.temporary)
	if err != nil || !info.Mode().IsRegular() {
		if err == nil {
			err = errors.New("temporary runtime file is not regular")
		}
		return compensateBeforePublish(ledgerPath, paths, previous, ledgerExisted, err, ops)
	}
	setPhase(intended.Intents, name, "temporary-written")
	if err := ops.writeLedger(ledgerPath, intended); err != nil {
		return compensateBeforePublish(ledgerPath, paths, previous, ledgerExisted, err, ops)
	}
	setPhase(intended.Intents, name, "publishing")
	if err := ops.writeLedger(ledgerPath, intended); err != nil {
		return compensateBeforePublish(ledgerPath, paths, previous, ledgerExisted, err, ops)
	}
	hadPrevious, err := ops.publish(paths.temporary, path, paths.backup)
	if err != nil {
		return compensateBeforePublish(ledgerPath, paths, previous, ledgerExisted, err, ops)
	}
	setPhase(intended.Intents, name, "published")
	if err := ops.writeLedger(ledgerPath, intended); err != nil {
		return errors.Join(fmt.Errorf("record published runtime ownership: %w", err), compensateAfterPublish(ledgerPath, path, paths, previous, ledgerExisted, hadPrevious, ops))
	}
	// Finalized is durable while the intent still owns transient paths.
	withFinalized := cloneLedger(intended)
	withFinalized.Finalized = sortedAdd(withFinalized.Finalized, name)
	if err := ops.writeLedger(ledgerPath, withFinalized); err != nil {
		return errors.Join(fmt.Errorf("finalize runtime ownership: %w", err), compensateAfterPublish(ledgerPath, path, paths, previous, ledgerExisted, hadPrevious, ops))
	}
	if err := wipePaths(paths, ops); err != nil {
		return fmt.Errorf("remove transient sensitive runtime file: %w", err)
	}
	finalized := cloneLedger(withFinalized)
	finalized.Intents = removeIntent(finalized.Intents, name)
	if err := ops.writeLedger(ledgerPath, finalized); err != nil {
		return fmt.Errorf("complete runtime ownership finalization: %w", err)
	}
	return nil
}

func newIntent(path string) (ownershipIntent, intentPaths, error) {
	var p intentPaths
	var err error
	if p.temporary, err = uniqueSibling(path, "publish"); err != nil {
		return ownershipIntent{}, p, err
	}
	if p.backup, err = uniqueSibling(path, "backup"); err != nil {
		return ownershipIntent{}, p, err
	}
	if p.replaced, err = uniqueSibling(path, "replaced"); err != nil {
		return ownershipIntent{}, p, err
	}
	return ownershipIntent{Target: filepath.Base(path), Temporary: filepath.Base(p.temporary), Backup: filepath.Base(p.backup), Replaced: filepath.Base(p.replaced), Phase: "prepared"}, p, nil
}
func setPhase(intents []ownershipIntent, target, phase string) {
	for i := range intents {
		if intents[i].Target == target {
			intents[i].Phase = phase
			return
		}
	}
}
func compensateBeforePublish(ledgerPath string, paths intentPaths, previous ownershipLedger, existed bool, cause error, ops ownerOps) error {
	if wipeErr := wipePaths(paths, ops); wipeErr != nil {
		return errors.Join(cause, wipeErr)
	}
	return errors.Join(cause, restoreLedger(ledgerPath, previous, existed, ops))
}
func compensateAfterPublish(ledgerPath, path string, paths intentPaths, previous ownershipLedger, existed, hadPrevious bool, ops ownerOps) error {
	var fileErr error
	if hadPrevious {
		fileErr = ops.restore(paths.backup, path, paths.replaced)
		fileErr = errors.Join(fileErr, ops.wipe(paths.replaced))
	} else {
		fileErr = ops.wipe(path)
	}
	fileErr = errors.Join(fileErr, ops.wipe(paths.temporary), ops.wipe(paths.backup))
	if fileErr != nil {
		return fileErr
	}
	return restoreLedger(ledgerPath, previous, existed, ops)
}
func wipePaths(paths intentPaths, ops ownerOps) error {
	return errors.Join(ops.wipe(paths.temporary), ops.wipe(paths.backup), ops.wipe(paths.replaced))
}
func restoreLedger(path string, previous ownershipLedger, existed bool, ops ownerOps) error {
	if existed || len(previous.Intents) != 0 || len(previous.Finalized) != 0 {
		return ops.writeLedger(path, previous)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func defaultOwnerOps() ownerOps {
	return ownerOps{writeLedger: writeLedgerAtomic, publish: publishFile, restore: restoreFile, wipe: secureRemove, lock: lockRuntimeOwnership}
}

func loadLedger(path string) (ownershipLedger, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ownershipLedger{SchemaVersion: 2}, false, nil
	}
	if err != nil {
		return ownershipLedger{}, false, err
	}
	var v ownershipLedger
	if json.Unmarshal(b, &v) != nil || v.SchemaVersion != 2 {
		return ownershipLedger{}, true, errors.New("invalid runtime ownership ledger")
	}
	if err := validateIntents(v.Intents); err != nil {
		return ownershipLedger{}, true, err
	}
	if err := validateNames(v.Finalized); err != nil {
		return ownershipLedger{}, true, err
	}
	return normalizeLedger(v), true, nil
}
func readLedger(path string) (ownershipLedger, error) {
	v, ok, err := loadLedger(path)
	if err != nil {
		return ownershipLedger{}, err
	}
	if !ok {
		return ownershipLedger{}, os.ErrNotExist
	}
	return v, nil
}
func writeLedgerAtomic(path string, value ownershipLedger) error {
	value = normalizeLedger(value)
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".runtime-owned-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		return err
	}
	keep = true
	return nil
}
func secureRemove(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, statErr := f.Stat()
	if statErr == nil && info.Mode().IsRegular() {
		zero := make([]byte, 64*1024)
		remaining := info.Size()
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			return err
		}
		for remaining > 0 {
			n := int64(len(zero))
			if remaining < n {
				n = remaining
			}
			if _, err := f.Write(zero[:n]); err != nil {
				_ = f.Close()
				return err
			}
			remaining -= n
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func uniqueSibling(path, kind string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+kind+"-"+hex.EncodeToString(random[:])+".tmp"), nil
}
func supported(name string) bool { return name == "credential.bin" || name == "sing-box.json" }
func validateIntents(intents []ownershipIntent) error {
	seen := map[string]bool{}
	for _, in := range intents {
		if !supported(in.Target) || seen[in.Target] {
			return errors.New("invalid runtime ownership intent")
		}
		seen[in.Target] = true
		if in.Phase != "prepared" && in.Phase != "temporary-written" && in.Phase != "publishing" && in.Phase != "published" {
			return errors.New("invalid runtime ownership intent phase")
		}
		for kind, name := range map[string]string{"publish": in.Temporary, "backup": in.Backup, "replaced": in.Replaced} {
			if filepath.Base(name) != name || !strings.HasPrefix(name, "."+in.Target+"."+kind+"-") || !strings.HasSuffix(name, ".tmp") {
				return errors.New("invalid runtime ownership transient path")
			}
		}
		if in.Temporary == in.Backup || in.Temporary == in.Replaced || in.Backup == in.Replaced {
			return errors.New("duplicate runtime ownership transient path")
		}
	}
	return nil
}
func validateNames(names []string) error {
	seen := map[string]bool{}
	for _, n := range names {
		if !supported(n) || seen[n] {
			return errors.New("invalid runtime ownership entry")
		}
		seen[n] = true
	}
	return nil
}
func normalizeLedger(v ownershipLedger) ownershipLedger {
	v.SchemaVersion = 2
	sort.Slice(v.Intents, func(i, j int) bool { return v.Intents[i].Target < v.Intents[j].Target })
	v.Finalized = sortedUnique(v.Finalized)
	return v
}
func cloneLedger(v ownershipLedger) ownershipLedger {
	return ownershipLedger{SchemaVersion: v.SchemaVersion, Intents: append([]ownershipIntent(nil), v.Intents...), Finalized: append([]string(nil), v.Finalized...)}
}
func hasIntent(v []ownershipIntent, target string) bool {
	for _, x := range v {
		if x.Target == target {
			return true
		}
	}
	return false
}
func removeIntent(v []ownershipIntent, target string) []ownershipIntent {
	out := v[:0]
	for _, x := range v {
		if x.Target != target {
			out = append(out, x)
		}
	}
	return out
}
func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
func sortedAdd(v []string, s string) []string {
	if !contains(v, s) {
		v = append(v, s)
	}
	return sortedUnique(v)
}
func sortedUnique(v []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(v))
	for _, x := range v {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
