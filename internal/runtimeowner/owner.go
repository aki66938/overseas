package runtimeowner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

const LedgerPath = `C:\ProgramData\RegenBio\OverseasAccess\runtime-owned.json`

type ledger struct {
	SchemaVersion int      `json:"schema_version"`
	Files         []string `json:"files"`
}

func Record(path string) error {
	name := filepath.Base(path)
	if name != "credential.bin" && name != "sing-box.json" {
		return errors.New("unsupported runtime-owned file")
	}
	l := ledger{SchemaVersion: 1}
	if b, err := os.ReadFile(LedgerPath); err == nil {
		if json.Unmarshal(b, &l) != nil || l.SchemaVersion != 1 {
			return errors.New("invalid runtime ownership ledger")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	seen := map[string]bool{name: true}
	for _, n := range l.Files {
		if n != "credential.bin" && n != "sing-box.json" {
			return errors.New("invalid runtime ownership entry")
		}
		seen[n] = true
	}
	l.Files = nil
	for n := range seen {
		l.Files = append(l.Files, n)
	}
	sort.Strings(l.Files)
	b, _ := json.Marshal(l)
	tmp := LedgerPath + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return replaceFile(tmp, LedgerPath)
}
