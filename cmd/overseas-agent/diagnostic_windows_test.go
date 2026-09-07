//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/traceevent"
)

func TestServiceDiagnosticsStartInertAndGateChildOutput(t *testing.T) {
	now := time.Now()
	dir := filepath.Join(t.TempDir(), "logs")
	gate := newServiceDiagnostics(dir, func() time.Time { return now })
	defer gate.Close()
	core := &supervisedCore{diagnostics: gate}
	process := core.newProcess()
	if !process.DisableDiagnosticTail {
		t.Fatal("service retains an ungated child tail")
	}
	process.LogWriter.Write([]byte("disabled-secret\n"))
	gate.Record(traceevent.Event{Message: "off"})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("default touched disk: %v", err)
	}
	if err := gate.Enable(now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	process.LogWriter.Write([]byte("password=split-"))
	process.LogWriter.Write([]byte("secret\n"))
	batch := gate.Batch(0, 8)
	if len(batch.Events) != 1 || batch.Events[0].Detail == "password=split-secret" {
		t.Fatalf("batch=%+v", batch)
	}
	now = now.Add(15 * time.Minute)
	process.LogWriter.Write([]byte("expired-secret\n"))
	if gate.Enabled(now) || len(gate.Batch(0, 8).Events) != 0 {
		t.Fatal("expiry retained output")
	}
	if err := gate.Enable(now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	process.LogWriter.Write([]byte("new session\n"))
	batch = gate.Batch(0, 8)
	if len(batch.Events) != 1 || batch.Events[0].Detail != "new session" {
		t.Fatalf("old output resurfaced: %+v", batch)
	}
}
