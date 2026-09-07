package diagnosticmode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/traceevent"
)

func TestGateDefaultExpiryRestartAndRedaction(t *testing.T) {
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	dir := filepath.Join(t.TempDir(), "logs")
	config := traceevent.RecorderConfig{Directory: dir, MemoryCapacity: 8, MaxFileBytes: 2 << 20, RetainFiles: 5, Now: func() time.Time { return now }}
	g := New(config)
	defer g.Close()
	event := traceevent.Event{Level: traceevent.LevelError, Component: traceevent.ComponentCore, Stage: traceevent.StageCoreReady, Event: traceevent.EventFailed, Message: "core failed", Detail: "password=super-secret"}
	g.Record(event)
	g.Write([]byte("password=super-secret\n"))
	if g.Enabled(now) || len(g.Batch(0, 8).Events) != 0 {
		t.Fatal("default collects diagnostics")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("default created directory: %v", err)
	}
	for _, minutes := range []int{15, 30, 60} {
		if err := g.Enable(now, time.Duration(minutes)*time.Minute); err != nil {
			t.Fatal(err)
		}
		g.Record(event)
		g.Write([]byte("password=super-secret\n"))
		if !g.Enabled(now) || len(g.Batch(0, 8).Events) != 2 {
			t.Fatal("enabled mode did not collect")
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		last := files[len(files)-1]
		data, err := os.ReadFile(last)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "super-secret") {
			t.Fatal("credential persisted")
		}
		now = now.Add(time.Duration(minutes) * time.Minute)
		if g.Enabled(now) || len(g.Batch(0, 8).Events) != 0 {
			t.Fatal("expired mode still collects")
		}
		// Windows rename fails for an open recorder handle: expiry must close it.
		if err := os.Rename(last, last+".closed"); err != nil {
			t.Fatalf("expiry did not close file: %v", err)
		}
	}
	if err := g.Enable(now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := New(config)
	defer restarted.Close()
	if restarted.Enabled(now) {
		t.Fatal("restart restored enabled mode")
	}
	if err := g.Enable(now, 15*time.Minute); err == nil {
		t.Fatal("closed gate reopened")
	}
}

func TestGateRejectsDurationsAndCreationFailure(t *testing.T) {
	now := time.Now()
	g := New(traceevent.RecorderConfig{Directory: filepath.Join(t.TempDir(), "missing", "logs"), MemoryCapacity: 8, MaxFileBytes: 2 << 20, RetainFiles: 5})
	defer g.Close()
	for _, duration := range []time.Duration{0, -time.Minute, time.Minute, 16 * time.Minute, 61 * time.Minute} {
		if err := g.Enable(now, duration); err == nil {
			t.Fatalf("accepted %s", duration)
		}
	}
	if err := g.Enable(now, 15*time.Minute); err == nil || g.Enabled(now) {
		t.Fatal("creation failure enabled collection")
	}
}

func TestGateTimerExpiresWithoutTrafficAndStaleTimerCannotCloseRenewal(t *testing.T) {
	now := time.Now()
	g := New(traceevent.RecorderConfig{Directory: filepath.Join(t.TempDir(), "logs"), MemoryCapacity: 8, MaxFileBytes: 2 << 20, RetainFiles: 5, Now: func() time.Time { return now }})
	defer g.Close()
	var callbacks []func()
	g.afterFunc = func(d time.Duration, f func()) timer { callbacks = append(callbacks, f); return &fakeTimer{} }
	if err := g.Enable(now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := g.Enable(now, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	callbacks[0]()
	if !g.Enabled(now) {
		t.Fatal("stale timer closed renewal")
	}
	callbacks[1]()
	if g.recorder != nil {
		t.Fatal("timer did not release recorder")
	}
}

type fakeTimer struct{}

func (*fakeTimer) Stop() bool { return true }

func TestGateNeverPersistsSuffixOfDisabledPartialLine(t *testing.T) {
	now := time.Now()
	g := New(traceevent.RecorderConfig{Directory: filepath.Join(t.TempDir(), "logs"), MemoryCapacity: 8, MaxFileBytes: 2 << 20, RetainFiles: 5, Now: func() time.Time { return now }})
	defer g.Close()
	g.Write([]byte("password="))
	if err := g.Enable(now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	g.Write([]byte("secret\nvalid line\npassword="))
	batch := g.Batch(0, 8)
	if len(batch.Events) != 1 || batch.Events[0].Detail != "valid line" {
		t.Fatalf("disabled suffix collected: %+v", batch)
	}
	now = now.Add(15 * time.Minute)
	g.Enabled(now)
	if err := g.Enable(now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	g.Write([]byte("secret\nnew line\n"))
	batch = g.Batch(0, 8)
	if len(batch.Events) != 1 || batch.Events[0].Detail != "new line" {
		t.Fatalf("expired prefix leaked suffix: %+v", batch)
	}
}

func TestGateSeparatesOutputStreams(t *testing.T) {
	now := time.Now()
	g := New(traceevent.RecorderConfig{Directory: filepath.Join(t.TempDir(), "logs"), MemoryCapacity: 8, MaxFileBytes: 2 << 20, RetainFiles: 5})
	defer g.Close()
	stdout, stderr := g.NewOutputStream(), g.NewOutputStream()
	if err := g.Enable(now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	stdout.Write([]byte("password="))
	stderr.Write([]byte("separate error\n"))
	stdout.Write([]byte("super-secret\n"))
	batch := g.Batch(0, 8)
	if len(batch.Events) != 2 || batch.Events[0].Detail != "separate error" || strings.Contains(batch.Events[1].Detail, "super-secret") {
		t.Fatalf("streams combined: %+v", batch)
	}
}
