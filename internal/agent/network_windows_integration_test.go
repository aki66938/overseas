//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/traceevent"
	"golang.org/x/sys/windows"
)

const liveTraceEvidenceEnvironment = "OVERSEAS_ACCESS_TRACE_EVIDENCE_PATH"

type liveTraceEvidence struct {
	SchemaVersion   int                 `json:"schema_version"`
	AfterPrepare    []traceevent.Event  `json:"after_prepare"`
	AfterCapture    []traceevent.Event  `json:"after_capture"`
	AfterRestore    []traceevent.Event  `json:"after_restore"`
	TerminalResidue *traceevent.Residue `json:"terminal_residue,omitempty"`
}

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

	testRoot := t.TempDir()
	recorder, err := traceevent.NewRecorder(traceevent.RecorderConfig{
		Directory: filepath.Join(testRoot, "logs"), MemoryCapacity: 128, MaxFileBytes: 65536, RetainFiles: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	manager, err := newWindowsNetworkManager(validPolicy(), filepath.Join(testRoot, "network-state.json"), powerShellNetworkRunner{}, fileSnapshotStore{}, WithWindowsTraceSink(recorder))
	if err != nil {
		t.Fatal(err)
	}
	evidence := &liveTraceEvidence{SchemaVersion: 1}
	defer writeLiveTraceEvidence(t, os.Getenv(liveTraceEvidenceEnvironment), manager, recorder, evidence)
	ctx, cancel := context.WithTimeout(traceevent.WithGeneration(context.Background(), 1), 120*time.Second)
	defer cancel()

	prepared := tracedLiveStep(t, recorder, ctx, traceevent.StageNetworkPrepare, func() (PreparedNetwork, error) {
		return manager.Prepare(ctx)
	})
	evidence.AfterPrepare = recorder.Batch(0, 128).Events
	snapshot := tracedLiveStep(t, recorder, ctx, traceevent.StageNetworkCapture, func() (any, error) {
		return manager.Capture(ctx, prepared)
	})
	evidence.AfterCapture = recorder.Batch(0, 128).Events
	tracedLiveAction(t, recorder, ctx, traceevent.StageNetworkRestore, func() error {
		return manager.Restore(ctx, snapshot)
	})
	if _, err := os.Stat(filepath.Join(testRoot, "network-state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state residue: %v", err)
	}
	residue := tracedLiveStep(t, recorder, ctx, traceevent.StageResidueVerify, func() (traceevent.Residue, error) {
		return manager.Residue(ctx)
	})
	if !residue.IsZero() {
		t.Fatalf("network residue = %#v", residue)
	}
	evidence.TerminalResidue = &residue
	evidence.AfterRestore = recorder.Batch(0, 128).Events
	assertTracePairs(t, evidence.AfterRestore)
}

func tracedLiveStep[T any](t *testing.T, recorder *traceevent.Recorder, ctx context.Context, stage string, action func() (T, error)) T {
	t.Helper()
	started := time.Now()
	recorder.Record(traceevent.Event{Generation: traceevent.GenerationFromContext(ctx), Level: traceevent.LevelInfo, Component: traceevent.ComponentNetwork, Stage: stage, Event: traceevent.EventStarted, Message: "live transaction step started"})
	value, err := action()
	elapsed := time.Since(started).Milliseconds()
	if err != nil {
		recorder.Record(traceevent.Event{Generation: traceevent.GenerationFromContext(ctx), Level: traceevent.LevelError, Component: traceevent.ComponentNetwork, Stage: stage, Event: traceevent.EventFailed, ElapsedMS: &elapsed, Message: "live transaction step failed", Detail: err.Error()})
		t.Fatal(err)
	}
	recorder.Record(traceevent.Event{Generation: traceevent.GenerationFromContext(ctx), Level: traceevent.LevelInfo, Component: traceevent.ComponentNetwork, Stage: stage, Event: traceevent.EventSucceeded, ElapsedMS: &elapsed, Message: "live transaction step succeeded"})
	return value
}

func tracedLiveAction(t *testing.T, recorder *traceevent.Recorder, ctx context.Context, stage string, action func() error) {
	t.Helper()
	tracedLiveStep(t, recorder, ctx, stage, func() (struct{}, error) { return struct{}{}, action() })
}

func writeLiveTraceEvidence(t *testing.T, path string, manager *WindowsNetworkManager, source traceevent.Source, evidence *liveTraceEvidence) {
	t.Helper()
	if path == "" {
		return
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Errorf("trace evidence path is not absolute and clean")
		return
	}
	if evidence.TerminalResidue == nil {
		ctx, cancel := context.WithTimeout(traceevent.WithGeneration(context.Background(), 1), 30*time.Second)
		residue, err := manager.Residue(ctx)
		cancel()
		if err != nil {
			t.Errorf("terminal residue evidence: %v", err)
		} else {
			evidence.TerminalResidue = &residue
		}
	}
	if len(evidence.AfterRestore) == 0 {
		evidence.AfterRestore = source.Batch(0, 128).Events
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Errorf("marshal trace evidence: %v", err)
		return
	}
	if len(encoded) > 65536 {
		t.Errorf("trace evidence exceeds 65536 bytes")
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Errorf("create trace evidence: %v", err)
		return
	}
	if _, err := file.Write(encoded); err != nil {
		t.Errorf("write trace evidence: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Errorf("close trace evidence: %v", err)
	}
}
