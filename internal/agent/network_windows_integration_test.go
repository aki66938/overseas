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
	BeforePublish   []traceevent.Event  `json:"before_publish"`
	AfterPublish    []traceevent.Event  `json:"after_publish"`
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
	statePath := filepath.Join(testRoot, "network-state.json")
	recorder, err := traceevent.NewRecorder(traceevent.RecorderConfig{
		Directory: filepath.Join(testRoot, "logs"), MemoryCapacity: 128, MaxFileBytes: 65536, RetainFiles: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := recorder.Close(); err != nil {
			t.Errorf("close trace recorder: %v", err)
		}
	}()
	manager, err := newWindowsNetworkManager(validPolicy(), statePath, powerShellNetworkRunner{}, fileSnapshotStore{}, WithWindowsTraceSink(recorder))
	if err != nil {
		t.Fatal(err)
	}
	evidence := &liveTraceEvidence{SchemaVersion: 1}
	defer writeLiveTraceEvidence(t, os.Getenv(liveTraceEvidenceEnvironment), manager, recorder, evidence)
	ctx, cancel := context.WithTimeout(traceevent.WithGeneration(context.Background(), 1), 120*time.Second)
	defer cancel()
	prepared, err := manager.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Capture(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.EnableProtection(ctx, prepared); err != nil {
		t.Fatal(err)
	}
	evidence.BeforePublish = recorder.Batch(0, 128).Events
	restored := false
	defer func() {
		if restored {
			return
		}
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		if restoreErr := manager.Restore(cleanupContext, snapshot); restoreErr != nil {
			t.Errorf("cleanup restore: %v", restoreErr)
		}
	}()

	evidence.AfterPublish = recorder.Batch(0, 128).Events
	if err := manager.Restore(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	restored = true
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state residue: %v", err)
	}
	residue, err := manager.Residue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !residue.IsZero() {
		t.Fatalf("network residue = %#v", residue)
	}
	evidence.TerminalResidue = &residue
	evidence.AfterRestore = recorder.Batch(0, 128).Events
	events := recorder.Batch(0, 128).Events
	for _, stage := range []string{
		traceevent.StageNetworkPrepare,
		traceevent.StageFirewallEnable,
		traceevent.StageFirewallVerify,
		traceevent.StageNetworkRestore,
		traceevent.StageResidueVerify,
	} {
		if !containsString(traceKeys(events), stage+":"+traceevent.EventStarted) || !containsString(traceKeys(events), stage+":"+traceevent.EventSucceeded) {
			t.Fatalf("live trace stage %q is incomplete: %v", stage, traceKeys(events))
		}
	}
	assertTracePairs(t, events)
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
