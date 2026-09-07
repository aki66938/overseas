package main

import (
	"strings"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/traceevent"
)

func viewTraceEvent(sequence, generation uint64, stage, event string, residue *traceevent.Residue) traceevent.Event {
	return traceevent.Event{
		SchemaVersion: traceevent.SchemaVersion, Sequence: sequence,
		TimestampUTC: time.Date(2026, 9, 1, 8, 0, int(sequence%60), 0, time.UTC),
		Generation:   generation, Level: traceevent.LevelInfo, Component: traceevent.ComponentNetwork,
		Stage: stage, Event: event, Message: "test event", Residue: residue,
	}
}

func TestFormatTraceTimelineShowsLevelsStagesDetailsAndGenerations(t *testing.T) {
	elapsed := int64(37)
	residue := traceevent.Residue{ManagedRules: 23, Snapshot: true, SnapshotPhase: "protected"}
	events := []traceevent.Event{
		viewTraceEvent(1, 5, traceevent.StageFirewallPublish, traceevent.EventStarted, nil),
		func() traceevent.Event {
			event := viewTraceEvent(2, 5, traceevent.StageFirewallPublish, traceevent.EventFailed, &residue)
			event.Level = traceevent.LevelError
			event.ElapsedMS = &elapsed
			event.Detail = "exit status 7"
			return event
		}(),
		viewTraceEvent(3, 6, traceevent.StageNetworkRestore, traceevent.EventSucceeded, &traceevent.Residue{}),
	}
	text := formatTraceTimeline(events, true, true, time.FixedZone("CST", 8*60*60))
	for _, want := range []string{
		"部分早期日志", "日志通道暂不可用", "Generation 5", "Generation 6",
		"[INFO] →", "[ERROR] ✕", "firewall_publish", "37 ms", "exit status 7",
		"managed_rules=23", "snapshot_phase=protected", "[INFO] ✓", "network_restore",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("timeline missing %q:\n%s", want, text)
		}
	}
}

func TestFormatTraceTimelineDoesNotDuplicateSequences(t *testing.T) {
	event := viewTraceEvent(1, 1, traceevent.StageNetworkCapture, traceevent.EventState, nil)
	text := formatTraceTimeline([]traceevent.Event{event, event}, false, false, time.UTC)
	if strings.Count(text, "network_capture") != 1 {
		t.Fatalf("duplicate sequence rendered:\n%s", text)
	}
}
