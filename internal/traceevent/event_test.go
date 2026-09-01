package traceevent

import (
	"context"
	"testing"
	"time"
)

func validEvent() Event {
	elapsed := int64(12)
	return Event{
		SchemaVersion: SchemaVersion,
		Sequence:      1,
		TimestampUTC:  time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		Generation:    5,
		Level:         LevelInfo,
		Component:     ComponentNetwork,
		Stage:         StageFirewallPublish,
		Event:         EventSucceeded,
		ElapsedMS:     &elapsed,
		Message:       "防泄漏规则发布完成",
	}
}

func TestValidateAcceptsApprovedEvent(t *testing.T) {
	if err := Validate(validEvent()); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsUnknownOrIncompleteFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{"schema", func(event *Event) { event.SchemaVersion = 2 }},
		{"sequence", func(event *Event) { event.Sequence = 0 }},
		{"timestamp", func(event *Event) { event.TimestampUTC = time.Time{} }},
		{"non utc timestamp", func(event *Event) { event.TimestampUTC = event.TimestampUTC.In(time.FixedZone("CST", 8*60*60)) }},
		{"level", func(event *Event) { event.Level = "debug" }},
		{"component", func(event *Event) { event.Component = "unknown" }},
		{"stage", func(event *Event) { event.Stage = "unknown" }},
		{"event", func(event *Event) { event.Event = "complete" }},
		{"message", func(event *Event) { event.Message = "" }},
		{"negative elapsed", func(event *Event) { value := int64(-1); event.ElapsedMS = &value }},
		{"started elapsed", func(event *Event) { event.Event = EventStarted }},
		{"started residue", func(event *Event) { event.Event = EventStarted; event.ElapsedMS = nil; event.Residue = &Residue{} }},
		{"negative residue", func(event *Event) { event.Residue = &Residue{ManagedRules: -1} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := validEvent()
			test.mutate(&event)
			if err := Validate(event); err == nil {
				t.Fatal("Validate() succeeded")
			}
		})
	}
}

func TestApprovedEnumsAreComplete(t *testing.T) {
	for _, level := range []string{LevelInfo, LevelWarning, LevelError} {
		event := validEvent()
		event.Level = level
		if err := Validate(event); err != nil {
			t.Fatalf("level %q: %v", level, err)
		}
	}
	for _, terminal := range []string{EventSucceeded, EventFailed, EventState} {
		event := validEvent()
		event.Event = terminal
		if err := Validate(event); err != nil {
			t.Fatalf("event %q: %v", terminal, err)
		}
	}
	for _, component := range ApprovedComponents() {
		event := validEvent()
		event.Component = component
		if err := Validate(event); err != nil {
			t.Fatalf("component %q: %v", component, err)
		}
	}
	for _, stage := range ApprovedStages() {
		event := validEvent()
		event.Stage = stage
		if err := Validate(event); err != nil {
			t.Fatalf("stage %q: %v", stage, err)
		}
	}
}

func TestStagePairCanRepresentEveryTimedStage(t *testing.T) {
	for _, stage := range ApprovedStages() {
		if stage == StageConnected || stage == StageLoggingDegraded {
			continue
		}
		started := validEvent()
		started.Stage = stage
		started.Event = EventStarted
		started.ElapsedMS = nil
		if err := Validate(started); err != nil {
			t.Fatalf("stage %q started: %v", stage, err)
		}
		finished := validEvent()
		finished.Stage = stage
		if err := Validate(finished); err != nil {
			t.Fatalf("stage %q terminal: %v", stage, err)
		}
	}
}

func TestResidueIsZero(t *testing.T) {
	if !(Residue{}).IsZero() {
		t.Fatal("empty residue is not zero")
	}
	if (Residue{SnapshotPhase: "none"}).IsZero() != true {
		t.Fatal("non-owning phase should remain zero")
	}
	if (Residue{ManagedRules: 1}).IsZero() {
		t.Fatal("managed rules were ignored")
	}
	if (Residue{Snapshot: true}).IsZero() {
		t.Fatal("snapshot was ignored")
	}
}

func TestGenerationContextRoundTrip(t *testing.T) {
	ctx := WithGeneration(context.Background(), 17)
	if got := GenerationFromContext(ctx); got != 17 {
		t.Fatalf("GenerationFromContext() = %d", got)
	}
	if got := GenerationFromContext(context.Background()); got != 0 {
		t.Fatalf("empty generation = %d", got)
	}
}
