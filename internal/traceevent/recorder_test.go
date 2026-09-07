package traceevent

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func testRecorder(t *testing.T, capacity int, maxBytes int64, retain int) *Recorder {
	t.Helper()
	parent := t.TempDir()
	recorder, err := NewRecorder(RecorderConfig{
		Directory:      filepath.Join(parent, "logs"),
		MemoryCapacity: capacity,
		MaxFileBytes:   maxBytes,
		RetainFiles:    retain,
		Now: func() time.Time {
			return time.Date(2026, 9, 1, 8, 9, 10, 123456789, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	return recorder
}

func recorderEvent(generation uint64, message string) Event {
	return Event{
		Generation: generation,
		Level:      LevelInfo,
		Component:  ComponentController,
		Stage:      StageRequestReceived,
		Event:      EventState,
		Message:    message,
	}
}

func TestRecorderCloseReleasesMemory(t *testing.T) {
	recorder := testRecorder(t, 8, 2<<20, 5)
	recorder.Record(recorderEvent(1, "temporary diagnostics"))
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	if len(recorder.Batch(0, 8).Events) != 0 {
		t.Fatal("closed recorder retained diagnostics")
	}
}

func TestRecorderAssignsSequenceTimestampAndCopies(t *testing.T) {
	recorder := testRecorder(t, 8, 1<<20, 5)
	event := recorderEvent(5, "first")
	residue := &Residue{ManagedRules: 2}
	event.Residue = residue
	recorder.Record(event)
	residue.ManagedRules = 99
	event.Message = "mutated"
	recorder.Record(recorderEvent(5, "second"))

	batch := recorder.Batch(0, 10)
	if len(batch.Events) != 2 || batch.Events[0].Sequence != 1 || batch.Events[1].Sequence != 2 {
		t.Fatalf("batch = %#v", batch)
	}
	if batch.Events[0].SchemaVersion != SchemaVersion || !batch.Events[0].TimestampUTC.Equal(time.Date(2026, 9, 1, 8, 9, 10, 123456789, time.UTC)) {
		t.Fatalf("assigned fields = %#v", batch.Events[0])
	}
	if batch.Events[0].Message != "first" || batch.Events[0].Residue.ManagedRules != 2 {
		t.Fatalf("stored event was mutated: %#v", batch.Events[0])
	}
	batch.Events[0].Message = "caller mutation"
	if got := recorder.Batch(0, 1).Events[0].Message; got != "first" {
		t.Fatalf("Batch returned internal event: %q", got)
	}
}

func TestRecorderRingPaginationAndOverwrite(t *testing.T) {
	recorder := testRecorder(t, 3, 1<<20, 5)
	for index := 1; index <= 5; index++ {
		recorder.Record(recorderEvent(5, string(rune('0'+index))))
	}
	first := recorder.Batch(0, 2)
	if first.OldestSequence != 3 || len(first.Events) != 2 || first.Events[0].Sequence != 3 || first.Events[1].Sequence != 4 || !first.HasMore || first.NextSequence != 4 {
		t.Fatalf("first batch = %#v", first)
	}
	second := recorder.Batch(first.NextSequence, 2)
	if len(second.Events) != 1 || second.Events[0].Sequence != 5 || second.HasMore || second.NextSequence != 5 {
		t.Fatalf("second batch = %#v", second)
	}
}

func TestRecorderSequenceIsStrictUnderConcurrency(t *testing.T) {
	recorder := testRecorder(t, 256, 1<<20, 5)
	var writers sync.WaitGroup
	for index := 0; index < 100; index++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			recorder.Record(recorderEvent(7, "concurrent"))
		}()
	}
	writers.Wait()
	events := recorder.Batch(0, 200).Events
	if len(events) != 100 {
		t.Fatalf("event count = %d", len(events))
	}
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("sequence[%d] = %d", index, event.Sequence)
		}
	}
}

func TestRecorderCreatesGenerationFilesAndRetainsFive(t *testing.T) {
	recorder := testRecorder(t, 32, 1<<20, 5)
	directory := recorder.config.Directory
	if err := os.WriteFile(filepath.Join(directory, "unrelated.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	lookalike := filepath.Join(directory, "trace-not-product-gfake.jsonl")
	if err := os.WriteFile(lookalike, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for generation := uint64(1); generation <= 7; generation++ {
		recorder.Record(recorderEvent(generation, "generation"))
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	allFiles, err := filepath.Glob(filepath.Join(directory, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, path := range allFiles {
		if isTraceFilename(filepath.Base(path)) {
			files = append(files, path)
		}
	}
	if len(files) != 5 {
		t.Fatalf("trace files = %v", files)
	}
	sort.Strings(files)
	if _, err := os.Stat(filepath.Join(directory, "unrelated.txt")); err != nil {
		t.Fatalf("unrelated file removed: %v", err)
	}
	if _, err := os.Stat(lookalike); err != nil {
		t.Fatalf("lookalike file removed: %v", err)
	}
	seen := map[uint64]bool{}
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var event Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			seen[event.Generation] = true
		}
		_ = file.Close()
	}
	for generation := uint64(3); generation <= 7; generation++ {
		if !seen[generation] {
			t.Fatalf("generation %d not retained: %v", generation, seen)
		}
	}
}

func TestRecorderStopsAtFileLimitWithTruncationEvent(t *testing.T) {
	recorder := testRecorder(t, 64, 650, 5)
	for index := 0; index < 20; index++ {
		recorder.Record(recorderEvent(9, strings.Repeat("x", 180)))
	}
	batch := recorder.Batch(0, 100)
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(recorder.config.Directory, "trace-*-g9.jsonl"))
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > recorder.config.MaxFileBytes {
		t.Fatalf("file size = %d", info.Size())
	}
	count := 0
	for _, event := range batch.Events {
		if event.Stage == StageLoggingDegraded && strings.Contains(event.Message, "截断") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("truncation events = %d", count)
	}
}

func TestRecorderDiskFailureDegradesOnceAndKeepsMemory(t *testing.T) {
	recorder := testRecorder(t, 16, 1<<20, 5)
	recorder.Record(recorderEvent(11, "open file"))
	if recorder.file == nil {
		t.Fatal("log file was not opened")
	}
	if err := recorder.file.Close(); err != nil {
		t.Fatal(err)
	}
	recorder.Record(recorderEvent(11, "after close one"))
	recorder.Record(recorderEvent(11, "after close two"))
	events := recorder.Batch(0, 20).Events
	degraded := 0
	for _, event := range events {
		if event.Stage == StageLoggingDegraded && strings.Contains(event.Message, "持久化") {
			degraded++
		}
	}
	if degraded != 1 || len(events) != 4 {
		t.Fatalf("degraded=%d events=%#v", degraded, events)
	}
}

func TestNewRecorderRejectsMissingParentAndFileTarget(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "logs")
	if _, err := NewRecorder(RecorderConfig{Directory: missing, MemoryCapacity: 1, MaxFileBytes: 1, RetainFiles: 1}); err == nil {
		t.Fatal("missing parent accepted")
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "logs")
	if err := os.WriteFile(target, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRecorder(RecorderConfig{Directory: target, MemoryCapacity: 1, MaxFileBytes: 1, RetainFiles: 1}); err == nil {
		t.Fatal("file target accepted")
	}
}
