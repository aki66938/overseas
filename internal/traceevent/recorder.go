package traceevent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var traceFilenamePattern = regexp.MustCompile(`^trace-\d{8}T\d{6}\.\d{9}Z(?:-\d{2})?-g\d+\.jsonl$`)

type RecorderConfig struct {
	Directory      string
	MemoryCapacity int
	MaxFileBytes   int64
	RetainFiles    int
	Now            func() time.Time
}

type Recorder struct {
	config RecorderConfig

	mu             sync.Mutex
	sequence       uint64
	events         []Event
	file           *os.File
	fileBytes      int64
	fileGeneration uint64
	fileTruncated  bool
	diskDegraded   bool
	closed         bool
}

func NewRecorder(config RecorderConfig) (*Recorder, error) {
	if config.Directory == "" || config.MemoryCapacity <= 0 || config.MaxFileBytes <= 0 || config.RetainFiles <= 0 {
		return nil, errors.New("trace recorder configuration is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	parent := filepath.Dir(filepath.Clean(config.Directory))
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return nil, errors.New("trace directory parent is unavailable")
	}
	if info, err = os.Stat(config.Directory); err == nil {
		if !info.IsDir() {
			return nil, errors.New("trace path is not a directory")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else if err := os.Mkdir(config.Directory, 0o700); err != nil {
		return nil, err
	}
	return &Recorder{config: config, events: make([]Event, 0, config.MemoryCapacity)}, nil
}

func (r *Recorder) Record(event Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	event = r.prepareLocked(event)
	if err := Validate(event); err != nil {
		r.appendLoggingFailureLocked(event.Generation, "无效日志事件已丢弃", err.Error())
		return
	}
	r.appendMemoryLocked(event)
	r.persistLocked(event)
}

func (r *Recorder) Batch(after uint64, limit int) Batch {
	r.mu.Lock()
	defer r.mu.Unlock()
	batch := Batch{NextSequence: after}
	if len(r.events) == 0 || limit <= 0 {
		return batch
	}
	batch.OldestSequence = r.events[0].Sequence
	for _, event := range r.events {
		if event.Sequence <= after {
			continue
		}
		if len(batch.Events) == limit {
			batch.HasMore = true
			break
		}
		batch.Events = append(batch.Events, cloneEvent(event))
		batch.NextSequence = event.Sequence
	}
	return batch
}

func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.closeFileLocked()
}

func (r *Recorder) prepareLocked(event Event) Event {
	r.sequence++
	event.SchemaVersion = SchemaVersion
	event.Sequence = r.sequence
	event.TimestampUTC = r.config.Now().UTC()
	event.Message, _ = SanitizeDetail(event.Message)
	event.Detail, event.DetailTruncated = SanitizeDetail(event.Detail)
	return cloneEvent(event)
}

func (r *Recorder) appendMemoryLocked(event Event) {
	if len(r.events) == r.config.MemoryCapacity {
		copy(r.events, r.events[1:])
		r.events[len(r.events)-1] = cloneEvent(event)
		return
	}
	r.events = append(r.events, cloneEvent(event))
}

func (r *Recorder) persistLocked(event Event) {
	if r.file == nil || r.fileGeneration != event.Generation {
		if err := r.openGenerationLocked(event.Generation); err != nil {
			r.appendLoggingFailureLocked(event.Generation, "日志持久化不可用", err.Error())
			return
		}
	}
	if r.diskDegraded || r.fileTruncated {
		return
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		r.appendLoggingFailureLocked(event.Generation, "日志序列化失败", err.Error())
		return
	}
	encoded = append(encoded, '\n')
	if r.fileBytes+int64(len(encoded)) > r.config.MaxFileBytes {
		r.fileTruncated = true
		truncated := r.prepareLocked(Event{
			Generation: event.Generation,
			Level:      LevelWarning,
			Component:  ComponentLogging,
			Stage:      StageLoggingDegraded,
			Event:      EventFailed,
			Message:    "日志文件达到大小上限，后续磁盘记录已截断",
		})
		r.appendMemoryLocked(truncated)
		terminal, marshalErr := json.Marshal(truncated)
		terminal = append(terminal, '\n')
		if marshalErr == nil && r.fileBytes+int64(len(terminal)) <= r.config.MaxFileBytes {
			if _, writeErr := r.file.Write(terminal); writeErr == nil {
				r.fileBytes += int64(len(terminal))
				_ = r.file.Sync()
			}
		}
		return
	}
	if _, err := r.file.Write(encoded); err != nil {
		r.appendLoggingFailureLocked(event.Generation, "日志持久化不可用", err.Error())
		return
	}
	r.fileBytes += int64(len(encoded))
	if event.Event != EventStarted {
		if err := r.file.Sync(); err != nil {
			r.appendLoggingFailureLocked(event.Generation, "日志持久化不可用", err.Error())
		}
	}
}

func (r *Recorder) openGenerationLocked(generation uint64) error {
	if err := r.closeFileLocked(); err != nil {
		return err
	}
	r.fileGeneration = generation
	r.fileBytes = 0
	r.fileTruncated = false
	r.diskDegraded = false
	stamp := r.config.Now().UTC().Format("20060102T150405.000000000Z")
	base := fmt.Sprintf("trace-%s-g%d.jsonl", stamp, generation)
	path := filepath.Join(r.config.Directory, base)
	var err error
	for suffix := 0; suffix < 100; suffix++ {
		candidate := path
		if suffix != 0 {
			candidate = filepath.Join(r.config.Directory, fmt.Sprintf("trace-%s-%02d-g%d.jsonl", stamp, suffix, generation))
		}
		r.file, err = os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return err
		}
	}
	if err != nil {
		return err
	}
	return r.pruneLocked()
}

func (r *Recorder) closeFileLocked() error {
	if r.file == nil {
		return nil
	}
	file := r.file
	r.file = nil
	if err := file.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func (r *Recorder) pruneLocked() error {
	entries, err := os.ReadDir(r.config.Directory)
	if err != nil {
		return err
	}
	type candidate struct {
		path    string
		name    string
		modTime time.Time
	}
	var candidates []candidate
	for _, entry := range entries {
		if entry.IsDir() || !isTraceFilename(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		candidates = append(candidates, candidate{filepath.Join(r.config.Directory, entry.Name()), entry.Name(), info.ModTime()})
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].modTime.Equal(candidates[right].modTime) {
			return candidates[left].name < candidates[right].name
		}
		return candidates[left].modTime.Before(candidates[right].modTime)
	})
	for len(candidates) > r.config.RetainFiles {
		if err := os.Remove(candidates[0].path); err != nil {
			return err
		}
		candidates = candidates[1:]
	}
	return nil
}

func (r *Recorder) appendLoggingFailureLocked(generation uint64, message, detail string) {
	if r.diskDegraded {
		return
	}
	r.diskDegraded = true
	event := r.prepareLocked(Event{
		Generation: generation,
		Level:      LevelError,
		Component:  ComponentLogging,
		Stage:      StageLoggingDegraded,
		Event:      EventFailed,
		Message:    message,
		Detail:     detail,
	})
	r.appendMemoryLocked(event)
}

func cloneEvent(event Event) Event {
	clone := event
	if event.ElapsedMS != nil {
		value := *event.ElapsedMS
		clone.ElapsedMS = &value
	}
	if event.Residue != nil {
		value := *event.Residue
		clone.Residue = &value
	}
	return clone
}

func isTraceFilename(name string) bool {
	return traceFilenamePattern.MatchString(name)
}
