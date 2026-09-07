// Package diagnosticmode owns a temporary, opt-in diagnostic recorder.
// Authorization belongs to the platform IPC transport, not this package.
package diagnosticmode

import (
	"errors"
	"io"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/traceevent"
)

type timer interface{ Stop() bool }

type Gate struct {
	mu        sync.Mutex
	config    traceevent.RecorderConfig
	recorder  *traceevent.Recorder
	deadline  time.Time
	expiry    timer
	epoch     uint64
	closed    bool
	output    outputState
	streams   []*outputState
	afterFunc func(time.Duration, func()) timer
}

type outputState struct {
	pending  []byte
	dropping bool
}
type outputWriter struct {
	gate  *Gate
	state *outputState
}

// NewOutputStream gives stdout and stderr independent framing/redaction.
func (g *Gate) NewOutputStream() io.Writer {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := &outputState{}
	g.streams = append(g.streams, state)
	return &outputWriter{gate: g, state: state}
}

func (w *outputWriter) Write(data []byte) (int, error) {
	w.gate.mu.Lock()
	defer w.gate.mu.Unlock()
	return w.gate.writeLocked(w.state, data)
}

func (w *outputWriter) Close() error {
	w.gate.mu.Lock()
	defer w.gate.mu.Unlock()
	w.state.clear()
	for i, state := range w.gate.streams {
		if state == w.state {
			w.gate.streams = append(w.gate.streams[:i], w.gate.streams[i+1:]...)
			break
		}
	}
	return nil
}

// New is inert: no filesystem access, event buffer, or timer until Enable.
func New(config traceevent.RecorderConfig) *Gate {
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Gate{config: config, afterFunc: func(d time.Duration, f func()) timer { return time.AfterFunc(d, f) }}
}

func (g *Gate) Enable(now time.Time, duration time.Duration) error {
	if duration != 15*time.Minute && duration != 30*time.Minute && duration != 60*time.Minute {
		return errors.New("diagnostic duration must be 15, 30, or 60 minutes")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errors.New("diagnostic mode is closed")
	}
	g.enabledLocked(now)
	if g.recorder == nil {
		recorder, err := traceevent.NewRecorder(g.config)
		if err != nil {
			return err
		}
		g.recorder = recorder
	}
	if g.expiry != nil {
		g.expiry.Stop()
	}
	g.deadline = now.Add(duration)
	g.epoch++
	epoch := g.epoch
	g.expiry = g.afterFunc(duration, func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.epoch == epoch {
			_ = g.offLocked()
		}
	})
	return nil
}

func (g *Gate) Enabled(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.enabledLocked(now)
}

func (g *Gate) enabledLocked(now time.Time) bool {
	if g.recorder != nil && !now.Before(g.deadline) {
		_ = g.offLocked()
	}
	return !g.closed && g.recorder != nil
}

func (g *Gate) Record(event traceevent.Event) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.enabledLocked(g.config.Now()) {
		g.recorder.Record(event)
	}
}

func (g *Gate) Batch(after uint64, limit int) traceevent.Batch {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.enabledLocked(g.config.Now()) {
		return traceevent.Batch{NextSequence: after}
	}
	return g.recorder.Batch(after, limit)
}

// Write collects complete child-output lines only while enabled. Keeping a
// bounded line before sanitizing prevents credentials split across writes
// from bypassing traceevent's existing redaction. Overlong lines are dropped.
func (g *Gate) Write(data []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.writeLocked(&g.output, data)
}

func (g *Gate) writeLocked(state *outputState, data []byte) (int, error) {
	if !g.enabledLocked(g.config.Now()) {
		// Retain only a line-boundary bit, never disabled output bytes.
		if len(data) > 0 {
			state.dropping = data[len(data)-1] != '\n'
		}
		return len(data), nil
	}
	for _, b := range data {
		if b == '\n' {
			if !state.dropping && len(state.pending) > 0 {
				g.recorder.Record(traceevent.Event{Level: traceevent.LevelInfo, Component: traceevent.ComponentCore, Stage: traceevent.StageCoreReady, Event: traceevent.EventState, Message: "数据面进程输出", Detail: string(state.pending)})
			}
			state.pending = nil
			state.dropping = false
		} else if !state.dropping {
			if len(state.pending) >= traceevent.MaxDetailBytes {
				state.pending = nil
				state.dropping = true
			} else {
				state.pending = append(state.pending, b)
			}
		}
	}
	return len(data), nil
}

func (g *Gate) offLocked() error {
	g.epoch++
	if g.expiry != nil {
		g.expiry.Stop()
		g.expiry = nil
	}
	g.output.clear()
	for _, state := range g.streams {
		state.clear()
	}
	if g.recorder == nil {
		return nil
	}
	recorder := g.recorder
	g.recorder = nil
	return recorder.Close()
}

func (s *outputState) clear() {
	s.dropping = s.dropping || len(s.pending) > 0
	clear(s.pending)
	s.pending = nil
}

func (g *Gate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return g.offLocked()
}
