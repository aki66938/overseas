package lineprobe

import (
	"context"
	"sync"
	"time"
)

const Interval = 30 * time.Second

type Timer interface {
	C() <-chan time.Time
	Stop()
}
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}
type realClock struct{}

func (realClock) Now() time.Time                 { return time.Now() }
func (realClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.Timer.C }
func (t realTimer) Stop()               { t.Timer.Stop() }

type Snapshot struct {
	Generation uint64
	Results    []Result
}
type round struct{ done chan struct{} }
type session struct {
	ctx        context.Context
	cancel     context.CancelFunc
	generation uint64
	active     *round
	aggregate  Aggregate
}

type Scheduler struct {
	mu      sync.Mutex
	probe   func(context.Context, Target) Result
	clock   Clock
	publish func(uint64, string) bool
	current *session
	last    Snapshot
}

func NewScheduler(probe func(context.Context, Target) Result, clock Clock, publish func(uint64, string) bool) *Scheduler {
	if clock == nil {
		clock = realClock{}
	}
	if probe == nil {
		probe = NewProber(nil, nil).Probe
	}
	return &Scheduler{probe: probe, clock: clock, publish: publish}
}

// Start is called with the controller's connected-generation lifetime context.
// It does not wait for probes or call the controller while holding this mutex.
func (s *Scheduler) Start(ctx context.Context, generation uint64) {
	s.mu.Lock()
	if ctx.Err() != nil || (s.current != nil && s.current.generation >= generation) {
		s.mu.Unlock()
		return
	}
	if s.current != nil {
		s.current.cancel()
	}
	lifetime, cancel := context.WithCancel(ctx)
	current := &session{ctx: lifetime, cancel: cancel, generation: generation}
	s.current = current
	// Do not present the previous connection's results as the new generation.
	s.last = Snapshot{Generation: generation}
	timer := s.clock.NewTimer(Interval)
	s.beginLocked(current)
	s.mu.Unlock()
	go func() {
		defer func() { timer.Stop() }()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-timer.C():
				s.mu.Lock()
				if s.current == current && lifetime.Err() == nil {
					s.beginLocked(current)
				}
				s.mu.Unlock()
				timer = s.clock.NewTimer(Interval)
			}
		}
	}()
}

func (s *Scheduler) Snapshot() Snapshot { s.mu.Lock(); defer s.mu.Unlock(); return s.snapshotLocked() }
func (s *Scheduler) snapshotLocked() Snapshot {
	results := append([]Result(nil), s.last.Results...)
	for i := range results {
		if results[i].ConsecutiveFailures != nil {
			count := *results[i].ConsecutiveFailures
			results[i].ConsecutiveFailures = &count
		}
	}
	return Snapshot{Generation: s.last.Generation, Results: results}
}

// Manual joins an active round. A caller's cancellation ends only its wait,
// while disconnect cancellation terminates the generation-owned network work.
// Disconnected calls return the stored last results and generate no traffic.
func (s *Scheduler) Manual(ctx context.Context) Snapshot {
	s.mu.Lock()
	current := s.current
	if ctx.Err() != nil || current == nil || current.ctx.Err() != nil {
		got := s.snapshotLocked()
		s.mu.Unlock()
		return got
	}
	active := s.beginLocked(current)
	s.mu.Unlock()
	select {
	case <-active.done:
	case <-ctx.Done():
	case <-current.ctx.Done():
	}
	return s.Snapshot()
}

func (s *Scheduler) beginLocked(current *session) *round {
	if current.active != nil {
		return current.active
	}
	active := &round{done: make(chan struct{})}
	current.active = active
	go s.runRound(current, active)
	return active
}

func (s *Scheduler) runRound(current *session, active *round) {
	defer close(active.done)
	ctx, cancel := context.WithCancel(current.ctx)
	defer cancel()
	timer := s.clock.NewTimer(RoundBudget)
	defer timer.Stop()
	targets := Targets()
	results := make([]Result, len(targets))
	received := make([]bool, len(targets))
	type answer struct {
		index  int
		result Result
	}
	answers := make(chan answer, len(targets))
	for i, target := range targets {
		results[i] = Result{ID: target.ID, CheckedAt: s.clock.Now(), ErrorCode: "timeout", LatencyMS: RoundBudget.Milliseconds()}
		go func(i int, target Target) {
			if ctx.Err() != nil {
				return
			}
			r := s.probe(ctx, target)
			r.ID = target.ID
			answers <- answer{i, r}
		}(i, target)
	}
	waiting := len(targets)
	for waiting > 0 {
		select {
		case <-current.ctx.Done():
			return
		case <-timer.C():
			cancel()
			waiting = 0
		case a := <-answers:
			if !received[a.index] {
				results[a.index] = a.result
				received[a.index] = true
				waiting--
			}
		}
	}
	s.mu.Lock()
	if s.current != current || current.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	quality := current.aggregate.Update(results)
	s.mu.Unlock()
	accepted := s.publish == nil || s.publish(current.generation, quality)
	s.mu.Lock()
	if s.current == current && current.ctx.Err() == nil {
		if accepted {
			s.last = Snapshot{Generation: current.generation, Results: results}
		}
		current.active = nil
	}
	s.mu.Unlock()
}
