package lineprobe

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeTimer struct {
	at      time.Time
	ch      chan time.Time
	stopped bool
	clock   *fakeClock
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }
func (t *fakeTimer) Stop()               { t.clock.mu.Lock(); t.stopped = true; t.clock.mu.Unlock() }

type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*fakeTimer
	created chan time.Duration
}

func newClock() *fakeClock {
	return &fakeClock{now: time.Unix(100, 0), created: make(chan time.Duration, 100)}
}
func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), ch: make(chan time.Time, 1), clock: c}
	c.timers = append(c.timers, t)
	c.created <- d
	return t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if !t.stopped && !t.at.After(c.now) {
			t.stopped = true
			t.ch <- c.now
		}
	}
}
func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(time.Second):
		t.Fatal("timed out awaiting event")
		var zero T
		return zero
	}
}

type waitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *waitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestSchedulerPeriodBudgetCoalescingAndCancel(t *testing.T) {
	clock := newClock()
	started := make(chan string, 30)
	release := make(chan struct{})
	var calls atomic.Int32
	published := make(chan string, 10)
	s := NewScheduler(func(ctx context.Context, target Target) Result {
		calls.Add(1)
		started <- target.ID
		select {
		case <-release:
			return Result{ID: target.ID, Reachable: true, HTTPStatus: 200}
		case <-ctx.Done():
			return Result{ID: target.ID, ErrorCode: "canceled"}
		}
	}, clock, func(_ uint64, q string) bool { published <- q; return true })
	if got := s.Manual(context.Background()); len(got.Results) != 0 || calls.Load() != 0 {
		t.Fatal("disconnected probe sent traffic")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx, 1)
	for i := 0; i < 5; i++ {
		await(t, started)
	}
	for i := 0; i < 2; i++ {
		d := await(t, clock.created)
		if d != 30*time.Second && d != 5*time.Second {
			t.Fatal(d)
		}
	}
	done := make(chan Snapshot, 1)
	manualCtx := &waitContext{Context: context.Background(), entered: make(chan struct{})}
	go func() { done <- s.Manual(manualCtx) }()
	await(t, manualCtx.entered)
	// A waiting manual call shares the connected generation's first round.
	clock.advance(5 * time.Second)
	got := await(t, done)
	await(t, published)
	if calls.Load() != 5 || len(got.Results) != 5 || got.Generation != 1 {
		t.Fatalf("calls=%d snapshot=%+v", calls.Load(), got)
	}
	for _, r := range got.Results {
		if r.ErrorCode != "timeout" {
			t.Fatal(r)
		}
	}
	clock.advance(24 * time.Second)
	if calls.Load() != 5 {
		t.Fatal("period fired early")
	}
	clock.advance(time.Second)
	for i := 0; i < 5; i++ {
		await(t, started)
	}
	cancel()
	// Manual after cancellation returns historical data and cannot launch traffic.
	s.Manual(context.Background())
	clock.advance(time.Minute)
	if calls.Load() != 10 {
		t.Fatal(calls.Load())
	}
}

func TestSchedulerRejectsObsoleteGenerationAndResetsHysteresis(t *testing.T) {
	clock := newClock()
	first := make(chan struct{})
	calls := make(chan string, 20)
	pub := make(chan uint64, 10)
	var old atomic.Bool
	old.Store(true)
	s := NewScheduler(func(ctx context.Context, target Target) Result {
		isOld := old.Load()
		calls <- target.ID
		if isOld {
			<-first
		}
		return Result{ID: target.ID, Reachable: true, HTTPStatus: 200}
	}, clock, func(g uint64, _ string) bool { pub <- g; return true })
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	s.Start(ctx1, 1)
	for i := 0; i < 5; i++ {
		await(t, calls)
	}
	old.Store(false)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	s.Start(ctx2, 3)
	for i := 0; i < 5; i++ {
		await(t, calls)
	}
	if g := await(t, pub); g != 3 {
		t.Fatal(g)
	}
	close(first)
	got := s.Manual(context.Background())
	if got.Generation != 3 {
		t.Fatal(got)
	}
	s.Start(ctx1, 1)
	if got := s.Snapshot(); got.Generation != 3 {
		t.Fatal("late lifecycle callback replaced new session")
	}
}

func TestSchedulerFakeClockThreeFailuresRecoveryAndReconnect(t *testing.T) {
	clock := newClock()
	started := make(chan struct{}, 5)
	release := make(chan struct{}, 5)
	qualities := make(chan string, 10)
	var fail atomic.Bool
	s := NewScheduler(func(ctx context.Context, target Target) Result {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return Result{ID: target.ID, Reachable: !fail.Load(), HTTPStatus: 200, CheckedAt: clock.Now()}
	}, clock, func(_ uint64, q string) bool { qualities <- q; return true })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx, 1)
	for i, step := range []struct {
		fail bool
		want string
	}{{false, "good"}, {true, "good"}, {true, "good"}, {true, "failed"}, {false, "good"}, {true, "good"}} {
		if i > 0 {
			clock.advance(Interval)
		}
		await(t, clock.created)
		await(t, clock.created)
		for n := 0; n < 5; n++ {
			await(t, started)
		}
		s.mu.Lock()
		done := s.current.active.done
		s.mu.Unlock()
		fail.Store(step.fail)
		for n := 0; n < 5; n++ {
			release <- struct{}{}
		}
		await(t, done)
		if q := await(t, qualities); q != step.want {
			t.Fatalf("round %d: %s", i, q)
		}
		wantCount := []int{0, 1, 2, 3, 0, 1}[i]
		for poll := 0; poll < 3; poll++ {
			got := s.Snapshot()
			for _, r := range got.Results {
				if r.ConsecutiveFailures == nil || *r.ConsecutiveFailures != wantCount {
					t.Fatalf("round %d poll %d: %+v", i, poll, r)
				}
			}
			// A client can mutate its own optional value without changing service history.
			*got.Results[0].ConsecutiveFailures = 99
		}
	}
	cancel()
	history := s.Manual(context.Background())
	if history.Generation != 1 || *history.Results[0].ConsecutiveFailures != 1 {
		t.Fatal("history lost", history)
	}
	*history.Results[0].ConsecutiveFailures = 99
	if got := s.Snapshot(); *got.Results[0].ConsecutiveFailures != 1 {
		t.Fatal("historical pointer shared")
	}
	next, cancelNext := context.WithCancel(context.Background())
	defer cancelNext()
	s.Start(next, 3)
	await(t, clock.created)
	await(t, clock.created)
	for n := 0; n < 5; n++ {
		await(t, started)
	}
	s.mu.Lock()
	done := s.current.active.done
	s.mu.Unlock()
	for n := 0; n < 5; n++ {
		release <- struct{}{}
	}
	await(t, done)
	if q := await(t, qualities); q != "unknown" {
		t.Fatalf("reconnect reused failure history: %s", q)
	}
	if got := s.Snapshot(); got.Generation != 3 || *got.Results[0].ConsecutiveFailures != 1 {
		t.Fatal("reconnect count not reset", got)
	}
}
