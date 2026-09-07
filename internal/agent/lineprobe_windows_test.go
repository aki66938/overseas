//go:build windows

package agent

import (
	"context"
	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"corp.example/overseas-access-gateway/internal/localapi"
	"sync/atomic"
	"testing"
	"time"
)

func TestPipeProbeAndStatusUseGenerationResults(t *testing.T) {
	deps := testDependencies(nil)
	var c *Controller
	var calls atomic.Int32
	scheduler := lineprobe.NewScheduler(func(_ context.Context, target lineprobe.Target) lineprobe.Result {
		calls.Add(1)
		return lineprobe.Result{ID: target.ID, Reachable: true, HTTPStatus: 403, CheckedAt: time.Now()}
	}, nil, func(g uint64, q string) bool { return c.UpdateLineQuality(g, q) })
	deps.ConnectedLifetime = scheduler.Start
	c = newTestController(newFakeNetwork(), newFakeProcess(), deps)
	server := NewPipeServer(c, WithLineProbe(scheduler))
	request := func(action string) localapi.Response {
		t.Helper()
		line, ok := rawVersionedPipeLine(t, server, []byte(`{"version":1,"id":"probe","action":"`+action+`"}`+"\n"))
		if !ok {
			t.Fatal("no response")
		}
		r, err := localapi.DecodeResponse(line, "probe")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if got := request("probe"); got.ErrorCode != "probe_unavailable" {
		t.Fatal(got)
	}
	if c.Connect(context.Background()).State != accessmodel.StateConnected {
		t.Fatal(c.Status())
	}
	defer c.Disconnect(context.Background())
	for _, action := range []string{"probe", "status"} {
		got := request(action)
		if len(got.ProbeResults) != 5 || got.ProbeGeneration != got.Status.Generation || got.ErrorCode != "" {
			t.Fatal(got)
		}
		for _, r := range got.ProbeResults {
			if r.ConsecutiveFailures == nil || *r.ConsecutiveFailures != 0 {
				t.Fatal("healthy round count missing", r)
			}
		}
	}
	oldGeneration := c.LocalStatusSnapshot().Generation
	c.Disconnect(context.Background())
	before := calls.Load()
	if got := request("probe"); got.ErrorCode != "probe_unavailable" || len(got.ProbeResults) != 5 || !got.ProbeHistorical || got.ProbeGeneration != oldGeneration {
		t.Fatal(got)
	}
	if got := request("status"); len(got.ProbeResults) != 5 || !got.ProbeHistorical || got.ProbeGeneration != oldGeneration || got.ProbeGeneration >= got.Status.Generation {
		t.Fatal(got)
	} else {
		for _, r := range got.ProbeResults {
			if r.ConsecutiveFailures == nil || *r.ConsecutiveFailures != 0 {
				t.Fatal("historical count lost", r)
			}
		}
	}
	if calls.Load() != before {
		t.Fatal("disconnected history started traffic")
	}
	if c.Connect(context.Background()).State != accessmodel.StateConnected {
		t.Fatal(c.Status())
	}
	if got := request("status"); got.ProbeHistorical || (len(got.ProbeResults) > 0 && got.ProbeGeneration != got.Status.Generation) {
		t.Fatal("reconnect exposed old results", got)
	}
}

// The shared network budget must expire before the pipe's write deadline.
func TestPipeProbeAllowsBudgetAndResponseOverhead(t *testing.T) {
	if timeout := PipeTimeoutForAction(localapi.ActionProbe); timeout <= lineprobe.RoundBudget || timeout > 10*time.Second {
		t.Fatalf("probe IPC timeout=%s", timeout)
	}
}

func TestPipeReturnsAllTimeoutResults(t *testing.T) {
	deps := testDependencies(nil)
	var c *Controller
	scheduler := lineprobe.NewScheduler(func(_ context.Context, target lineprobe.Target) lineprobe.Result {
		return lineprobe.Result{ID: target.ID, ErrorCode: "timeout", LatencyMS: 5000, CheckedAt: time.Now()}
	}, nil, func(g uint64, q string) bool { return c.UpdateLineQuality(g, q) })
	deps.ConnectedLifetime = scheduler.Start
	c = newTestController(newFakeNetwork(), newFakeProcess(), deps)
	c.Connect(context.Background())
	defer c.Disconnect(context.Background())
	line, ok := rawVersionedPipeLine(t, NewPipeServer(c, WithLineProbe(scheduler)), []byte("{\"version\":1,\"id\":\"timeout\",\"action\":\"probe\"}\n"))
	if !ok {
		t.Fatal("no timeout response")
	}
	got, err := localapi.DecodeResponse(line, "timeout")
	if err != nil || got.ErrorCode != "" || len(got.ProbeResults) != 5 {
		t.Fatalf("%+v %v", got, err)
	}
	for _, r := range got.ProbeResults {
		if r.ErrorCode != "timeout" {
			t.Fatal(r)
		}
	}
	if c.Status().State != accessmodel.StateConnected {
		t.Fatal("timeout changed network state")
	}
}
