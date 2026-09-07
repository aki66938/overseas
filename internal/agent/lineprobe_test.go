package agent

import (
	"context"
	"corp.example/overseas-access-gateway/internal/accessmodel"
	"errors"
	"testing"
	"time"
)

func TestConnectedLifetimeCallbackAndCancellation(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		network := newFakeNetwork()
		process := newFakeProcess()
		deps := testDependencies(nil)
		var lifetime context.Context
		var generation uint64
		var controller *Controller
		deps.ConnectedLifetime = func(ctx context.Context, g uint64) {
			lifetime = ctx
			generation = g
			if controller.Status().State != accessmodel.StateConnected {
				t.Error("callback not connected")
			}
			controller.UpdateLineQuality(g, "failed")
		}
		controller = newTestController(network, process, deps)
		if got := controller.Connect(context.Background()); got.State != accessmodel.StateConnected {
			t.Fatal(got)
		}
		if lifetime == nil || lifetime.Err() != nil || generation == 0 {
			t.Fatal("missing connected lifetime")
		}
		if controller.Status().State != accessmodel.StateConnected {
			t.Fatal("quality disconnected route")
		}
		if automatic {
			controller.automaticRestore(generation, ErrorReadinessLost, errors.New("test"))
		} else {
			controller.Disconnect(context.Background())
		}
		select {
		case <-lifetime.Done():
		case <-time.After(time.Second):
			t.Fatal("lifetime not canceled")
		}
		if controller.UpdateLineQuality(generation, "good") {
			t.Fatal("stale quality accepted")
		}
	}
}

func TestFailedConnectDoesNotStartProbes(t *testing.T) {
	deps := testDependencies(nil)
	calls := 0
	deps.ConnectedLifetime = func(context.Context, uint64) { calls++ }
	network := newFakeNetwork()
	network.activateErr = errors.New("test")
	c := newTestController(network, newFakeProcess(), deps)
	c.Connect(context.Background())
	if calls != 0 {
		t.Fatal("failure started probes")
	}
}
