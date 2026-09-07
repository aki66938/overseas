package agent

import (
	"context"
	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/localapi"
	"testing"
	"time"
)

type dispatchController struct {
	state                 accessmodel.ConnectionState
	connects, disconnects int
}

func (c *dispatchController) Connect(context.Context) Status {
	c.connects++
	c.state = accessmodel.StateConnected
	return c.Status()
}
func (c *dispatchController) Disconnect(context.Context) Status {
	c.disconnects++
	c.state = accessmodel.StatePrepared
	return c.Status()
}
func (c *dispatchController) Status() Status { return Status{State: c.state} }
func (c *dispatchController) Diagnostics() Diagnostics {
	return Diagnostics{State: c.state, Generation: 7}
}

type dispatchDiagnostic struct{ calls int }

func (d *dispatchDiagnostic) Enable(time.Time, time.Duration) error { d.calls++; return nil }

func TestLocalDispatchAuthorizationAndProjection(t *testing.T) {
	c := &dispatchController{state: accessmodel.StatePrepared}
	d := &dispatchDiagnostic{}
	h := NewLocalHandler(c, nil, d)
	req := localapi.Request{Version: 1, ID: "test-1", Action: localapi.ActionDiagnosticEnable, DurationMinutes: 15}
	denied := h.Dispatch(context.Background(), req, false)
	if denied.ErrorCode != "permission_denied" || d.calls != 0 {
		t.Fatalf("unauthorized dispatch: %#v calls=%d", denied, d.calls)
	}
	allowed := h.Dispatch(context.Background(), req, true)
	if allowed.ErrorCode != "" || d.calls != 1 {
		t.Fatalf("authorized dispatch: %#v calls=%d", allowed, d.calls)
	}
	req.Action = localapi.ActionConnect
	req.DurationMinutes = 0
	connected := h.Dispatch(context.Background(), req, false)
	if c.connects != 1 || connected.Status.State != "connected" || connected.Status.Generation != 7 {
		t.Fatalf("connect: %#v", connected)
	}
	req.Action = localapi.ActionDisconnect
	disconnected := h.Dispatch(context.Background(), req, false)
	if c.disconnects != 1 || disconnected.Status.State != "idle" {
		t.Fatalf("disconnect: %#v", disconnected)
	}
	req.Action = localapi.ActionProbe
	if got := h.Dispatch(context.Background(), req, false); got.ErrorCode != "probe_unavailable" {
		t.Fatalf("probe: %#v", got)
	}
}
