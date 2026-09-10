//go:build darwin

package main

import (
	"context"
	"corp.example/overseas-access-gateway/internal/localapi"
	"testing"
)

type recordingDispatcher struct{ calls int }

func (d *recordingDispatcher) Dispatch(_ context.Context, r localapi.Request, _ bool) localapi.Response {
	d.calls++
	return localapi.Response{ID: r.ID}
}
func TestTeardownStopsNewDispatch(t *testing.T) {
	d := &recordingDispatcher{}
	g := &dispatchGate{handler: d}
	g.Dispatch(context.Background(), localapi.Request{ID: "first", Action: localapi.ActionConnect}, false)
	g.stop()
	g.Dispatch(context.Background(), localapi.Request{ID: "second", Action: localapi.ActionConnect}, false)
	if d.calls != 1 {
		t.Fatalf("dispatch count=%d", d.calls)
	}
}
