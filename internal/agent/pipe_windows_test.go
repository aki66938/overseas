//go:build windows

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
)

func TestPipeSecurityDescriptorAllowsAuthenticatedUsersAndDeniesRemoteIdentities(t *testing.T) {
	for _, ace := range []string{
		"(D;;GA;;;AN)",
		"(D;;GA;;;NU)",
		"(A;;GA;;;SY)",
		"(A;;GA;;;BA)",
		"(A;;GRGW;;;AU)",
	} {
		if !strings.Contains(PipeSecurityDescriptor, ace) {
			t.Fatalf("PipeSecurityDescriptor %q does not contain %q", PipeSecurityDescriptor, ace)
		}
	}
	if strings.Index(PipeSecurityDescriptor, "(D;;GA;;;AN)") > strings.Index(PipeSecurityDescriptor, "(A;;GRGW;;;AU)") ||
		strings.Index(PipeSecurityDescriptor, "(D;;GA;;;NU)") > strings.Index(PipeSecurityDescriptor, "(A;;GRGW;;;AU)") {
		t.Fatalf("deny ACEs must precede Authenticated Users allow ACE: %q", PipeSecurityDescriptor)
	}
}

func TestPipeDispatchesOnlyFixedActionsAndEchoesRequestID(t *testing.T) {
	controller := &fakePipeController{status: Status{State: accessmodel.StateDisconnected}}
	server := NewPipeServer(controller)

	tests := []struct {
		action string
		want   string
	}{
		{action: ActionConnect, want: ActionConnect},
		{action: ActionDisconnect, want: ActionDisconnect},
		{action: ActionStatus, want: ActionStatus},
		{action: ActionDiagnostics, want: ActionDiagnostics},
	}
	for index, test := range tests {
		id := "request-" + string(rune('a'+index))
		response, ok := pipeTransaction(t, server, Request{ID: id, Action: test.action})
		if !ok {
			t.Fatalf("action %q did not return a response", test.action)
		}
		if response.ID != id {
			t.Fatalf("response ID = %q, want %q", response.ID, id)
		}
	}
	if got := controller.actions(); !equalStrings(got, []string{ActionConnect, ActionDisconnect, ActionStatus, ActionDiagnostics}) {
		t.Fatalf("actions = %v", got)
	}
}

func TestPipeRejectsUnknownAction(t *testing.T) {
	controller := &fakePipeController{status: Status{State: accessmodel.StateDisconnected}}
	response, ok := pipeTransaction(t, NewPipeServer(controller), Request{ID: "request-1", Action: "run"})

	if !ok || response.ID != "request-1" || response.ErrorCode != ErrorInvalidAction {
		t.Fatalf("response = %#v, ok = %v", response, ok)
	}
	if len(controller.actions()) != 0 {
		t.Fatalf("unknown action reached controller: %v", controller.actions())
	}
}

func TestPipeRejectsArbitraryExecutableAndConfigFields(t *testing.T) {
	controller := &fakePipeController{status: Status{State: accessmodel.StateDisconnected}}
	server := NewPipeServer(controller)

	for _, frame := range []string{
		`{"id":"one","action":"connect","executable":"C:\\evil.exe"}` + "\n",
		`{"id":"two","action":"connect","config":{"route":"direct"}}` + "\n",
	} {
		if response, ok := rawPipeTransaction(t, server, frame); ok {
			t.Fatalf("frame %q returned response %#v", frame, response)
		}
	}
	if len(controller.actions()) != 0 {
		t.Fatalf("injected fields reached controller: %v", controller.actions())
	}
}

func TestPipeMalformedAndOversizedFramesCloseConnection(t *testing.T) {
	controller := &fakePipeController{status: Status{State: accessmodel.StateDisconnected}}
	server := NewPipeServer(controller)

	frames := []string{
		"{not-json}\n",
		strings.Repeat("x", MaxPipeFrameBytes+1) + "\n",
	}
	for _, frame := range frames {
		if response, ok := rawPipeTransaction(t, server, frame); ok {
			t.Fatalf("invalid frame returned response %#v", response)
		}
	}
}

func TestPipeAppliesBoundedDeadlines(t *testing.T) {
	controller := &fakePipeController{status: Status{State: accessmodel.StateDisconnected}}
	server := NewPipeServer(controller)
	serverSide, clientSide := net.Pipe()
	tracked := &deadlineTrackingConn{Conn: serverSide}
	done := make(chan struct{})
	go func() {
		server.serveConnection(tracked)
		close(done)
	}()

	request, _ := json.Marshal(Request{ID: "deadline", Action: ActionStatus})
	_, _ = clientSide.Write(append(request, '\n'))
	_, _ = bufio.NewReader(clientSide).ReadBytes('\n')
	_ = clientSide.Close()
	<-done

	tracked.mu.Lock()
	deadlines := append([]time.Time(nil), tracked.deadlines...)
	tracked.mu.Unlock()
	if len(deadlines) < 2 {
		t.Fatalf("SetDeadline calls = %d, want at least read and write deadlines", len(deadlines))
	}
	for _, deadline := range deadlines {
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > PipeOperationTimeout+time.Second {
			t.Fatalf("deadline remaining = %s", remaining)
		}
	}
}

func TestPipeConnectReceivesBoundedOperationContext(t *testing.T) {
	controller := &deadlinePipeController{fakePipeController: fakePipeController{status: Status{State: accessmodel.StateDisconnected}}}
	_, ok := pipeTransaction(t, NewPipeServer(controller), Request{ID: "bounded-context", Action: ActionConnect})

	if !ok {
		t.Fatal("connect returned no response")
	}
	if controller.remaining <= 90*time.Second || controller.remaining > 120*time.Second {
		t.Fatalf("connect context deadline remaining = %s", controller.remaining)
	}
}

func TestPipeDiagnosticsAreRedacted(t *testing.T) {
	controller := &fakePipeController{
		status: Status{State: accessmodel.StateFailed},
		diagnostics: Diagnostics{
			State:     accessmodel.StateFailed,
			ErrorCode: ErrorCredential,
			Message:   "credential topsecret could not be read",
			Stage:     "firewall_publish",
			Detail:    "fixed operation topsecret failed",
		},
	}
	server := NewPipeServer(controller, WithPipeRedactions([]byte("topsecret")))

	response, ok := pipeTransaction(t, server, Request{ID: "diagnostics", Action: ActionDiagnostics})

	if !ok {
		t.Fatal("diagnostics returned no response")
	}
	if strings.Contains(response.Message, "topsecret") || !strings.Contains(response.Message, "[REDACTED]") {
		t.Fatalf("diagnostics message was not redacted: %q", response.Message)
	}
}

func pipeTransaction(t *testing.T, server *PipeServer, request Request) (Response, bool) {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return rawPipeTransaction(t, server, string(data)+"\n")
}

func rawPipeTransaction(t *testing.T, server *PipeServer, frame string) (Response, bool) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConnection(serverSide)
		close(done)
	}()
	writeDone := make(chan struct{})
	go func() {
		_, _ = io.WriteString(clientSide, frame)
		close(writeDone)
	}()
	_ = clientSide.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(clientSide).ReadBytes('\n')
	_ = clientSide.Close()
	<-writeDone
	<-done
	if err != nil {
		return Response{}, false
	}
	var response Response
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response, true
}

type fakePipeController struct {
	mu          sync.Mutex
	status      Status
	diagnostics Diagnostics
	called      []string
}

func (f *fakePipeController) Connect(context.Context) Status {
	return f.call(ActionConnect)
}

func (f *fakePipeController) Disconnect(context.Context) Status {
	return f.call(ActionDisconnect)
}

func (f *fakePipeController) Status() Status { return f.call(ActionStatus) }

func (f *fakePipeController) Diagnostics() Diagnostics {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = append(f.called, ActionDiagnostics)
	return f.diagnostics
}

func (f *fakePipeController) call(action string) Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = append(f.called, action)
	return f.status
}

func (f *fakePipeController) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.called...)
}

type deadlineTrackingConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

type deadlinePipeController struct {
	fakePipeController
	remaining time.Duration
}

func (d *deadlinePipeController) Connect(ctx context.Context) Status {
	deadline, ok := ctx.Deadline()
	if !ok {
		return Status{State: accessmodel.StateFailed, ErrorCode: "missing_deadline"}
	}
	d.remaining = time.Until(deadline)
	return Status{State: accessmodel.StateConnected}
}

func (c *deadlineTrackingConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}
