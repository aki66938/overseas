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
	"corp.example/overseas-access-gateway/internal/traceevent"
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

func TestPipeTraceReturnsIncrementalBoundedBatch(t *testing.T) {
	events := []traceevent.Event{
		pipeTraceEvent(3, "first"),
		pipeTraceEvent(4, "second"),
		pipeTraceEvent(5, "third"),
	}
	source := &fakeTraceSource{batch: traceevent.Batch{
		Events: events, NextSequence: 5, HasMore: true, OldestSequence: 3,
	}}
	controller := &fakePipeController{status: Status{State: accessmodel.StatePrepared}}
	server := NewPipeServer(controller, WithTraceSource(source))

	response, ok := pipeTransaction(t, server, Request{ID: "trace-1", Action: ActionTrace, AfterSequence: 2, Limit: 3})
	if !ok {
		t.Fatal("trace returned no response")
	}
	if response.ID != "trace-1" || response.State != string(accessmodel.StatePrepared) || response.ErrorCode != "" {
		t.Fatalf("response = %#v", response)
	}
	var batch traceevent.Batch
	if err := json.Unmarshal([]byte(response.Message), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 3 || batch.NextSequence != 5 || !batch.HasMore || batch.OldestSequence != 3 {
		t.Fatalf("batch = %#v", batch)
	}
	if source.after != 2 || source.limit != 3 {
		t.Fatalf("source request = after %d limit %d", source.after, source.limit)
	}
}

func TestPipeTraceUsesDefaultLimitAndSupportsEmptyBatch(t *testing.T) {
	source := &fakeTraceSource{batch: traceevent.Batch{NextSequence: 9, OldestSequence: 9}}
	server := NewPipeServer(&fakePipeController{status: Status{State: accessmodel.StateDisconnected}}, WithTraceSource(source))
	response, ok := pipeTransaction(t, server, Request{ID: "trace-empty", Action: ActionTrace, AfterSequence: 9})
	if !ok {
		t.Fatal("trace returned no response")
	}
	if source.limit != TraceDefaultLimit {
		t.Fatalf("default limit = %d", source.limit)
	}
	var batch traceevent.Batch
	if err := json.Unmarshal([]byte(response.Message), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 0 || batch.NextSequence != 9 {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestPipeTraceRejectsInvalidRequestFields(t *testing.T) {
	controller := &fakePipeController{status: Status{State: accessmodel.StateDisconnected}}
	server := NewPipeServer(controller, WithTraceSource(&fakeTraceSource{}))
	frames := []string{
		`{"id":"negative","action":"trace","limit":-1}` + "\n",
		`{"id":"large","action":"trace","limit":65}` + "\n",
		`{"id":"connect-cursor","action":"connect","after_sequence":1}` + "\n",
		`{"id":"status-limit","action":"status","limit":1}` + "\n",
	}
	for _, frame := range frames {
		if response, ok := rawPipeTransaction(t, server, frame); ok {
			t.Fatalf("invalid frame returned %#v", response)
		}
	}
}

func TestPipeTraceWithoutSourceFailsClosed(t *testing.T) {
	server := NewPipeServer(&fakePipeController{status: Status{State: accessmodel.StateDisconnected}})
	response, ok := pipeTransaction(t, server, Request{ID: "no-source", Action: ActionTrace})
	if !ok || response.ErrorCode != ErrorInvalidRequest || response.State != string(accessmodel.StatePrepared) {
		t.Fatalf("response = %#v ok=%v", response, ok)
	}
}

func TestPipeTraceRejectsInvalidSourceBatch(t *testing.T) {
	event := pipeTraceEvent(1, "invalid")
	event.Stage = "unapproved_stage"
	source := &fakeTraceSource{batch: traceevent.Batch{Events: []traceevent.Event{event}, NextSequence: 1, OldestSequence: 1}}
	server := NewPipeServer(&fakePipeController{status: Status{State: accessmodel.StateConnected}}, WithTraceSource(source))
	response, ok := pipeTransaction(t, server, Request{ID: "invalid-source", Action: ActionTrace})
	if !ok || response.ErrorCode != ErrorInvalidRequest || response.State != string(accessmodel.StatePrepared) {
		t.Fatalf("response = %#v ok=%v", response, ok)
	}
}

func TestPipeTraceResponseFitsFrameByWholeEvents(t *testing.T) {
	var events []traceevent.Event
	for sequence := uint64(1); sequence <= uint64(TraceMaxLimit); sequence++ {
		event := pipeTraceEvent(sequence, "large")
		event.Detail = strings.Repeat(`"\\`, traceevent.MaxDetailBytes/2)
		event.Detail, event.DetailTruncated = traceevent.SanitizeDetail(event.Detail)
		events = append(events, event)
	}
	source := &fakeTraceSource{batch: traceevent.Batch{Events: events, NextSequence: uint64(TraceMaxLimit), OldestSequence: 1}}
	server := NewPipeServer(&fakePipeController{status: Status{State: accessmodel.StateConnected}}, WithTraceSource(source))

	line, ok := rawPipeLine(t, server, Request{ID: "bounded", Action: ActionTrace, Limit: TraceMaxLimit})
	if !ok {
		t.Fatal("trace returned no response")
	}
	if len(line) > MaxPipeFrameBytes {
		t.Fatalf("response bytes = %d", len(line))
	}
	var response Response
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	var batch traceevent.Batch
	if err := json.Unmarshal([]byte(response.Message), &batch); err != nil {
		t.Fatalf("nested batch was cut: %v", err)
	}
	if len(batch.Events) == 0 || len(batch.Events) >= len(events) || !batch.HasMore {
		t.Fatalf("batch was not reduced at event boundary: %d events, has_more=%v", len(batch.Events), batch.HasMore)
	}
	if batch.NextSequence != batch.Events[len(batch.Events)-1].Sequence {
		t.Fatalf("next_sequence=%d last=%d", batch.NextSequence, batch.Events[len(batch.Events)-1].Sequence)
	}
}

func pipeTraceEvent(sequence uint64, message string) traceevent.Event {
	return traceevent.Event{
		SchemaVersion: traceevent.SchemaVersion,
		Sequence:      sequence,
		TimestampUTC:  time.Date(2026, 9, 1, 8, 0, int(sequence), 0, time.UTC),
		Generation:    5,
		Level:         traceevent.LevelInfo,
		Component:     traceevent.ComponentNetwork,
		Stage:         traceevent.StageFirewallPublish,
		Event:         traceevent.EventState,
		Message:       message,
	}
}

type fakeTraceSource struct {
	batch traceevent.Batch
	after uint64
	limit int
}

func (f *fakeTraceSource) Batch(after uint64, limit int) traceevent.Batch {
	f.after, f.limit = after, limit
	return f.batch
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

func TestPipeDisconnectHasDedicatedRecoveryDeadline(t *testing.T) {
	if got := PipeTimeoutForAction(ActionDisconnect); got != PipeDisconnectTimeout {
		t.Fatalf("disconnect timeout = %s, want %s", got, PipeDisconnectTimeout)
	}
	if PipeDisconnectTimeout <= PipeOperationTimeout {
		t.Fatalf("disconnect timeout %s must exceed ordinary operation timeout %s", PipeDisconnectTimeout, PipeOperationTimeout)
	}
}

func TestPipeDisconnectReceivesDedicatedRecoveryContext(t *testing.T) {
	controller := &deadlinePipeController{fakePipeController: fakePipeController{status: Status{State: accessmodel.StateConnected}}}
	_, ok := pipeTransaction(t, NewPipeServer(controller), Request{ID: "disconnect-deadline", Action: ActionDisconnect})
	if !ok {
		t.Fatal("disconnect returned no response")
	}
	if controller.remaining <= 20*time.Second || controller.remaining > PipeDisconnectTimeout {
		t.Fatalf("disconnect context deadline remaining = %s", controller.remaining)
	}
}

func TestPipeDiagnosticsAreRedacted(t *testing.T) {
	controller := &fakePipeController{
		status: Status{State: accessmodel.StatePrepared},
		diagnostics: Diagnostics{
			State:     accessmodel.StatePrepared,
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

func rawPipeLine(t *testing.T, server *PipeServer, request Request) ([]byte, bool) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConnection(serverSide)
		close(done)
	}()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan struct{})
	go func() {
		_, _ = clientSide.Write(append(data, '\n'))
		close(writeDone)
	}()
	_ = clientSide.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(clientSide).ReadBytes('\n')
	_ = clientSide.Close()
	<-writeDone
	<-done
	return line, err == nil
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
		return Status{State: accessmodel.StatePrepared, ErrorCode: "missing_deadline"}
	}
	d.remaining = time.Until(deadline)
	return Status{State: accessmodel.StateConnected}
}

func (d *deadlinePipeController) Disconnect(ctx context.Context) Status {
	deadline, ok := ctx.Deadline()
	if !ok {
		return Status{State: accessmodel.StatePrepared, ErrorCode: "missing_deadline"}
	}
	d.remaining = time.Until(deadline)
	return Status{State: accessmodel.StateDisconnected}
}

func (c *deadlineTrackingConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}
