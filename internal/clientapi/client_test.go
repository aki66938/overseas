package clientapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/traceevent"
)

func TestConnectUsesFixedPipeDeadlineAndRequestShape(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	var gotPath string
	var gotDeadline time.Time
	requestSeen := make(chan map[string]any, 1)

	go func() {
		defer serverConn.Close()
		line, err := bufio.NewReader(serverConn).ReadBytes('\n')
		if err != nil {
			t.Errorf("ReadBytes: %v", err)
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(line, &payload); err != nil {
			t.Errorf("Unmarshal request: %v", err)
			return
		}
		requestSeen <- payload
		response := agent.Response{ID: "request-fixed", State: string(accessmodel.StateConnected)}
		if err := json.NewEncoder(serverConn).Encode(response); err != nil {
			t.Errorf("Encode response: %v", err)
		}
	}()

	client := New(
		WithDialPipe(func(ctx context.Context, path string) (net.Conn, error) {
			gotPath = path
			var ok bool
			gotDeadline, ok = ctx.Deadline()
			if !ok {
				t.Fatal("dial context had no deadline")
			}
			return clientConn, nil
		}),
		WithRequestIDGenerator(func() (string, error) { return "request-fixed", nil }),
	)

	status, err := client.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if status.State != accessmodel.StateConnected {
		t.Fatalf("Connect() state = %q", status.State)
	}
	if gotPath != agent.PipeName {
		t.Fatalf("dial path = %q, want %q", gotPath, agent.PipeName)
	}
	if remaining := time.Until(gotDeadline); remaining < 119*time.Second || remaining > 121*time.Second {
		t.Fatalf("dial deadline remaining = %s, want about 120s", remaining)
	}

	payload := <-requestSeen
	if len(payload) != 2 {
		t.Fatalf("request field count = %d, want 2", len(payload))
	}
	if payload["id"] != "request-fixed" || payload["action"] != agent.ActionConnect {
		t.Fatalf("request payload = %#v", payload)
	}
	if _, ok := payload["secret"]; ok {
		t.Fatalf("request leaked secret field: %#v", payload)
	}
	if _, ok := payload["config"]; ok {
		t.Fatalf("request leaked config field: %#v", payload)
	}
}

func TestTraceUsesExactIncrementalRequestAndAcceptsBatch(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	requestSeen := make(chan map[string]any, 1)
	go func() {
		defer serverConn.Close()
		line, _ := bufio.NewReader(serverConn).ReadBytes('\n')
		var request map[string]any
		_ = json.Unmarshal(line, &request)
		requestSeen <- request
		batch := traceevent.Batch{
			Events:       []traceevent.Event{clientTraceEvent(8)},
			NextSequence: 8, OldestSequence: 4,
		}
		message, _ := json.Marshal(batch)
		_ = json.NewEncoder(serverConn).Encode(agent.Response{
			ID: "request-fixed", State: string(accessmodel.StateFailed), Message: string(message),
		})
	}()
	client := New(
		WithDialPipe(func(context.Context, string) (net.Conn, error) { return clientConn, nil }),
		WithRequestIDGenerator(func() (string, error) { return "request-fixed", nil }),
	)
	batch, err := client.Trace(context.Background(), 7, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 1 || batch.NextSequence != 8 || batch.OldestSequence != 4 {
		t.Fatalf("batch = %#v", batch)
	}
	request := <-requestSeen
	if len(request) != 4 || request["id"] != "request-fixed" || request["action"] != agent.ActionTrace || request["after_sequence"] != float64(7) || request["limit"] != float64(12) {
		t.Fatalf("request = %#v", request)
	}
}

func TestTraceRejectsMalformedOrUnapprovedBatch(t *testing.T) {
	valid := clientTraceEvent(8)
	validJSON := mustJSON(t, valid)
	unknownEventJSON := strings.TrimSuffix(validJSON, "}") + `,"unexpected":true}`
	tests := []struct {
		name    string
		message string
	}{
		{"unknown batch field", `{"events":[],"next_sequence":7,"oldest_sequence":0,"unexpected":true}`},
		{"unknown event field", `{"events":[` + unknownEventJSON + `],"next_sequence":8,"oldest_sequence":8}`},
		{"unknown schema", func() string {
			event := valid
			event.SchemaVersion = 2
			return mustJSON(t, traceevent.Batch{Events: []traceevent.Event{event}, NextSequence: 8, OldestSequence: 8})
		}()},
		{"unknown stage", func() string {
			event := valid
			event.Stage = "shell"
			return mustJSON(t, traceevent.Batch{Events: []traceevent.Event{event}, NextSequence: 8, OldestSequence: 8})
		}()},
		{"non monotonic", mustJSON(t, traceevent.Batch{Events: []traceevent.Event{clientTraceEvent(9), clientTraceEvent(8)}, NextSequence: 8, OldestSequence: 8})},
		{"cursor replay", mustJSON(t, traceevent.Batch{Events: []traceevent.Event{clientTraceEvent(7)}, NextSequence: 7, OldestSequence: 7})},
		{"wrong next", mustJSON(t, traceevent.Batch{Events: []traceevent.Event{valid}, NextSequence: 9, OldestSequence: 8})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClientWithResponse(t, agent.Response{ID: "request-fixed", State: string(accessmodel.StateFailed), Message: test.message})
			if _, err := client.Trace(context.Background(), 7, 12); !errors.Is(err, ErrInvalidResponseShape) {
				t.Fatalf("Trace() error = %v", err)
			}
		})
	}
}

func TestTraceRejectsOversizedResponse(t *testing.T) {
	client := newTestClientWithRawFrame(t, strings.Repeat("x", agent.MaxPipeFrameBytes+1)+"\n")
	if _, err := client.Trace(context.Background(), 0, 0); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Trace() error = %v", err)
	}
}

func clientTraceEvent(sequence uint64) traceevent.Event {
	return traceevent.Event{
		SchemaVersion: traceevent.SchemaVersion,
		Sequence:      sequence,
		TimestampUTC:  time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		Generation:    5,
		Level:         traceevent.LevelInfo,
		Component:     traceevent.ComponentNetwork,
		Stage:         traceevent.StageFirewallPublish,
		Event:         traceevent.EventState,
		Message:       "published",
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestConnectRejectsMismatchedResponseID(t *testing.T) {
	client := newTestClientWithResponse(t, agent.Response{
		ID:    "different-id",
		State: string(accessmodel.StateConnected),
	})

	_, err := client.Connect(context.Background())
	if !errors.Is(err, ErrMismatchedResponseID) {
		t.Fatalf("Connect() error = %v, want %v", err, ErrMismatchedResponseID)
	}
}

func TestStatusRejectsUnknownStateAndErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		response agent.Response
		wantErr  error
	}{
		{
			name:     "unknown state",
			response: agent.Response{ID: "request-fixed", State: "half-open"},
			wantErr:  ErrInvalidResponseState,
		},
		{
			name:     "unknown error code",
			response: agent.Response{ID: "request-fixed", State: string(accessmodel.StateFailed), ErrorCode: "not-approved"},
			wantErr:  ErrInvalidResponseCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClientWithResponse(t, test.response)
			_, err := client.Status(context.Background())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Status() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestDiagnosticsRejectsOversizedResponse(t *testing.T) {
	client := newTestClientWithRawFrame(t, strings.Repeat("x", agent.MaxPipeFrameBytes+1)+"\n")

	_, err := client.Diagnostics(context.Background())
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Diagnostics() error = %v, want %v", err, ErrResponseTooLarge)
	}
}

func TestDiagnosticsAcceptsBoundedNetworkStageAndDetail(t *testing.T) {
	message := `{"state":"failed","error_code":"public_tcp_block_failed","message":"无法建立防泄漏保护","generation":2,"stage":"firewall_publish","detail":"The specified interface was not found."}`
	client := newTestClientWithResponse(t, agent.Response{ID: "request-fixed", State: "failed", ErrorCode: agent.ErrorPublicTCPBlock, Message: message})

	diagnostics, err := client.Diagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.Stage != "firewall_publish" || diagnostics.Detail != "The specified interface was not found." {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestDiagnosticsRejectsSecretOrConfigFields(t *testing.T) {
	tests := []string{
		`{"id":"request-fixed","state":"failed","message":"{\"state\":\"failed\",\"generation\":1,\"secret\":\"abc\"}"}` + "\n",
		`{"id":"request-fixed","state":"failed","message":"{\"state\":\"failed\",\"generation\":1,\"config\":{\"route\":\"direct\"}}"}` + "\n",
		`{"id":"request-fixed","state":"failed","config":{"path":"C:\\evil.json"}}` + "\n",
	}

	for _, frame := range tests {
		client := newTestClientWithRawFrame(t, frame)
		if _, err := client.Diagnostics(context.Background()); !errors.Is(err, ErrInvalidResponseShape) {
			t.Fatalf("Diagnostics() error = %v, want %v", err, ErrInvalidResponseShape)
		}
	}
}

func newTestClientWithResponse(t *testing.T, response agent.Response) *Client {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		_, _ = bufio.NewReader(serverConn).ReadBytes('\n')
		_ = json.NewEncoder(serverConn).Encode(response)
	}()
	return New(
		WithDialPipe(func(context.Context, string) (net.Conn, error) { return clientConn, nil }),
		WithRequestIDGenerator(func() (string, error) { return "request-fixed", nil }),
	)
}

func newTestClientWithRawFrame(t *testing.T, frame string) *Client {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		_, _ = bufio.NewReader(serverConn).ReadBytes('\n')
		_, _ = serverConn.Write([]byte(frame))
	}()
	return New(
		WithDialPipe(func(context.Context, string) (net.Conn, error) { return clientConn, nil }),
		WithRequestIDGenerator(func() (string, error) { return "request-fixed", nil }),
	)
}
