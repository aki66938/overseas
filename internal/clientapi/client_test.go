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
	if remaining := time.Until(gotDeadline); remaining < 29*time.Second || remaining > 31*time.Second {
		t.Fatalf("dial deadline remaining = %s, want about 30s", remaining)
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
