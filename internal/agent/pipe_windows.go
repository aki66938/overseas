//go:build windows

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"

	"github.com/Microsoft/go-winio"
)

const (
	PipeName               = `\\.\pipe\RegenBioOverseasAccess`
	MaxPipeFrameBytes      = 64 * 1024
	PipeOperationTimeout   = 5 * time.Second
	PipeConnectTimeout     = 30 * time.Second
	PipeSecurityDescriptor = "D:P(D;;GA;;;AN)(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

	ActionConnect     = "connect"
	ActionDisconnect  = "disconnect"
	ActionStatus      = "status"
	ActionDiagnostics = "diagnostics"

	ErrorInvalidAction  = "invalid_action"
	ErrorInvalidRequest = "invalid_request"
)

type Request struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

type Response struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
}

type PipeController interface {
	Connect(context.Context) Status
	Disconnect(context.Context) Status
	Status() Status
	Diagnostics() Diagnostics
}

type PipeOption func(*PipeServer)

func WithPipeRedactions(values ...[]byte) PipeOption {
	return func(server *PipeServer) {
		for _, value := range values {
			if len(value) != 0 {
				server.redactions = append(server.redactions, append([]byte(nil), value...))
			}
		}
	}
}

type PipeServer struct {
	controller PipeController
	redactions [][]byte
}

func NewPipeServer(controller PipeController, options ...PipeOption) *PipeServer {
	server := &PipeServer{controller: controller}
	for _, option := range options {
		option(server)
	}
	return server
}

// ListenAndServe exposes only the fixed local pipe name and relies on both the
// kernel DACL and strict request decoding. A connection handles one request.
func (s *PipeServer) ListenAndServe(ctx context.Context) error {
	listener, err := winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: PipeSecurityDescriptor,
		MessageMode:        false,
		InputBufferSize:    MaxPipeFrameBytes,
		OutputBufferSize:   MaxPipeFrameBytes,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)

	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			s.serveConnection(connection)
		}()
	}
}

func (s *PipeServer) serveConnection(connection net.Conn) {
	defer connection.Close()
	if s.controller == nil {
		return
	}
	if err := connection.SetDeadline(time.Now().Add(PipeOperationTimeout)); err != nil {
		return
	}
	frame, err := readPipeFrame(connection)
	if err != nil {
		return
	}
	request, err := decodePipeRequest(frame)
	if err != nil {
		return
	}
	operationTimeout := PipeTimeoutForAction(request.Action)
	if err := connection.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		return
	}
	operationContext, cancel := context.WithTimeout(context.Background(), operationTimeout)
	response := s.dispatch(operationContext, request)
	cancel()
	data, err := json.Marshal(response)
	if err != nil || len(data)+1 > MaxPipeFrameBytes {
		return
	}
	if err := connection.SetDeadline(time.Now().Add(PipeOperationTimeout)); err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = connection.Write(data)
}

func PipeTimeoutForAction(action string) time.Duration {
	if action == ActionConnect {
		return PipeConnectTimeout
	}
	return PipeOperationTimeout
}

func readPipeFrame(connection io.Reader) ([]byte, error) {
	reader := bufio.NewReader(io.LimitReader(connection, MaxPipeFrameBytes+1))
	frame, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if len(frame) > MaxPipeFrameBytes || len(frame) == 0 || frame[len(frame)-1] != '\n' {
		return nil, errors.New("invalid pipe frame size")
	}
	return frame[:len(frame)-1], nil
}

func decodePipeRequest(frame []byte) (Request, error) {
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Request{}, errors.New("multiple JSON values in one frame")
		}
		return Request{}, err
	}
	if request.ID == "" || len(request.ID) > 128 || strings.IndexFunc(request.ID, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return Request{}, errors.New("invalid request ID")
	}
	return request, nil
}

func (s *PipeServer) dispatch(ctx context.Context, request Request) Response {
	var status Status
	switch request.Action {
	case ActionConnect:
		status = s.controller.Connect(ctx)
	case ActionDisconnect:
		status = s.controller.Disconnect(ctx)
	case ActionStatus:
		status = s.controller.Status()
	case ActionDiagnostics:
		diagnostics := s.controller.Diagnostics()
		message, err := json.Marshal(diagnostics)
		if err != nil {
			return Response{ID: request.ID, State: string(diagnostics.State), ErrorCode: ErrorInvalidRequest, Message: "诊断信息不可用"}
		}
		message = s.redact(message)
		return Response{
			ID:        request.ID,
			State:     string(diagnostics.State),
			ErrorCode: diagnostics.ErrorCode,
			Message:   string(message),
		}
	default:
		return Response{ID: request.ID, State: string(accessmodel.StateFailed), ErrorCode: ErrorInvalidAction, Message: "不支持的操作"}
	}
	return Response{ID: request.ID, State: string(status.State), ErrorCode: status.ErrorCode, Message: status.Message}
}

func (s *PipeServer) redact(message []byte) []byte {
	redacted := append([]byte(nil), message...)
	for _, secret := range s.redactions {
		redacted = bytes.ReplaceAll(redacted, secret, []byte("[REDACTED]"))
	}
	return redacted
}
