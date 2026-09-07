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
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"corp.example/overseas-access-gateway/internal/localapi"
	"corp.example/overseas-access-gateway/internal/traceevent"

	"github.com/Microsoft/go-winio"
)

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

func WithTraceSource(source traceevent.Source) PipeOption {
	return func(server *PipeServer) { server.traceSource = source }
}

type PipeServer struct {
	controller     PipeController
	redactions     [][]byte
	traceSource    traceevent.Source
	lineProbe      *lineprobe.Scheduler
	diagnosticMode diagnosticEnabler
}

func WithLineProbe(scheduler *lineprobe.Scheduler) PipeOption {
	return func(server *PipeServer) { server.lineProbe = scheduler }
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
	if isVersionedPipeRequest(frame) {
		s.serveV1(connection, frame)
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

func isVersionedPipeRequest(frame []byte) bool {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(frame, &envelope) != nil {
		return false
	}
	_, present := envelope["version"]
	return present
}

func (s *PipeServer) serveV1(connection net.Conn, frame []byte) {
	request, err := localapi.DecodeRequest(frame)
	if err != nil {
		return
	}
	operationTimeout := PipeTimeoutForAction(request.Action)
	if err := connection.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()

	administrator := request.Action == localapi.ActionDiagnosticEnable && pipeAdministrator(connection)
	response := NewLocalHandler(s.controller, s.lineProbe, s.diagnosticMode).Dispatch(ctx, request, administrator)
	data, err := localapi.EncodeResponse(response)
	if err != nil {
		return
	}
	if err := connection.SetDeadline(time.Now().Add(PipeOperationTimeout)); err != nil {
		return
	}
	_, _ = connection.Write(data)
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
	if request.Action == ActionTrace {
		if request.Limit < 0 || request.Limit > TraceMaxLimit {
			return Request{}, errors.New("invalid trace limit")
		}
	} else if request.AfterSequence != 0 || request.Limit != 0 {
		return Request{}, errors.New("trace fields require trace action")
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
	case ActionTrace:
		if s.traceSource == nil {
			return Response{ID: request.ID, State: string(accessmodel.StatePrepared), ErrorCode: ErrorInvalidRequest, Message: "日志通道不可用"}
		}
		limit := request.Limit
		if limit == 0 {
			limit = TraceDefaultLimit
		}
		batch := s.traceSource.Batch(request.AfterSequence, limit)
		if !validTraceBatch(batch, request.AfterSequence, limit) {
			return Response{ID: request.ID, State: string(accessmodel.StatePrepared), ErrorCode: ErrorInvalidRequest, Message: "日志批次不可用"}
		}
		return s.fitTraceResponse(request, batch)
	default:
		return Response{ID: request.ID, State: string(accessmodel.StatePrepared), ErrorCode: ErrorInvalidAction, Message: "不支持的操作"}
	}
	return responseFromStatus(request.ID, status)
}

func validTraceBatch(batch traceevent.Batch, after uint64, limit int) bool {
	if len(batch.Events) > limit {
		return false
	}
	previous := after
	for _, event := range batch.Events {
		if traceevent.Validate(event) != nil || event.Sequence <= previous {
			return false
		}
		if batch.OldestSequence == 0 || event.Sequence < batch.OldestSequence {
			return false
		}
		previous = event.Sequence
	}
	if len(batch.Events) == 0 {
		return batch.NextSequence == after && !batch.HasMore
	}
	return batch.NextSequence == batch.Events[len(batch.Events)-1].Sequence
}

func (s *PipeServer) fitTraceResponse(request Request, batch traceevent.Batch) Response {
	state := s.controller.Status()
	for count := len(batch.Events); count >= 0; count-- {
		candidate := batch
		candidate.Events = append([]traceevent.Event(nil), batch.Events[:count]...)
		if count == 0 {
			candidate.NextSequence = request.AfterSequence
		} else {
			candidate.NextSequence = candidate.Events[count-1].Sequence
		}
		if count < len(batch.Events) {
			candidate.HasMore = true
		}
		message, err := json.Marshal(candidate)
		if err != nil {
			break
		}
		message = s.redact(message)
		response := Response{
			ID: request.ID, State: string(state.State), ErrorCode: state.ErrorCode, Message: string(message),
		}
		encoded, err := json.Marshal(response)
		if err == nil && len(encoded)+1 <= MaxPipeFrameBytes {
			return response
		}
	}
	return Response{ID: request.ID, State: string(accessmodel.StatePrepared), ErrorCode: ErrorInvalidRequest, Message: "日志批次不可用"}
}

func (s *PipeServer) redact(message []byte) []byte {
	redacted := append([]byte(nil), message...)
	for _, secret := range s.redactions {
		redacted = bytes.ReplaceAll(redacted, secret, []byte("[REDACTED]"))
	}
	return redacted
}
