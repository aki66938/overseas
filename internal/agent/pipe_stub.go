//go:build !windows

package agent

import (
	"context"
	"errors"
	"time"
)

const (
	PipeName               = `\\.\pipe\RegenBioOverseasAccess`
	MaxPipeFrameBytes      = 64 * 1024
	PipeOperationTimeout   = 5 * time.Second
	PipeConnectTimeout     = 120 * time.Second
	PipeSecurityDescriptor = "D:P(D;;GA;;;AN)(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

	ActionConnect     = "connect"
	ActionDisconnect  = "disconnect"
	ActionStatus      = "status"
	ActionDiagnostics = "diagnostics"

	ErrorInvalidAction  = "invalid_action"
	ErrorInvalidRequest = "invalid_request"
)

func PipeTimeoutForAction(action string) time.Duration {
	if action == ActionConnect {
		return PipeConnectTimeout
	}
	return PipeOperationTimeout
}

var ErrPipeUnsupported = errors.New("named-pipe service is unsupported on this platform")

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

func WithPipeRedactions(...[]byte) PipeOption { return func(*PipeServer) {} }

type PipeServer struct{ controller PipeController }

func NewPipeServer(controller PipeController, _ ...PipeOption) *PipeServer {
	return &PipeServer{controller: controller}
}

func (*PipeServer) ListenAndServe(context.Context) error { return ErrPipeUnsupported }
