package agent

import (
	"context"
	"time"

	"corp.example/overseas-access-gateway/internal/lineprobe"
	"corp.example/overseas-access-gateway/internal/localapi"
)

const (
	PipeName             = `\\.\pipe\RegenBioOverseasAccess`
	MaxPipeFrameBytes    = 64 * 1024
	PipeOperationTimeout = 5 * time.Second
	// Disconnect runs the full reverse-order restoration (multiple PowerShell
	// transactions, 3-12s each on the pilot machine); 30s repeatedly expired
	// before the zero-residue proof and misreported failed_safe.
	PipeDisconnectTimeout  = 90 * time.Second
	PipeConnectTimeout     = 120 * time.Second
	PipeSecurityDescriptor = "D:P(D;;GA;;;AN)(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

	ActionConnect     = "connect"
	ActionDisconnect  = "disconnect"
	ActionStatus      = "status"
	ActionDiagnostics = "diagnostics"
	ActionTrace       = "trace"

	TraceDefaultLimit = 32
	TraceMaxLimit     = 64

	ErrorInvalidAction  = "invalid_action"
	ErrorInvalidRequest = "invalid_request"
)

type Request struct {
	ID            string `json:"id"`
	Action        string `json:"action"`
	AfterSequence uint64 `json:"after_sequence,omitempty"`
	Limit         int    `json:"limit,omitempty"`
}

type Response struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	ErrorCode  string `json:"error_code,omitempty"`
	Message    string `json:"message,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Step       int    `json:"step,omitempty"`
	TotalSteps int    `json:"total_steps,omitempty"`
	ElapsedMS  int64  `json:"elapsed_ms,omitempty"`
}

func responseFromStatus(id string, status Status) Response {
	return Response{
		ID: id, State: string(status.State), ErrorCode: status.ErrorCode, Message: status.Message,
		Phase: status.Phase, Step: status.Step, TotalSteps: status.TotalSteps, ElapsedMS: status.ElapsedMS,
	}
}

type PipeController interface {
	Connect(context.Context) Status
	Disconnect(context.Context) Status
	Status() Status
	Diagnostics() Diagnostics
}

func PipeTimeoutForAction(action string) time.Duration {
	switch action {
	case ActionConnect:
		return PipeConnectTimeout
	case ActionDisconnect:
		return PipeDisconnectTimeout
	case localapi.ActionProbe:
		return lineprobe.RoundBudget + PipeOperationTimeout
	default:
		return PipeOperationTimeout
	}
}
