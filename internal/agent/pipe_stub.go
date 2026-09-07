//go:build !windows

package agent

import (
	"context"
	"errors"

	"corp.example/overseas-access-gateway/internal/traceevent"
)

var ErrPipeUnsupported = errors.New("named-pipe service is unsupported on this platform")

type PipeOption func(*PipeServer)

func WithPipeRedactions(...[]byte) PipeOption      { return func(*PipeServer) {} }
func WithTraceSource(traceevent.Source) PipeOption { return func(*PipeServer) {} }

type PipeServer struct{ controller PipeController }

func NewPipeServer(controller PipeController, _ ...PipeOption) *PipeServer {
	return &PipeServer{controller: controller}
}

func (*PipeServer) ListenAndServe(context.Context) error { return ErrPipeUnsupported }
