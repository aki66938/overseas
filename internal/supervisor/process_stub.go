//go:build !windows

// Package supervisor provides process supervision on supported platforms.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	ErrUnsupported      = errors.New("process supervision is unsupported on this platform")
	ErrAlreadyStarted   = errors.New("process has already been started")
	ErrNotStarted       = errors.New("process has not been started")
	ErrReadyTimeout     = errors.New("process readiness timed out")
	ErrUnsafePath       = errors.New("executable and config paths must be absolute, regular, and non-reparse")
	ErrNoReadinessProbe = errors.New("configuration has no deterministic readiness probe")
)

type ExitError struct {
	Code        int
	BeforeReady bool
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("supervised process exited unexpectedly with code %d", e.Code)
}

type Process struct {
	ReadyTimeout time.Duration
	StopTimeout  time.Duration
	ReadyProbe   func(context.Context) error
	LogWriter    io.Writer
	Secrets      []string
	MaxLogBytes  int
}

func (*Process) Start(context.Context, string, string) error { return ErrUnsupported }
func (*Process) Ready(context.Context) error                 { return ErrUnsupported }
func (*Process) Stop(context.Context) error                  { return ErrUnsupported }
func (*Process) Wait() error                                 { return ErrUnsupported }
