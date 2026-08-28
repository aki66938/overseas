//go:build windows

package main

import (
	"context"
	"sync"
	"testing"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
	"golang.org/x/sys/windows/svc"
)

func TestServiceStopDisconnectsAndReturnsServiceSpecificFailure(t *testing.T) {
	controller := &fakeServiceController{
		recoverStatus:    agent.Status{State: accessmodel.StateDisconnected},
		disconnectStatus: agent.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorRestoreFailed},
	}
	handler := &serviceHandler{controller: controller, pipe: blockingPipeRunner{}}
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 4)
	result := make(chan serviceResult, 1)
	go func() {
		specific, code := handler.Execute(nil, requests, changes)
		result <- serviceResult{specific: specific, code: code}
	}()

	waitForRunning(t, changes)
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	got := <-result

	if !got.specific || got.code == 0 {
		t.Fatalf("Execute() = serviceSpecific %v, code %d", got.specific, got.code)
	}
	if controller.disconnectCalls != 1 {
		t.Fatalf("Disconnect() calls = %d, want 1", controller.disconnectCalls)
	}
}

func TestServiceStopReturnsSuccessAfterRestoration(t *testing.T) {
	controller := &fakeServiceController{
		recoverStatus:    agent.Status{State: accessmodel.StateDisconnected},
		disconnectStatus: agent.Status{State: accessmodel.StateDisconnected},
	}
	handler := &serviceHandler{controller: controller, pipe: blockingPipeRunner{}}
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 4)
	result := make(chan serviceResult, 1)
	go func() {
		specific, code := handler.Execute(nil, requests, changes)
		result <- serviceResult{specific: specific, code: code}
	}()

	waitForRunning(t, changes)
	requests <- svc.ChangeRequest{Cmd: svc.Shutdown}
	got := <-result

	if got.specific || got.code != 0 {
		t.Fatalf("Execute() = serviceSpecific %v, code %d", got.specific, got.code)
	}
}

func TestServiceStartupFailsWhenRestartReconciliationFails(t *testing.T) {
	controller := &fakeServiceController{
		recoverStatus: agent.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorRestoreFailed},
	}
	handler := &serviceHandler{controller: controller, pipe: blockingPipeRunner{}}

	specific, code := handler.Execute(nil, make(chan svc.ChangeRequest), make(chan svc.Status, 2))

	if !specific || code == 0 {
		t.Fatalf("Execute() = serviceSpecific %v, code %d", specific, code)
	}
}

type serviceResult struct {
	specific bool
	code     uint32
}

type fakeServiceController struct {
	mu               sync.Mutex
	recoverStatus    agent.Status
	disconnectStatus agent.Status
	disconnectCalls  int
}

func (f *fakeServiceController) Connect(context.Context) agent.Status {
	return agent.Status{State: accessmodel.StateConnected}
}

func (f *fakeServiceController) Disconnect(context.Context) agent.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnectCalls++
	return f.disconnectStatus
}

func (f *fakeServiceController) Recover(context.Context) agent.Status { return f.recoverStatus }
func (f *fakeServiceController) Status() agent.Status                 { return f.recoverStatus }
func (f *fakeServiceController) Diagnostics() agent.Diagnostics {
	return agent.Diagnostics{State: f.recoverStatus.State}
}

type blockingPipeRunner struct{}

func (blockingPipeRunner) ListenAndServe(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func waitForRunning(t *testing.T, changes <-chan svc.Status) {
	t.Helper()
	for {
		status := <-changes
		if status.State == svc.Running {
			return
		}
	}
}
