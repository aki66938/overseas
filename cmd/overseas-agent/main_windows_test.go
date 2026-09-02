//go:build windows

package main

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/traceevent"
	"golang.org/x/sys/windows/svc"
)

func TestBuildCoreVerifierRejectsInvalidTrustPolicy(t *testing.T) {
	if _, err := buildCoreVerifier(bootstrapConfig{CoreSHA256: "invalid"}); err == nil {
		t.Fatal("invalid core trust policy was accepted")
	}
}

func TestRenderClientConfigUsesDirectTelecomHTTPOutbound(t *testing.T) {
	policy := accessmodel.Policy{
		SchemaVersion: 2, Mode: "poc",
		Nodes:          []accessmodel.Node{{ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 8080, Priority: 10}},
		CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"},
		BlockUDP: true, BlockQUIC: true,
	}
	contents, err := renderClientConfig(policy, agent.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(contents, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Outbounds) != 2 || config.Outbounds[1]["type"] != "http" || config.Outbounds[1]["server"] != "172.20.9.15" || config.Outbounds[1]["server_port"] != float64(8080) {
		t.Fatalf("outbounds = %#v", config.Outbounds)
	}
	if _, exists := config.Outbounds[1]["password"]; exists {
		t.Fatal("HTTP outbound contains a password")
	}
}

func TestServiceTraceClosesAndRecordsNormalLifecycle(t *testing.T) {
	controller := &fakeServiceController{
		recoverStatus: agent.Status{State: accessmodel.StatePrepared}, disconnectStatus: agent.Status{State: accessmodel.StatePrepared},
	}
	trace := &fakeServiceTrace{}
	handler := &serviceHandler{controller: controller, pipe: blockingPipeRunner{}, trace: trace}
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
	if got.specific || got.code != 0 || trace.closeCalls != 1 {
		t.Fatalf("result=%#v closeCalls=%d", got, trace.closeCalls)
	}
	events := trace.eventsCopy()
	if len(events) < 3 || events[0].Generation != 0 || events[0].Stage != traceevent.StageServiceRecovery || events[0].Event != traceevent.EventState {
		t.Fatalf("service trace = %#v", events)
	}
	if events[len(events)-1].Message != "Windows 服务已停止" {
		t.Fatalf("terminal service event = %#v", events[len(events)-1])
	}
}

func TestServiceTraceClosesWhenStartupRecoveryFails(t *testing.T) {
	trace := &fakeServiceTrace{}
	handler := &serviceHandler{
		controller: &fakeServiceController{recoverStatus: agent.Status{State: accessmodel.StateFailedSafe, ErrorCode: agent.ErrorAutomaticRestore}},
		pipe:       blockingPipeRunner{}, trace: trace,
	}
	specific, code := handler.Execute(nil, make(chan svc.ChangeRequest), make(chan svc.Status, 2))
	if !specific || code != serviceExitRestore || trace.closeCalls != 1 {
		t.Fatalf("specific=%v code=%d closeCalls=%d", specific, code, trace.closeCalls)
	}
	events := trace.eventsCopy()
	if len(events) < 2 || events[len(events)-1].Level != traceevent.LevelError || events[len(events)-1].Event != traceevent.EventState {
		t.Fatalf("failure trace = %#v", events)
	}
}

func TestServiceTraceProductionLimitsAreFixed(t *testing.T) {
	if traceDirectory != dataDirectory+`\logs` || traceMemoryCapacity != 2048 || traceMaxFileBytes != 2*1024*1024 || traceRetainFiles != 5 {
		t.Fatalf("trace limits = directory %q capacity %d bytes %d files %d", traceDirectory, traceMemoryCapacity, traceMaxFileBytes, traceRetainFiles)
	}
}

func TestServiceStopDisconnectsAndReturnsServiceSpecificFailure(t *testing.T) {
	controller := &fakeServiceController{
		recoverStatus:    agent.Status{State: accessmodel.StatePrepared},
		disconnectStatus: agent.Status{State: accessmodel.StateFailedSafe, ErrorCode: agent.ErrorAutomaticRestore},
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
		recoverStatus:    agent.Status{State: accessmodel.StatePrepared},
		disconnectStatus: agent.Status{State: accessmodel.StatePrepared},
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

func TestServiceStopRequiresDisconnectedTerminalState(t *testing.T) {
	for _, state := range []accessmodel.ConnectionState{
		accessmodel.StateConnecting,
		accessmodel.StateConnected,
		accessmodel.StateFailedSafe,
	} {
		t.Run(string(state), func(t *testing.T) {
			controller := &fakeServiceController{
				recoverStatus:    agent.Status{State: accessmodel.StatePrepared},
				disconnectStatus: agent.Status{State: state, ErrorCode: agent.ErrorCanceled},
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
				t.Fatalf("Execute() for %s = serviceSpecific %v, code %d", state, got.specific, got.code)
			}
		})
	}
}

func TestServiceStartupFailsWhenRestartReconciliationFails(t *testing.T) {
	controller := &fakeServiceController{
		recoverStatus: agent.Status{State: accessmodel.StateFailedSafe, ErrorCode: agent.ErrorAutomaticRestore},
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

type fakeServiceTrace struct {
	mu         sync.Mutex
	events     []traceevent.Event
	closeCalls int
}

func (f *fakeServiceTrace) Record(event traceevent.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	event.SchemaVersion = traceevent.SchemaVersion
	event.Sequence = uint64(len(f.events) + 1)
	event.TimestampUTC = time.Now().UTC()
	f.events = append(f.events, event)
}

func (f *fakeServiceTrace) Batch(after uint64, limit int) traceevent.Batch {
	f.mu.Lock()
	defer f.mu.Unlock()
	batch := traceevent.Batch{NextSequence: after}
	if len(f.events) != 0 {
		batch.OldestSequence = f.events[0].Sequence
	}
	for _, event := range f.events {
		if event.Sequence > after && len(batch.Events) < limit {
			batch.Events = append(batch.Events, event)
			batch.NextSequence = event.Sequence
		}
	}
	return batch
}

func (f *fakeServiceTrace) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
	return nil
}

func (f *fakeServiceTrace) eventsCopy() []traceevent.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]traceevent.Event(nil), f.events...)
}
