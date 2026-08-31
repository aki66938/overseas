//go:build windows

package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows/svc"
)

func TestReadinessAddressComesFromLockedServerConfig(t *testing.T) {
	config := []byte(`{"inbounds":[{"type":"shadowsocks","tag":"tunnel-in","listen":"172.20.9.15","listen_port":18443}],"outbounds":[{"type":"http"}]}`)
	address, err := serverListenAddress(config)
	if err != nil {
		t.Fatal(err)
	}
	if address != "172.20.9.15:18443" {
		t.Fatalf("address=%q", address)
	}
	for _, changed := range [][]byte{
		[]byte(strings.Replace(string(config), `"listen":"172.20.9.15"`, `"listen":"127.0.0.1"`, 1)),
		[]byte(strings.Replace(string(config), `]`, `,{"type":"shadowsocks","listen":"172.20.9.16","listen_port":18443}]`, 1)),
		append(config, []byte(` {}`)...),
	} {
		if _, err := serverListenAddress(changed); err == nil {
			t.Fatal("unsafe or ambiguous server config was accepted")
		}
	}
}

type fakeManagedProcess struct {
	mu                sync.Mutex
	events            []string
	startErr          error
	readyErr          error
	stopErr           error
	terminationProven bool
	wait              chan error
}

func newFakeManagedProcess() *fakeManagedProcess {
	return &fakeManagedProcess{terminationProven: true, wait: make(chan error, 1)}
}

func (f *fakeManagedProcess) record(event string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *fakeManagedProcess) Start(context.Context) error { f.record("start"); return f.startErr }
func (f *fakeManagedProcess) Ready(context.Context) error { f.record("ready"); return f.readyErr }
func (f *fakeManagedProcess) Stop(context.Context) error  { f.record("stop"); return f.stopErr }
func (f *fakeManagedProcess) Wait() error                 { return <-f.wait }
func (f *fakeManagedProcess) TerminationProven() bool     { return f.terminationProven }

func (f *fakeManagedProcess) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func TestServiceReportsRunningOnlyAfterStartAndReadiness(t *testing.T) {
	process := newFakeManagedProcess()
	handler := &serviceHandler{process: process}
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 4)
	result := make(chan serviceResult, 1)
	go func() {
		specific, code := handler.Execute(nil, requests, changes)
		result <- serviceResult{specific: specific, code: code}
	}()

	startPending := <-changes
	running := <-changes
	if startPending.State != svc.StartPending || running.State != svc.Running {
		t.Fatalf("statuses = %v then %v, want StartPending then Running", startPending.State, running.State)
	}
	if !reflect.DeepEqual(process.recorded(), []string{"start", "ready"}) {
		t.Fatalf("events before Running = %v, want start then ready", process.recorded())
	}

	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if status := <-changes; status.State != svc.StopPending {
		t.Fatalf("stop status = %v, want StopPending", status.State)
	}
	got := <-result
	if got.specific || got.code != 0 {
		t.Fatalf("Execute() = serviceSpecific %v, code %d", got.specific, got.code)
	}
	if !reflect.DeepEqual(process.recorded(), []string{"start", "ready", "stop"}) {
		t.Fatalf("events = %v, want start, ready, stop", process.recorded())
	}
}

func TestServiceShutdownRequiresProvenCleanup(t *testing.T) {
	process := newFakeManagedProcess()
	process.terminationProven = false
	handler := &serviceHandler{process: process}
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 4)
	result := make(chan serviceResult, 1)
	go func() {
		specific, code := handler.Execute(nil, requests, changes)
		result <- serviceResult{specific: specific, code: code}
	}()

	<-changes
	<-changes
	requests <- svc.ChangeRequest{Cmd: svc.Shutdown}
	<-changes
	got := <-result
	if !got.specific || got.code != serviceExitCleanup {
		t.Fatalf("Execute() = serviceSpecific %v, code %d, want cleanup failure", got.specific, got.code)
	}
	if !reflect.DeepEqual(process.recorded(), []string{"start", "ready", "stop"}) {
		t.Fatalf("events = %v, want start, ready, stop", process.recorded())
	}
}

func TestReadinessFailureStopsAndProvesCleanupBeforeReturning(t *testing.T) {
	process := newFakeManagedProcess()
	process.readyErr = errors.New("not ready")
	handler := &serviceHandler{process: process}
	changes := make(chan svc.Status, 4)

	specific, code := handler.Execute(nil, make(chan svc.ChangeRequest), changes)
	if !specific || code != serviceExitReadiness {
		t.Fatalf("Execute() = serviceSpecific %v, code %d, want readiness failure", specific, code)
	}
	if !reflect.DeepEqual(process.recorded(), []string{"start", "ready", "stop"}) {
		t.Fatalf("events = %v, want start, ready, stop", process.recorded())
	}
	if status := <-changes; status.State != svc.StartPending {
		t.Fatalf("first status = %v, want StartPending", status.State)
	}
	if status := <-changes; status.State != svc.StopPending {
		t.Fatalf("second status = %v, want StopPending", status.State)
	}
}

func TestStartFailureRunsCleanupAndReturnsStartFailure(t *testing.T) {
	process := newFakeManagedProcess()
	process.startErr = errors.New("start failed")
	handler := &serviceHandler{process: process}
	changes := make(chan svc.Status, 3)

	specific, code := handler.Execute(nil, make(chan svc.ChangeRequest), changes)
	if !specific || code != serviceExitStart {
		t.Fatalf("Execute() = serviceSpecific %v, code %d, want start failure", specific, code)
	}
	if !reflect.DeepEqual(process.recorded(), []string{"start", "stop"}) {
		t.Fatalf("events = %v, want start then cleanup stop", process.recorded())
	}
}

func TestUnexpectedChildExitReturnsServiceFailureAfterProof(t *testing.T) {
	process := newFakeManagedProcess()
	handler := &serviceHandler{process: process}
	requests := make(chan svc.ChangeRequest)
	changes := make(chan svc.Status, 4)
	result := make(chan serviceResult, 1)
	go func() {
		specific, code := handler.Execute(nil, requests, changes)
		result <- serviceResult{specific: specific, code: code}
	}()

	<-changes
	<-changes
	process.wait <- errors.New("child exited")
	if status := <-changes; status.State != svc.StopPending {
		t.Fatalf("exit status = %v, want StopPending", status.State)
	}
	got := <-result
	if !got.specific || got.code != serviceExitProcess {
		t.Fatalf("Execute() = serviceSpecific %v, code %d, want child-process failure", got.specific, got.code)
	}
}

func TestFixedRuntimePathsAndNoConfigurableExecutable(t *testing.T) {
	if serviceName != "RegenBioOverseasAccessServer" {
		t.Fatalf("serviceName = %q", serviceName)
	}
	if corePath != `C:\Program Files\RegenBio\OverseasAccessServer\sing-box.exe` {
		t.Fatalf("corePath = %q", corePath)
	}
	if configPath != `C:\ProgramData\RegenBio\OverseasAccessServer\config.json` {
		t.Fatalf("configPath = %q", configPath)
	}
	if manifestPath != `C:\ProgramData\RegenBio\OverseasAccessServer\runtime-manifest.json` {
		t.Fatalf("manifestPath = %q", manifestPath)
	}
}

type serviceResult struct {
	specific bool
	code     uint32
}
