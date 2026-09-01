package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/clientapi"
	"corp.example/overseas-access-gateway/internal/traceevent"
)

func TestViewModelMapsConnectionStatesToExactCopy(t *testing.T) {
	tests := []struct {
		name   string
		status clientapi.Status
		want   ViewState
	}{
		{
			name:   "disconnected",
			status: clientapi.Status{State: accessmodel.StateDisconnected},
			want: ViewState{
				StatusText:    "未连接",
				DetailText:    "",
				ButtonText:    "开启海外访问",
				ButtonEnabled: true,
			},
		},
		{
			name:   "connecting",
			status: clientapi.Status{State: accessmodel.StateConnecting},
			want: ViewState{
				StatusText:    "正在连接",
				DetailText:    "",
				ButtonText:    "正在连接",
				ButtonEnabled: false,
			},
		},
		{
			name:   "connected",
			status: clientapi.Status{State: accessmodel.StateConnected},
			want: ViewState{
				StatusText:    "已连接",
				DetailText:    "",
				ButtonText:    "关闭海外访问",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed invalid binary",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorInvalidBinary, Message: "raw internal message"},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "客户端配置需要修复，请联系 IT",
				ButtonText:    "安全重试",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed upstream unavailable",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorCoreNotReady},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "无法连接海外访问服务器",
				ButtonText:    "安全重试",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed carrier session lost",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorReadinessLost},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "运营商线路未登录或已失效，请联系 IT",
				ButtonText:    "安全重试",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed local configuration",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorNetworkCapture},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "本机安全网络配置失败，请联系 IT",
				ButtonText:    "安全重试",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed unauthorized",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: clientapi.ErrorUnauthorized},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "当前账号未获授权",
				ButtonText:    "安全重试",
				ButtonEnabled: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vm := NewViewModel(&fakeServiceClient{statusResult: test.status}, nil)
			vm.setStatus(test.status)
			if got := vm.State(); got.StatusText != test.want.StatusText || got.DetailText != test.want.DetailText || got.ButtonText != test.want.ButtonText || got.ButtonEnabled != test.want.ButtonEnabled {
				t.Fatalf("State() = %#v, want core fields %#v", got, test.want)
			}
		})
	}
}

func TestViewModelSuppressesDoubleClickWhileOperationRuns(t *testing.T) {
	client := &fakeServiceClient{
		statusResult:  clientapi.Status{State: accessmodel.StateDisconnected},
		connectResult: clientapi.Status{State: accessmodel.StateConnected},
		connectGate:   make(chan struct{}),
		started:       make(chan struct{}, 1),
	}
	vm := NewViewModel(client, nil)
	vm.setStatus(client.statusResult)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := vm.Toggle(context.Background()); err != nil {
			t.Errorf("first Toggle() error = %v", err)
		}
	}()
	<-client.started

	if got := vm.State(); got.ButtonText != "正在连接" || got.ButtonEnabled {
		t.Fatalf("busy state = %#v", got)
	}
	if err := vm.Toggle(context.Background()); err != nil {
		t.Fatalf("second Toggle() error = %v", err)
	}
	close(client.connectGate)
	<-done

	if client.connectCalls() != 1 {
		t.Fatalf("Connect() calls = %d, want 1", client.connectCalls())
	}
	if got := vm.State(); got.StatusText != "已连接" || got.ButtonText != "关闭海外访问" {
		t.Fatalf("final state = %#v", got)
	}
}

func TestViewModelShowsDisconnectBusyStateAndThenDisconnected(t *testing.T) {
	client := &fakeServiceClient{
		statusResult:     clientapi.Status{State: accessmodel.StateConnected},
		disconnectResult: clientapi.Status{State: accessmodel.StateDisconnected},
		disconnectGate:   make(chan struct{}),
		disconnectStart:  make(chan struct{}, 1),
	}
	vm := NewViewModel(client, nil)
	vm.setStatus(client.statusResult)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := vm.Toggle(context.Background()); err != nil {
			t.Errorf("Toggle() error = %v", err)
		}
	}()
	<-client.disconnectStart

	if got := vm.State(); got.StatusText != "正在关闭" || got.ButtonText != "正在关闭" || got.ButtonEnabled {
		t.Fatalf("disconnect busy state = %#v", got)
	}

	close(client.disconnectGate)
	<-done

	if client.disconnectCalls() != 1 {
		t.Fatalf("Disconnect() calls = %d, want 1", client.disconnectCalls())
	}
	if got := vm.State(); got.StatusText != "未连接" || got.ButtonText != "开启海外访问" || !got.ButtonEnabled {
		t.Fatalf("final state = %#v", got)
	}
}

func TestViewModelShowsDisconnectBusyStateAndThenError(t *testing.T) {
	client := &fakeServiceClient{
		statusResult:    clientapi.Status{State: accessmodel.StateConnected},
		disconnectErr:   clientapi.ErrServiceUnavailable,
		disconnectGate:  make(chan struct{}),
		disconnectStart: make(chan struct{}, 1),
	}
	vm := NewViewModel(client, nil)
	vm.setStatus(client.statusResult)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := vm.Toggle(context.Background()); err != nil {
			t.Errorf("Toggle() error = %v", err)
		}
	}()
	<-client.disconnectStart

	if got := vm.State(); got.StatusText != "正在关闭" || got.ButtonText != "正在关闭" || got.ButtonEnabled {
		t.Fatalf("disconnect busy state = %#v", got)
	}

	close(client.disconnectGate)
	<-done

	if got := vm.State(); got.StatusText != "连接失败" || got.DetailText != "无法连接海外访问服务器" || got.ButtonText != "安全重试" || !got.ButtonEnabled {
		t.Fatalf("final error state = %#v", got)
	}
}

func TestViewModelCloseLeavesServiceConnectionUnchanged(t *testing.T) {
	client := &fakeServiceClient{statusResult: clientapi.Status{State: accessmodel.StateConnected}}
	vm := NewViewModel(client, nil)
	vm.setStatus(client.statusResult)
	vm.Start()
	vm.Close()

	if calls := client.disconnectCalls(); calls != 0 {
		t.Fatalf("Disconnect() calls = %d, want 0", calls)
	}
}

func TestViewModelCopiesOnlyRedactedDiagnostics(t *testing.T) {
	clipboard := &fakeClipboard{}
	client := &fakeServiceClient{
		diagnosticsResult: clientapi.Diagnostics{
			State:      accessmodel.StateFailed,
			ErrorCode:  agent.ErrorCredential,
			Message:    "credential [REDACTED] unavailable",
			Generation: 7,
			Stage:      "firewall_publish",
			Detail:     "The specified interface was not found.",
		},
	}
	vm := NewViewModel(client, clipboard)

	if err := vm.CopyDiagnostics(context.Background()); err != nil {
		t.Fatalf("CopyDiagnostics() error = %v", err)
	}

	if got := clipboard.text(); got == "" || got != clientapi.FormatDiagnostics(client.diagnosticsResult) {
		t.Fatalf("clipboard text = %q", got)
	}
	if got := clipboard.text(); containsSecret(got) {
		t.Fatalf("clipboard leaked secret: %q", got)
	}
}

func TestViewModelRefreshTreatsMissingServiceAsDisconnected(t *testing.T) {
	client := &fakeServiceClient{statusErr: clientapi.ErrServiceUnavailable}
	vm := NewViewModel(client, nil)

	if err := vm.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if got := vm.State(); got.StatusText != "未连接" || got.DetailText != "" || got.ButtonText != "开启海外访问" {
		t.Fatalf("State() = %#v", got)
	}
}

type fakeServiceClient struct {
	mu                sync.Mutex
	statusResult      clientapi.Status
	statusErr         error
	connectResult     clientapi.Status
	connectErr        error
	disconnectResult  clientapi.Status
	disconnectErr     error
	diagnosticsResult clientapi.Diagnostics
	diagnosticsErr    error
	statusCount       int
	connectCount      int
	disconnectCount   int
	connectGate       chan struct{}
	started           chan struct{}
	disconnectGate    chan struct{}
	disconnectStart   chan struct{}
	traceBatches      []traceevent.Batch
	traceErr          error
	traceCount        int
	callLog           []string
}

func (f *fakeServiceClient) Status(context.Context) (clientapi.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusCount++
	return f.statusResult, f.statusErr
}

func (f *fakeServiceClient) Connect(context.Context) (clientapi.Status, error) {
	f.mu.Lock()
	f.connectCount++
	f.callLog = append(f.callLog, "connect")
	gate := f.connectGate
	started := f.started
	result := f.connectResult
	err := f.connectErr
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	return result, err
}

func (f *fakeServiceClient) Disconnect(context.Context) (clientapi.Status, error) {
	f.mu.Lock()
	f.disconnectCount++
	f.callLog = append(f.callLog, "disconnect")
	gate := f.disconnectGate
	started := f.disconnectStart
	result := f.disconnectResult
	err := f.disconnectErr
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	return result, err
}

func (f *fakeServiceClient) Diagnostics(context.Context) (clientapi.Diagnostics, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callLog = append(f.callLog, "diagnostics")
	return f.diagnosticsResult, f.diagnosticsErr
}

func (f *fakeServiceClient) Trace(_ context.Context, _ uint64, _ int) (traceevent.Batch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.traceCount++
	f.callLog = append(f.callLog, "trace")
	if f.traceErr != nil {
		return traceevent.Batch{}, f.traceErr
	}
	if len(f.traceBatches) == 0 {
		return traceevent.Batch{}, nil
	}
	batch := f.traceBatches[0]
	if len(f.traceBatches) > 1 {
		f.traceBatches = f.traceBatches[1:]
	}
	return batch, nil
}

func (f *fakeServiceClient) connectCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connectCount
}

func (f *fakeServiceClient) disconnectCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disconnectCount
}

func (f *fakeServiceClient) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.callLog...)
}

type fakeClipboard struct {
	mu      sync.Mutex
	writes  int
	content string
}

func (f *fakeClipboard) SetText(value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	f.content = value
	return nil
}

func (f *fakeClipboard) text() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.content
}

func containsSecret(value string) bool {
	return strings.Contains(value, "topsecret") || strings.Contains(value, `"config"`)
}

func TestViewModelStartPollsWhileVisible(t *testing.T) {
	client := &fakeServiceClient{statusResult: clientapi.Status{State: accessmodel.StateDisconnected}}
	vm := NewViewModel(client, nil, WithPollInterval(10*time.Millisecond))
	vm.Start()
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		count := client.statusCount
		client.mu.Unlock()
		if count >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	vm.Close()

	client.mu.Lock()
	count := client.statusCount
	client.mu.Unlock()
	if count < 2 {
		t.Fatalf("Status() calls = %d, want at least 2 polls", count)
	}
}

func TestViewModelTracePollContinuesWhileConnectIsBusy(t *testing.T) {
	event := viewTraceEvent(1, 1, traceevent.StageFirewallPublish, traceevent.EventStarted, nil)
	client := &fakeServiceClient{
		statusResult:  clientapi.Status{State: accessmodel.StateDisconnected},
		connectResult: clientapi.Status{State: accessmodel.StateConnected},
		connectGate:   make(chan struct{}), started: make(chan struct{}, 1),
		traceBatches: []traceevent.Batch{{Events: []traceevent.Event{event}, NextSequence: 1, OldestSequence: 1}},
	}
	vm := NewViewModel(client, nil, WithPollInterval(time.Hour), WithTraceInterval(10*time.Millisecond))
	vm.setStatus(client.statusResult)
	vm.Start()
	defer vm.Close()
	done := make(chan struct{})
	go func() { _ = vm.Toggle(context.Background()); close(done) }()
	<-client.started
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && !strings.Contains(vm.State().LogText, "firewall_publish") {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(vm.State().LogText, "firewall_publish") {
		t.Fatalf("trace did not update while busy: %#v", vm.State())
	}
	close(client.connectGate)
	<-done
}

func TestViewModelSafeRetryRestoresAndProvesZeroResidueBeforeConnect(t *testing.T) {
	zero := traceevent.Residue{}
	event := viewTraceEvent(12, 4, traceevent.StageResidueVerify, traceevent.EventSucceeded, &zero)
	client := &fakeServiceClient{
		statusResult:      clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorPublicTCPBlock},
		disconnectResult:  clientapi.Status{State: accessmodel.StateDisconnected},
		diagnosticsResult: clientapi.Diagnostics{State: accessmodel.StateDisconnected, Generation: 4},
		connectResult:     clientapi.Status{State: accessmodel.StateConnected},
		traceBatches:      []traceevent.Batch{{Events: []traceevent.Event{event}, NextSequence: 12, OldestSequence: 12}},
	}
	vm := NewViewModel(client, nil, WithTraceInterval(time.Millisecond))
	vm.setStatus(client.statusResult)
	if err := vm.Toggle(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := client.calls()
	if indexOf(calls, "disconnect") >= indexOf(calls, "diagnostics") || indexOf(calls, "diagnostics") >= indexOf(calls, "trace") || indexOf(calls, "trace") >= indexOf(calls, "connect") {
		t.Fatalf("safe retry order = %v", calls)
	}
	if vm.State().StatusText != "已连接" {
		t.Fatalf("state = %#v", vm.State())
	}
}

func TestViewModelSafeRetryStopsOnNonzeroResidue(t *testing.T) {
	residue := traceevent.Residue{ManagedRules: 1}
	event := viewTraceEvent(9, 2, traceevent.StageResidueVerify, traceevent.EventFailed, &residue)
	client := &fakeServiceClient{
		statusResult:      clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorPublicTCPBlock},
		disconnectResult:  clientapi.Status{State: accessmodel.StateDisconnected},
		diagnosticsResult: clientapi.Diagnostics{State: accessmodel.StateDisconnected, Generation: 2},
		traceBatches:      []traceevent.Batch{{Events: []traceevent.Event{event}, NextSequence: 9, OldestSequence: 9}},
	}
	vm := NewViewModel(client, nil, WithTraceInterval(time.Millisecond))
	vm.setStatus(client.statusResult)
	if err := vm.Toggle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.connectCalls() != 0 || vm.State().PrimaryEnabled {
		t.Fatalf("unsafe retry state=%#v calls=%v", vm.State(), client.calls())
	}
}

func TestViewModelRestoreNeverReconnects(t *testing.T) {
	client := &fakeServiceClient{
		statusResult:     clientapi.Status{State: accessmodel.StateFailed},
		disconnectResult: clientapi.Status{State: accessmodel.StateDisconnected},
	}
	vm := NewViewModel(client, nil)
	vm.setStatus(client.statusResult)
	if err := vm.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.disconnectCalls() != 1 || client.connectCalls() != 0 {
		t.Fatalf("calls = %v", client.calls())
	}
}

func TestViewModelCopyLogsUsesLocalEventsWithoutDiagnosticsCall(t *testing.T) {
	clipboard := &fakeClipboard{}
	client := &fakeServiceClient{traceBatches: []traceevent.Batch{{Events: []traceevent.Event{viewTraceEvent(1, 8, traceevent.StageFirewallPublish, traceevent.EventFailed, nil)}, NextSequence: 1, OldestSequence: 1}}}
	vm := NewViewModel(client, clipboard)
	if err := vm.RefreshTrace(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := vm.CopyLogs(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clipboard.text(), "Generation 8") || indexOf(client.calls(), "diagnostics") >= 0 {
		t.Fatalf("clipboard=%q calls=%v", clipboard.text(), client.calls())
	}
}

func viewTraceEvent(sequence, generation uint64, stage, event string, residue *traceevent.Residue) traceevent.Event {
	return traceevent.Event{
		SchemaVersion: traceevent.SchemaVersion, Sequence: sequence,
		TimestampUTC: time.Date(2026, 9, 1, 8, 0, int(sequence%60), 0, time.UTC),
		Generation:   generation, Level: traceevent.LevelInfo, Component: traceevent.ComponentNetwork,
		Stage: stage, Event: event, Message: "test event", Residue: residue,
	}
}

func indexOf(values []string, want string) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return -1
}
