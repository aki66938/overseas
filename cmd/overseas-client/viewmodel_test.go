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
				ButtonText:    "重试",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed upstream unavailable",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorCoreNotReady},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "无法连接海外访问服务器",
				ButtonText:    "重试",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed carrier session lost",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorReadinessLost},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "运营商线路未登录或已失效，请联系 IT",
				ButtonText:    "重试",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed local configuration",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorNetworkCapture},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "本机安全网络配置失败，请联系 IT",
				ButtonText:    "重试",
				ButtonEnabled: true,
			},
		},
		{
			name:   "failed unauthorized",
			status: clientapi.Status{State: accessmodel.StateFailed, ErrorCode: clientapi.ErrorUnauthorized},
			want: ViewState{
				StatusText:    "连接失败",
				DetailText:    "当前账号未获授权",
				ButtonText:    "重试",
				ButtonEnabled: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vm := NewViewModel(&fakeServiceClient{statusResult: test.status}, nil)
			vm.setStatus(test.status)
			if got := vm.State(); got != test.want {
				t.Fatalf("State() = %#v, want %#v", got, test.want)
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
	defer f.mu.Unlock()
	f.disconnectCount++
	return f.disconnectResult, f.disconnectErr
}

func (f *fakeServiceClient) Diagnostics(context.Context) (clientapi.Diagnostics, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.diagnosticsResult, f.diagnosticsErr
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
