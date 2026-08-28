package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/clientapi"
)

type serviceClient interface {
	Connect(context.Context) (clientapi.Status, error)
	Disconnect(context.Context) (clientapi.Status, error)
	Status(context.Context) (clientapi.Status, error)
	Diagnostics(context.Context) (clientapi.Diagnostics, error)
}

type clipboard interface {
	SetText(string) error
}

type ViewState struct {
	StatusText    string
	DetailText    string
	ButtonText    string
	ButtonEnabled bool
}

type ViewModelOption func(*ViewModel)

type ViewModel struct {
	client       serviceClient
	clipboard    clipboard
	pollInterval time.Duration

	mu         sync.Mutex
	status     clientapi.Status
	busy       bool
	busyAction string
	onChange   func(ViewState)
	startOnce  sync.Once
	closeOnce  sync.Once
	closePoll  chan struct{}
}

func NewViewModel(client serviceClient, clipboard clipboard, options ...ViewModelOption) *ViewModel {
	vm := &ViewModel{
		client:       client,
		clipboard:    clipboard,
		pollInterval: 2 * time.Second,
		status:       clientapi.Status{State: accessmodel.StateDisconnected},
		closePoll:    make(chan struct{}),
	}
	for _, option := range options {
		option(vm)
	}
	return vm
}

func WithPollInterval(interval time.Duration) ViewModelOption {
	return func(vm *ViewModel) {
		if interval > 0 {
			vm.pollInterval = interval
		}
	}
}

func (v *ViewModel) SetOnChange(handler func(ViewState)) {
	v.mu.Lock()
	v.onChange = handler
	state := v.renderLocked()
	v.mu.Unlock()
	v.notify(state)
}

func (v *ViewModel) State() ViewState {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.renderLocked()
}

func (v *ViewModel) Start() {
	v.startOnce.Do(func() {
		go v.poll()
	})
}

func (v *ViewModel) Close() {
	v.closeOnce.Do(func() {
		close(v.closePoll)
	})
}

func (v *ViewModel) Refresh(ctx context.Context) error {
	if v.isBusy() {
		return nil
	}
	status, err := v.client.Status(ctx)
	if err != nil {
		if errors.Is(err, clientapi.ErrServiceUnavailable) {
			v.update(clientapi.Status{State: accessmodel.StateDisconnected}, false)
			return nil
		}
		v.update(clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorInvalidBinary}, false)
		return nil
	}
	v.update(status, false)
	return nil
}

func (v *ViewModel) Toggle(ctx context.Context) error {
	v.mu.Lock()
	if v.busy || v.status.State == accessmodel.StateConnecting {
		state := v.renderLocked()
		v.mu.Unlock()
		v.notify(state)
		return nil
	}
	current := v.status
	v.busy = true
	v.busyAction = busyActionConnect
	if current.State == accessmodel.StateConnected {
		v.busyAction = busyActionDisconnect
	}
	state := v.renderLocked()
	v.mu.Unlock()
	v.notify(state)

	var (
		next clientapi.Status
		err  error
	)
	switch current.State {
	case accessmodel.StateConnected:
		next, err = v.client.Disconnect(ctx)
	default:
		next, err = v.client.Connect(ctx)
	}
	if err != nil {
		next = statusForClientError(err)
	}
	v.update(next, false)
	return nil
}

func (v *ViewModel) CopyDiagnostics(ctx context.Context) error {
	if v.clipboard == nil {
		return nil
	}
	diagnostics, err := v.client.Diagnostics(ctx)
	if err != nil {
		return err
	}
	return v.clipboard.SetText(clientapi.FormatDiagnostics(diagnostics))
}

func (v *ViewModel) setStatus(status clientapi.Status) {
	v.update(status, v.isBusy())
}

func (v *ViewModel) isBusy() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.busy
}

func (v *ViewModel) poll() {
	_ = v.Refresh(context.Background())
	ticker := time.NewTicker(v.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = v.Refresh(context.Background())
		case <-v.closePoll:
			return
		}
	}
}

func (v *ViewModel) update(status clientapi.Status, busy bool) {
	v.mu.Lock()
	v.status = status
	v.busy = busy
	if !busy {
		v.busyAction = ""
	}
	state := v.renderLocked()
	v.mu.Unlock()
	v.notify(state)
}

func (v *ViewModel) notify(state ViewState) {
	v.mu.Lock()
	handler := v.onChange
	v.mu.Unlock()
	if handler != nil {
		handler(state)
	}
}

func (v *ViewModel) renderLocked() ViewState {
	if v.busy {
		if v.busyAction == busyActionDisconnect {
			return ViewState{
				StatusText:    "正在关闭",
				DetailText:    "",
				ButtonText:    "正在关闭",
				ButtonEnabled: false,
			}
		}
		return ViewState{
			StatusText:    "正在连接",
			DetailText:    "",
			ButtonText:    "正在连接",
			ButtonEnabled: false,
		}
	}
	if v.status.State == accessmodel.StateConnecting {
		return ViewState{
			StatusText:    "正在连接",
			DetailText:    "",
			ButtonText:    "正在连接",
			ButtonEnabled: false,
		}
	}
	switch v.status.State {
	case accessmodel.StateConnected:
		return ViewState{
			StatusText:    "已连接",
			DetailText:    "",
			ButtonText:    "关闭海外访问",
			ButtonEnabled: true,
		}
	case accessmodel.StateFailed:
		return ViewState{
			StatusText:    "连接失败",
			DetailText:    approvedMessage(v.status),
			ButtonText:    "重试",
			ButtonEnabled: true,
		}
	default:
		return ViewState{
			StatusText:    "未连接",
			DetailText:    "",
			ButtonText:    "开启海外访问",
			ButtonEnabled: true,
		}
	}
}

const (
	busyActionConnect    = "connect"
	busyActionDisconnect = "disconnect"
)

func approvedMessage(status clientapi.Status) string {
	switch status.ErrorCode {
	case clientapi.ErrorUnauthorized:
		return "当前账号未获授权"
	case agent.ErrorReadinessLost:
		return "运营商线路未登录或已失效，请联系 IT"
	case agent.ErrorNetworkCapture, agent.ErrorPublicTCPBlock, agent.ErrorRouteActivationFailed, agent.ErrorRestoreFailed:
		return "本机安全网络配置失败，请联系 IT"
	case agent.ErrorInvalidPolicy, agent.ErrorInvalidBinary, agent.ErrorCredential, agent.ErrorExpiredCredential, agent.ErrorRender:
		return "客户端配置需要修复，请联系 IT"
	case agent.ErrorCoreStart, agent.ErrorCoreNotReady, agent.ErrorCanceled:
		return "无法连接海外访问服务器"
	default:
		if status.Message != "" {
			return "无法连接海外访问服务器"
		}
		return "无法连接海外访问服务器"
	}
}

func statusForClientError(err error) clientapi.Status {
	if errors.Is(err, clientapi.ErrServiceUnavailable) {
		return clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorCoreNotReady}
	}
	return clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorInvalidBinary}
}
