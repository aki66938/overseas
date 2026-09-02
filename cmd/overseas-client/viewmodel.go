package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/clientapi"
	"corp.example/overseas-access-gateway/internal/traceevent"
)

const (
	defaultTraceInterval  = 500 * time.Millisecond
	traceBatchLimit       = 32
	maxTimelineEvents     = 2048
	safeRetryProofTimeout = 10 * time.Second
)

var errResidueProof = errors.New("zero-residue proof is unavailable")

type serviceClient interface {
	Connect(context.Context) (clientapi.Status, error)
	Disconnect(context.Context) (clientapi.Status, error)
	Status(context.Context) (clientapi.Status, error)
	Diagnostics(context.Context) (clientapi.Diagnostics, error)
	Trace(context.Context, uint64, int) (traceevent.Batch, error)
}

type clipboard interface {
	SetText(string) error
}

type ViewState struct {
	StatusText        string
	DetailText        string
	GenerationText    string
	StageText         string
	ProtectionText    string
	LogText           string
	PrimaryButtonText string
	PrimaryEnabled    bool
	RestoreEnabled    bool
	CopyEnabled       bool
	ButtonText        string
	ButtonEnabled     bool
}

type ViewModelOption func(*ViewModel)

type ViewModel struct {
	client        serviceClient
	clipboard     clipboard
	pollInterval  time.Duration
	traceInterval time.Duration

	mu           sync.Mutex
	status       clientapi.Status
	busy         bool
	busyAction   string
	retryBlocked bool
	traceCursor  uint64
	traceEvents  []traceevent.Event
	traceGap     bool
	traceWarning bool
	onChange     func(ViewState)
	startOnce    sync.Once
	closeOnce    sync.Once
	closePoll    chan struct{}
	pollers      sync.WaitGroup
}

func NewViewModel(client serviceClient, clipboard clipboard, options ...ViewModelOption) *ViewModel {
	vm := &ViewModel{
		client: client, clipboard: clipboard,
		pollInterval: 2 * time.Second, traceInterval: defaultTraceInterval,
		status:    clientapi.Status{State: accessmodel.StatePrepared},
		closePoll: make(chan struct{}),
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

func WithTraceInterval(interval time.Duration) ViewModelOption {
	return func(vm *ViewModel) {
		if interval > 0 {
			vm.traceInterval = interval
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
		v.pollers.Add(2)
		go v.pollStatus()
		go v.pollTrace()
	})
}

func (v *ViewModel) Close() {
	v.closeOnce.Do(func() { close(v.closePoll) })
	v.pollers.Wait()
}

func (v *ViewModel) Refresh(ctx context.Context) error {
	if v.isBusy() {
		return nil
	}
	status, err := v.client.Status(ctx)
	if err != nil {
		if errors.Is(err, clientapi.ErrServiceUnavailable) {
			v.update(clientapi.Status{State: accessmodel.StateDisconnected}, false, false)
			return nil
		}
		v.update(clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorInvalidBinary}, false, false)
		return nil
	}
	v.update(status, false, false)
	return nil
}

func (v *ViewModel) RefreshTrace(ctx context.Context) error {
	v.mu.Lock()
	after := v.traceCursor
	v.mu.Unlock()
	batch, err := v.client.Trace(ctx, after, traceBatchLimit)
	if err != nil {
		v.mu.Lock()
		v.traceWarning = true
		state := v.renderLocked()
		v.mu.Unlock()
		v.notify(state)
		return err
	}
	v.mu.Lock()
	if batch.OldestSequence > 0 && batch.OldestSequence > after+1 {
		v.traceGap = true
	}
	for _, event := range batch.Events {
		if event.Sequence <= v.traceCursor {
			continue
		}
		v.traceEvents = append(v.traceEvents, event)
		v.traceCursor = event.Sequence
	}
	if batch.NextSequence > v.traceCursor {
		v.traceCursor = batch.NextSequence
	}
	if len(v.traceEvents) > maxTimelineEvents {
		v.traceEvents = append([]traceevent.Event(nil), v.traceEvents[len(v.traceEvents)-maxTimelineEvents:]...)
		v.traceGap = true
	}
	v.traceWarning = false
	state := v.renderLocked()
	v.mu.Unlock()
	v.notify(state)
	return nil
}

func (v *ViewModel) Toggle(ctx context.Context) error {
	v.mu.Lock()
	if v.busy || stateBlocksToggle(v.status.State) {
		state := v.renderLocked()
		v.mu.Unlock()
		v.notify(state)
		return nil
	}
	current := v.status
	v.busy = true
	switch current.State {
	case accessmodel.StateConnected:
		v.busyAction = busyActionDisconnect
	default:
		// A prepared response may carry the last failure code; the v18
		// connect transaction restores by itself, so retry needs no
		// preliminary disconnect.
		v.busyAction = busyActionConnect
	}
	state := v.renderLocked()
	v.mu.Unlock()
	v.notify(state)

	var next clientapi.Status
	var err error
	if current.State == accessmodel.StateConnected {
		next, err = v.client.Disconnect(ctx)
	} else {
		next, err = v.client.Connect(ctx)
	}
	if err != nil {
		next = statusForClientError(err)
	}
	v.update(next, false, false)
	return nil
}

// stateBlocksToggle reports whether the primary button must refuse to start a
// new connect transaction in the given state.
func stateBlocksToggle(state accessmodel.ConnectionState) bool {
	switch state {
	case accessmodel.StateConnecting, accessmodel.StatePreparing, accessmodel.StateRestoring, accessmodel.StateFailedSafe:
		return true
	default:
		return false
	}
}

func (v *ViewModel) Restore(ctx context.Context) error {
	v.mu.Lock()
	if v.busy {
		v.mu.Unlock()
		return nil
	}
	v.busy = true
	v.busyAction = busyActionRestore
	state := v.renderLocked()
	v.mu.Unlock()
	v.notify(state)
	status, err := v.client.Disconnect(ctx)
	if err != nil {
		status = statusForClientError(err)
	}
	v.update(status, false, status.State == accessmodel.StateFailedSafe)
	return nil
}

func (v *ViewModel) CopyLogs() error {
	if v.clipboard == nil {
		return nil
	}
	v.mu.Lock()
	generation := latestGeneration(v.traceEvents)
	events := make([]traceevent.Event, 0)
	for _, event := range v.traceEvents {
		if event.Generation == generation {
			events = append(events, event)
		}
	}
	state := v.renderLocked()
	contents := fmt.Sprintf("状态：%s\r\n保护：%s\r\n%s", state.StatusText, state.ProtectionText, formatTraceTimeline(events, false, v.traceWarning, time.Local))
	v.mu.Unlock()
	return v.clipboard.SetText(contents)
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
	v.update(status, v.isBusy(), false)
}

func (v *ViewModel) isBusy() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.busy
}

func (v *ViewModel) pollStatus() {
	defer v.pollers.Done()
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

func (v *ViewModel) pollTrace() {
	defer v.pollers.Done()
	_ = v.RefreshTrace(context.Background())
	ticker := time.NewTicker(v.traceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = v.RefreshTrace(context.Background())
		case <-v.closePoll:
			return
		}
	}
}

func (v *ViewModel) update(status clientapi.Status, busy, retryBlocked bool) {
	v.mu.Lock()
	v.status = status
	v.busy = busy
	v.retryBlocked = retryBlocked
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
	state := ViewState{
		GenerationText: generationSummary(v.traceEvents),
		StageText:      stageSummary(v.traceEvents),
		ProtectionText: protectionSummary(v.traceEvents, v.status),
		LogText:        formatTraceTimeline(v.traceEvents, v.traceGap, v.traceWarning, time.Local),
		CopyEnabled:    len(v.traceEvents) != 0,
	}
	if v.busy {
		switch v.busyAction {
		case busyActionDisconnect:
			state.StatusText, state.PrimaryButtonText = "正在关闭", "正在关闭"
		case busyActionRestore:
			state.StatusText, state.PrimaryButtonText = "正在恢复", "正在恢复"
		default:
			state.StatusText, state.PrimaryButtonText = connectionPhaseText(v.status), "正在连接"
		}
		return withCompatibility(state)
	}
	switch v.status.State {
	case accessmodel.StateConnecting:
		state.StatusText = connectionPhaseText(v.status)
		state.PrimaryButtonText = "正在连接"
		return withCompatibility(state)
	case accessmodel.StatePreparing:
		state.StatusText = "正在准备网络保护配置"
		state.PrimaryButtonText = "正在准备网络保护配置"
		return withCompatibility(state)
	case accessmodel.StateRestoring:
		state.StatusText = "正在恢复普通网络"
		state.PrimaryButtonText = "正在恢复普通网络"
		return withCompatibility(state)
	case accessmodel.StateConnected:
		state.StatusText = "已连接"
		state.PrimaryButtonText = "关闭海外访问"
		state.PrimaryEnabled = true
		state.RestoreEnabled = true
	case accessmodel.StateFailedSafe:
		state.StatusText = "已进入应急防护"
		state.DetailText = "自动恢复未能证明完成，应急防护已启用。请重启本机 RegenBio 服务或联系 IT 处理，期间不会发生公网直连。"
		state.PrimaryButtonText = "连接不可用"
		state.PrimaryEnabled = false
		state.RestoreEnabled = true
	case accessmodel.StatePrepared:
		state.StatusText = "未连接"
		state.DetailText = approvedMessage(v.status)
		state.PrimaryButtonText = "开启海外访问"
		state.PrimaryEnabled = true
		if v.status.ErrorCode != "" {
			state.PrimaryButtonText = "重试连接"
			state.RestoreEnabled = true
		}
	default:
		state.StatusText = "未连接"
		state.PrimaryButtonText = "开启海外访问"
		state.PrimaryEnabled = true
	}
	return withCompatibility(state)
}

// connectionPhaseText renders the six-step business header, for example
// "正在启用防泄漏保护 · 2.1 秒 · 第 2/6 步".
func connectionPhaseText(status clientapi.Status) string {
	names := map[string]string{
		agent.PhaseFingerprintSnapshot: "正在读取当前网络配置",
		agent.PhaseFirewall:            "正在启用防泄漏保护",
		agent.PhaseCore:                "正在启动访问核心",
		agent.PhaseTUN:                 "正在等待 TUN 网卡",
		agent.PhaseRouteDNS:            "正在切换 DNS 与安全路由",
		agent.PhaseConnected:           "已连接",
	}
	name, ok := names[status.Phase]
	if !ok || name == "" {
		name = "正在建立安全连接"
	}
	if status.Step > 0 && status.TotalSteps >= status.Step {
		return fmt.Sprintf("%s · %.1f 秒 · 第 %d/%d 步", name, float64(status.ElapsedMS)/1000.0, status.Step, status.TotalSteps)
	}
	return name
}

func withCompatibility(state ViewState) ViewState {
	state.ButtonText = state.PrimaryButtonText
	state.ButtonEnabled = state.PrimaryEnabled
	return state
}

const (
	busyActionConnect    = "connect"
	busyActionDisconnect = "disconnect"
	busyActionRestore    = "restore"
)

func approvedMessage(status clientapi.Status) string {
	if status.ErrorCode == "" {
		return ""
	}
	switch status.ErrorCode {
	case clientapi.ErrorUnauthorized:
		return "当前账号未获授权"
	case agent.ErrorReadinessLost:
		return "连接中断后已自动恢复普通网络，可重试"
	case agent.ErrorNetworkChanged:
		return "网络环境发生变化，已自动恢复，可重试"
	case agent.ErrorNetworkCapture, agent.ErrorPublicTCPBlock, agent.ErrorFirewallEnable, agent.ErrorFirewallVerify, agent.ErrorRouteActivationFailed, agent.ErrorRestoreFailed:
		return "本机安全网络配置失败，已自动恢复，可重试"
	case agent.ErrorTUNNotFound, agent.ErrorTUNIdentityMismatch:
		return "TUN 网卡创建异常，已自动恢复，可重试"
	case agent.ErrorPreparedUnavailable:
		return "网络保护配置暂不可用，请稍后重试或联系 IT"
	case agent.ErrorInvalidPolicy, agent.ErrorInvalidBinary, agent.ErrorCredential, agent.ErrorExpiredCredential, agent.ErrorRender:
		return "客户端配置需要修复，请联系 IT"
	case agent.ErrorCoreStart, agent.ErrorCoreNotReady:
		return "无法启动访问核心，已自动恢复，可重试"
	default:
		return "连接未成功，已自动恢复普通网络，可重试"
	}
}

func statusForClientError(err error) clientapi.Status {
	if errors.Is(err, clientapi.ErrServiceUnavailable) {
		return clientapi.Status{State: accessmodel.StatePrepared, ErrorCode: agent.ErrorCoreNotReady}
	}
	return clientapi.Status{State: accessmodel.StatePrepared, ErrorCode: agent.ErrorInvalidBinary}
}
