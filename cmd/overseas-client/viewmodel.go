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
		status:    clientapi.Status{State: accessmodel.StateDisconnected},
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
	if v.busy || v.status.State == accessmodel.StateConnecting || (v.status.State == accessmodel.StateFailed && v.retryBlocked) {
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
	case accessmodel.StateFailed:
		v.busyAction = busyActionRetry
	default:
		v.busyAction = busyActionConnect
	}
	state := v.renderLocked()
	v.mu.Unlock()
	v.notify(state)

	var next clientapi.Status
	var err error
	switch current.State {
	case accessmodel.StateConnected:
		next, err = v.client.Disconnect(ctx)
	case accessmodel.StateFailed:
		next, err = v.safeRetry(ctx)
	default:
		next, err = v.client.Connect(ctx)
	}
	if err != nil {
		if errors.Is(err, errResidueProof) {
			v.update(clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorRestoreFailed}, false, true)
			return nil
		}
		next = statusForClientError(err)
	}
	v.update(next, false, false)
	return nil
}

func (v *ViewModel) safeRetry(ctx context.Context) (clientapi.Status, error) {
	restored, err := v.client.Disconnect(ctx)
	if err != nil {
		return clientapi.Status{}, err
	}
	if restored.State != accessmodel.StateDisconnected {
		return clientapi.Status{}, errResidueProof
	}
	diagnostics, err := v.client.Diagnostics(ctx)
	if err != nil || diagnostics.State != accessmodel.StateDisconnected {
		return clientapi.Status{}, errResidueProof
	}
	if err := v.waitForZeroResidue(ctx, diagnostics.Generation); err != nil {
		return clientapi.Status{}, errResidueProof
	}
	return v.client.Connect(ctx)
}

func (v *ViewModel) waitForZeroResidue(ctx context.Context, generation uint64) error {
	proofContext, cancel := context.WithTimeout(ctx, safeRetryProofTimeout)
	defer cancel()
	for {
		if found, zero := v.residueProof(generation); found {
			if zero {
				return nil
			}
			return errResidueProof
		}
		if err := v.RefreshTrace(proofContext); err != nil {
			return err
		}
		if found, zero := v.residueProof(generation); found {
			if zero {
				return nil
			}
			return errResidueProof
		}
		timer := time.NewTimer(v.traceInterval)
		select {
		case <-proofContext.Done():
			timer.Stop()
			return proofContext.Err()
		case <-timer.C:
		}
	}
}

func (v *ViewModel) residueProof(generation uint64) (found, zero bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for index := len(v.traceEvents) - 1; index >= 0; index-- {
		event := v.traceEvents[index]
		if event.Generation != generation || event.Stage != traceevent.StageResidueVerify || event.Residue == nil {
			continue
		}
		if event.Event != traceevent.EventSucceeded && event.Event != traceevent.EventFailed {
			continue
		}
		return true, event.Event == traceevent.EventSucceeded && event.Residue.IsZero()
	}
	return false, false
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
	v.update(status, false, status.State != accessmodel.StateDisconnected)
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
		case busyActionRetry:
			state.StatusText, state.PrimaryButtonText = "正在安全重试", "正在安全重试"
		default:
			state.StatusText, state.PrimaryButtonText = "正在连接", "正在连接"
		}
		return withCompatibility(state)
	}
	if v.status.State == accessmodel.StateConnecting {
		state.StatusText, state.PrimaryButtonText = "正在连接", "正在连接"
		return withCompatibility(state)
	}
	switch v.status.State {
	case accessmodel.StateConnected:
		state.StatusText = "已连接"
		state.PrimaryButtonText = "关闭海外访问"
		state.PrimaryEnabled = true
		state.RestoreEnabled = true
	case accessmodel.StateFailed:
		state.StatusText = "连接失败"
		state.DetailText = approvedMessage(v.status)
		state.PrimaryButtonText = "安全重试"
		state.PrimaryEnabled = !v.retryBlocked
		state.RestoreEnabled = true
	default:
		state.StatusText = "未连接"
		state.PrimaryButtonText = "开启海外访问"
		state.PrimaryEnabled = true
	}
	return withCompatibility(state)
}

func withCompatibility(state ViewState) ViewState {
	state.ButtonText = state.PrimaryButtonText
	state.ButtonEnabled = state.PrimaryEnabled
	return state
}

const (
	busyActionConnect    = "connect"
	busyActionDisconnect = "disconnect"
	busyActionRetry      = "retry"
	busyActionRestore    = "restore"
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
	default:
		return "无法连接海外访问服务器"
	}
}

func statusForClientError(err error) clientapi.Status {
	if errors.Is(err, clientapi.ErrServiceUnavailable) {
		return clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorCoreNotReady}
	}
	return clientapi.Status{State: accessmodel.StateFailed, ErrorCode: agent.ErrorInvalidBinary}
}
