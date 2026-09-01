// Package agent coordinates the fail-closed overseas access lifecycle.
package agent

import (
	"context"
	"errors"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
)

const (
	ErrorInvalidPolicy         = "invalid_policy"
	ErrorInvalidBinary         = "invalid_binary"
	ErrorCredential            = "credential_unavailable"
	ErrorExpiredCredential     = "credential_expired"
	ErrorNetworkCapture        = "network_capture_failed"
	ErrorPublicTCPBlock        = "public_tcp_block_failed"
	ErrorRender                = "config_render_failed"
	ErrorCoreStart             = "core_start_failed"
	ErrorCoreNotReady          = "core_not_ready"
	ErrorRouteActivationFailed = "route_activation_failed"
	ErrorReadinessLost         = "readiness_lost"
	ErrorRestoreFailed         = "restore_failed"
	ErrorCanceled              = "canceled"
)

type Status struct {
	State     accessmodel.ConnectionState `json:"state"`
	ErrorCode string                      `json:"error_code,omitempty"`
	Message   string                      `json:"message,omitempty"`
}

type Diagnostics struct {
	State      accessmodel.ConnectionState `json:"state"`
	ErrorCode  string                      `json:"error_code,omitempty"`
	Message    string                      `json:"message,omitempty"`
	Generation uint64                      `json:"generation"`
	Stage      string                      `json:"stage,omitempty"`
	Detail     string                      `json:"detail,omitempty"`
}

type stagedDiagnosticError interface {
	error
	DiagnosticStage() string
	DiagnosticDetail() string
}

// Credential is the decrypted, short-lived material consumed by the renderer.
// Password is cleared by Controller immediately after rendering or on failure.
type Credential struct {
	Method    string
	Password  []byte
	ExpiresAt time.Time
}

// NetworkManager owns all operating-system network mutations. Implementations
// must make block, restore, and reconcile idempotent and persist enough state to
// reconcile residue after a service restart.
type NetworkManager interface {
	Capture(context.Context) (any, error)
	InstallPublicTCPBlock(context.Context) (<-chan error, error)
	WaitTUNReady(context.Context) error
	ActivateTUNRoutes(context.Context) error
	Restore(context.Context, any) error
	Reconcile(context.Context) error
}

// ProcessStartResult distinguishes a failure before/after native creation.
// TerminationProven means no process from this Start can still be running.
type ProcessStartResult struct {
	Err               error
	TerminationProven bool
}

// ProcessTermination reports process outcome separately from proof that the
// supervised job tree is empty. Exit errors do not invalidate positive proof.
type ProcessTermination struct {
	Err    error
	Proven bool
}

// ProcessInstance is immutable generation-owned state. Done must belong only
// to this native process tree and deliver exactly one terminal result.
type ProcessInstance interface {
	Ready(context.Context) error
	Stop(context.Context) ProcessTermination
	Done() <-chan ProcessTermination
}

// ProcessSupervisor allocates a fresh single-use instance for every Start.
// It returns the instance even when a post-creation cleanup error occurred so
// the controller can retry termination without permitting another launch.
type ProcessSupervisor interface {
	Start(context.Context, string, string) (ProcessInstance, ProcessStartResult)
}

// Dependencies are explicit so tests never need to touch the filesystem,
// DPAPI, executable verification, or live network state.
type Dependencies struct {
	ExecutablePath    string
	ConfigPath        string
	ValidatePolicy    func(accessmodel.Policy) error
	VerifyExecutable  func(string) error
	LoadCredential    func(context.Context, accessmodel.CredentialRef) (Credential, error)
	RenderConfig      func(accessmodel.Policy, Credential) ([]byte, error)
	WriteConfigAtomic func(string, []byte) error
	Now               func() time.Time
}

type Option func(*Dependencies)

func WithDependencies(dependencies Dependencies) Option {
	return func(target *Dependencies) { *target = dependencies }
}

type transition struct {
	kind   string
	done   chan struct{}
	cancel context.CancelFunc
}

type Controller struct {
	policy  accessmodel.Policy
	network NetworkManager
	process ProcessSupervisor
	deps    Dependencies

	mu               sync.Mutex
	status           Status
	generation       uint64
	transition       *transition
	snapshot         any
	hasSnapshot      bool
	processStarted   bool
	processInstance  ProcessInstance
	monitorCancel    context.CancelFunc
	monitorDone      chan struct{}
	reconciled       bool
	diagnosticStage  string
	diagnosticDetail string
}

func NewController(policy accessmodel.Policy, network NetworkManager, process ProcessSupervisor, options ...Option) *Controller {
	dependencies := Dependencies{
		ValidatePolicy: accessmodel.Validate,
		Now:            time.Now,
	}
	for _, option := range options {
		option(&dependencies)
	}
	if dependencies.ValidatePolicy == nil {
		dependencies.ValidatePolicy = accessmodel.Validate
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	return &Controller{
		policy:  clonePolicy(policy),
		network: network,
		process: process,
		deps:    dependencies,
		status:  Status{State: accessmodel.StateDisconnected},
	}
}

func (c *Controller) Connect(ctx context.Context) Status {
	for {
		c.mu.Lock()
		if c.status.State == accessmodel.StateConnected && c.transition == nil {
			status := c.status
			c.mu.Unlock()
			return status
		}
		if active := c.transition; active != nil {
			done := active.done
			kind := active.kind
			c.mu.Unlock()
			if kind == "connect" {
				return c.waitForTransition(ctx, done)
			}
			if !waitContext(ctx, done) {
				return canceledStatus(c.Status())
			}
			continue
		}

		c.generation++
		generation := c.generation
		operationContext, cancel := context.WithCancel(ctx)
		active := &transition{kind: "connect", done: make(chan struct{}), cancel: cancel}
		c.transition = active
		c.status = Status{State: accessmodel.StateConnecting, Message: "正在建立安全连接"}
		c.diagnosticStage = ""
		c.diagnosticDetail = ""
		c.mu.Unlock()

		status, instance, failures, started := c.runConnect(operationContext)
		cancel()

		c.mu.Lock()
		if c.generation == generation {
			c.status = status
			c.processStarted = started
			c.processInstance = instance
		}
		connected := status.State == accessmodel.StateConnected && c.generation == generation
		var monitorContext context.Context
		var monitorDone chan struct{}
		if connected {
			var monitorCancel context.CancelFunc
			monitorContext, monitorCancel = context.WithCancel(context.Background())
			monitorDone = make(chan struct{})
			c.monitorCancel = monitorCancel
			c.monitorDone = monitorDone
		}
		c.transition = nil
		close(active.done)
		c.mu.Unlock()
		if connected {
			go c.monitorLifecycle(monitorContext, generation, instance, failures, monitorDone)
		}
		return status
	}
}

func (c *Controller) Disconnect(ctx context.Context) Status {
	return c.disconnect(ctx, false)
}

// Recover reconciles state left by a previous service instance. It is safe to
// call repeatedly; only a failed reconciliation is retried.
func (c *Controller) Recover(ctx context.Context) Status {
	return c.disconnect(ctx, true)
}

func (c *Controller) disconnect(ctx context.Context, recovery bool) Status {
	for {
		c.mu.Lock()
		if active := c.transition; active != nil {
			done := active.done
			if active.kind == "connect" {
				active.cancel()
			}
			c.mu.Unlock()
			if !waitContext(ctx, done) {
				return canceledStatus(c.Status())
			}
			continue
		}
		if recovery && c.reconciled && !c.hasSnapshot && !c.processStarted {
			status := c.status
			c.mu.Unlock()
			return status
		}

		c.generation++
		generation := c.generation
		operationContext, cancel := context.WithCancel(ctx)
		active := &transition{kind: "disconnect", done: make(chan struct{}), cancel: cancel}
		c.transition = active
		c.mu.Unlock()

		status, restored := c.runDisconnect(operationContext)
		cancel()

		c.mu.Lock()
		if c.generation == generation {
			c.status = status
			if restored {
				c.snapshot = nil
				c.hasSnapshot = false
				c.processStarted = false
				c.processInstance = nil
				c.reconciled = true
			}
		}
		c.transition = nil
		close(active.done)
		c.mu.Unlock()
		return status
	}
}

func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *Controller) Diagnostics() Diagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Diagnostics{
		State:      c.status.State,
		ErrorCode:  c.status.ErrorCode,
		Message:    c.status.Message,
		Generation: c.generation,
		Stage:      c.diagnosticStage,
		Detail:     c.diagnosticDetail,
	}
}

func (c *Controller) recordDiagnostic(err error) {
	var diagnostic stagedDiagnosticError
	if !errors.As(err, &diagnostic) {
		return
	}
	if diagnostic.DiagnosticStage() == "" || diagnostic.DiagnosticDetail() == "" {
		return
	}
	c.mu.Lock()
	c.diagnosticStage = diagnostic.DiagnosticStage()
	c.diagnosticDetail = diagnostic.DiagnosticDetail()
	c.mu.Unlock()
}

func (c *Controller) runConnect(ctx context.Context) (Status, ProcessInstance, <-chan error, bool) {
	if err := contextError(ctx); err != nil {
		return failure(ErrorCanceled), nil, nil, false
	}
	c.mu.Lock()
	processMayStillBeRunning := c.processStarted
	previousInstance := c.processInstance
	c.mu.Unlock()
	if processMayStillBeRunning {
		return failure(ErrorRestoreFailed), previousInstance, nil, true
	}
	if err := c.deps.ValidatePolicy(c.policy); err != nil {
		return failure(ErrorInvalidPolicy), nil, nil, false
	}
	if c.deps.VerifyExecutable == nil || c.deps.ExecutablePath == "" {
		return failure(ErrorInvalidBinary), nil, nil, false
	}
	if err := c.deps.VerifyExecutable(c.deps.ExecutablePath); err != nil {
		return failure(ErrorInvalidBinary), nil, nil, false
	}
	credential := Credential{}
	if c.policy.SchemaVersion == 1 {
		if c.deps.LoadCredential == nil {
			return failure(ErrorCredential), nil, nil, false
		}
		var err error
		credential, err = c.deps.LoadCredential(ctx, c.policy.Credential)
		if err != nil {
			return failure(ErrorCredential), nil, nil, false
		}
		defer clearBytes(credential.Password)
		if credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(c.deps.Now()) {
			return failure(ErrorExpiredCredential), nil, nil, false
		}
	}
	if err := contextError(ctx); err != nil {
		return failure(ErrorCanceled), nil, nil, false
	}

	c.mu.Lock()
	hasSnapshot := c.hasSnapshot
	c.mu.Unlock()
	if !hasSnapshot {
		if c.network == nil {
			return failure(ErrorNetworkCapture), nil, nil, false
		}
		snapshot, err := c.network.Capture(ctx)
		if err != nil {
			c.recordDiagnostic(err)
			return failure(ErrorNetworkCapture), nil, nil, false
		}
		c.mu.Lock()
		c.snapshot = snapshot
		c.hasSnapshot = true
		c.mu.Unlock()
	}
	failures, err := c.network.InstallPublicTCPBlock(ctx)
	if err != nil {
		c.recordDiagnostic(err)
		return failure(ErrorPublicTCPBlock), nil, nil, false
	}
	if c.deps.RenderConfig == nil || c.deps.WriteConfigAtomic == nil || c.deps.ConfigPath == "" {
		return failure(ErrorRender), nil, failures, false
	}
	config, err := c.deps.RenderConfig(c.policy, credential)
	if err != nil {
		return failure(ErrorRender), nil, failures, false
	}
	defer clearBytes(config)
	if err := c.deps.WriteConfigAtomic(c.deps.ConfigPath, config); err != nil {
		return failure(ErrorRender), nil, failures, false
	}
	if err := contextError(ctx); err != nil {
		return failure(ErrorCanceled), nil, failures, false
	}
	if c.process == nil {
		return failure(ErrorCoreStart), nil, failures, false
	}
	// Start owns the core lifetime until Disconnect. The transition deadline
	// still bounds Ready below, but must not terminate a successfully connected
	// core when the connect operation itself returns.
	instance, startResult := c.process.Start(context.WithoutCancel(ctx), c.deps.ExecutablePath, c.deps.ConfigPath)
	if startResult.Err != nil {
		return failure(ErrorCoreStart), instance, failures, !startResult.TerminationProven
	}
	if instance == nil {
		return failure(ErrorCoreStart), nil, failures, false
	}
	started := true
	if err := instance.Ready(ctx); err != nil {
		unproven := !instance.Stop(context.Background()).Proven
		return failure(codeForContext(ctx, ErrorCoreNotReady)), instance, failures, unproven
	}
	if err := c.network.WaitTUNReady(ctx); err != nil {
		unproven := !instance.Stop(context.Background()).Proven
		return failure(codeForContext(ctx, ErrorCoreNotReady)), instance, failures, unproven
	}
	if err := contextError(ctx); err != nil {
		unproven := !instance.Stop(context.Background()).Proven
		return failure(ErrorCanceled), instance, failures, unproven
	}
	if err := c.network.ActivateTUNRoutes(ctx); err != nil {
		unproven := !instance.Stop(context.Background()).Proven
		return failure(ErrorRouteActivationFailed), instance, failures, unproven
	}
	return Status{State: accessmodel.StateConnected, Message: "海外访问已连接"}, instance, failures, started
}

func (c *Controller) runDisconnect(ctx context.Context) (Status, bool) {
	c.mu.Lock()
	started := c.processStarted
	instance := c.processInstance
	hasSnapshot := c.hasSnapshot
	snapshot := c.snapshot
	reconciled := c.reconciled
	c.mu.Unlock()
	c.stopLifecycleMonitor()

	if started && instance != nil {
		termination := instance.Stop(ctx)
		if !termination.Proven {
			// Restoring routes, DNS, or the leak block is unsafe until the whole
			// supervised process tree is proven terminated.
			return failure(ErrorRestoreFailed), false
		}
	}
	if hasSnapshot {
		if c.network == nil || c.network.Restore(ctx, snapshot) != nil {
			return failure(ErrorRestoreFailed), false
		}
	} else if !reconciled {
		if c.network == nil || c.network.Reconcile(ctx) != nil {
			return failure(ErrorRestoreFailed), false
		}
	}
	return Status{State: accessmodel.StateDisconnected, Message: "海外访问已关闭"}, true
}

func (c *Controller) stopLifecycleMonitor() {
	c.mu.Lock()
	cancel, done := c.monitorCancel, c.monitorDone
	c.monitorCancel, c.monitorDone = nil, nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (c *Controller) monitorLifecycle(ctx context.Context, generation uint64, instance ProcessInstance, failures <-chan error, done chan struct{}) {
	defer close(done)
	var termination ProcessTermination
	select {
	case termination = <-instance.Done():
	case <-failures:
		termination = instance.Stop(context.Background())
	case <-ctx.Done():
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation || c.status.State != accessmodel.StateConnected {
		return
	}
	c.status = failure(ErrorReadinessLost)
	if termination.Proven {
		c.processStarted = false
	}
}

func (c *Controller) waitForTransition(ctx context.Context, done <-chan struct{}) Status {
	if !waitContext(ctx, done) {
		return canceledStatus(c.Status())
	}
	return c.Status()
}

func waitContext(ctx context.Context, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

func failure(code string) Status {
	messages := map[string]string{
		ErrorInvalidPolicy:         "客户端策略无效",
		ErrorInvalidBinary:         "客户端核心验证失败",
		ErrorCredential:            "访问凭据不可用",
		ErrorExpiredCredential:     "访问凭据已过期",
		ErrorNetworkCapture:        "无法保存当前网络状态",
		ErrorPublicTCPBlock:        "无法建立防泄漏保护",
		ErrorRender:                "无法生成受控配置",
		ErrorCoreStart:             "无法启动访问核心",
		ErrorCoreNotReady:          "访问服务器不可用",
		ErrorRouteActivationFailed: "无法启用安全路由",
		ErrorReadinessLost:         "安全连接已中断",
		ErrorRestoreFailed:         "无法完整恢复网络状态",
		ErrorCanceled:              "操作已取消",
	}
	return Status{State: accessmodel.StateFailed, ErrorCode: code, Message: messages[code]}
}

func canceledStatus(current Status) Status {
	status := failure(ErrorCanceled)
	status.State = current.State
	return status
}

func codeForContext(ctx context.Context, fallback string) string {
	if ctx.Err() != nil {
		return ErrorCanceled
	}
	return fallback
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func clearBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func clonePolicy(policy accessmodel.Policy) accessmodel.Policy {
	copy := policy
	copy.Nodes = append([]accessmodel.Node(nil), policy.Nodes...)
	copy.CorporateCIDRs = append([]string(nil), policy.CorporateCIDRs...)
	copy.CorporateDNS = append([]string(nil), policy.CorporateDNS...)
	copy.InternalSuffixes = append([]string(nil), policy.InternalSuffixes...)
	return copy
}
