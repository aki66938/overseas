// Package agent coordinates the fail-closed overseas access lifecycle.
package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/traceevent"
)

const (
	ErrorInvalidPolicy         = "invalid_policy"
	ErrorInvalidBinary         = "invalid_binary"
	ErrorCredential            = "credential_unavailable"
	ErrorExpiredCredential     = "credential_expired"
	ErrorPreparedUnavailable   = "prepared_state_unavailable"
	ErrorNetworkChanged        = "network_changed"
	ErrorNetworkCapture        = "network_capture_failed"
	ErrorFirewallEnable        = "firewall_enable_failed"
	ErrorFirewallVerify        = "firewall_verify_failed"
	ErrorPublicTCPBlock        = "public_tcp_block_failed"
	ErrorRender                = "config_render_failed"
	ErrorCoreStart             = "core_start_failed"
	ErrorCoreNotReady          = "core_not_ready"
	ErrorTUNNotFound           = "tun_not_found"
	ErrorTUNIdentityMismatch   = "tun_identity_mismatch"
	ErrorRouteActivationFailed = "route_activation_failed"
	ErrorReadinessLost         = "readiness_lost"
	ErrorRestoreFailed         = "restore_failed"
	ErrorAutomaticRestore      = "automatic_restore_failed"
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
	Trace             traceevent.Sink
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
		operationContext, cancel := context.WithCancel(traceevent.WithGeneration(ctx, generation))
		active := &transition{kind: "connect", done: make(chan struct{}), cancel: cancel}
		c.transition = active
		c.status = Status{State: accessmodel.StateConnecting, Message: "正在建立安全连接"}
		c.diagnosticStage = ""
		c.diagnosticDetail = ""
		c.mu.Unlock()
		c.emitTrace(traceevent.Event{Generation: generation, Level: traceevent.LevelInfo, Component: traceevent.ComponentController, Stage: traceevent.StageRequestReceived, Event: traceevent.EventState, Message: "收到连接请求"})

		status, instance, failures, started := c.runConnect(operationContext, generation)
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
		operationContext, cancel := context.WithCancel(traceevent.WithGeneration(ctx, generation))
		active := &transition{kind: "disconnect", done: make(chan struct{}), cancel: cancel}
		c.transition = active
		c.mu.Unlock()

		status, restored := c.runDisconnect(operationContext, generation, recovery)
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
				c.diagnosticStage = ""
				c.diagnosticDetail = ""
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

func (c *Controller) recordDiagnostic(fallbackStage string, err error) (string, string) {
	stage := fallbackStage
	detail := ""
	var diagnostic stagedDiagnosticError
	if errors.As(err, &diagnostic) {
		stage = normalizeDiagnosticStage(diagnostic.DiagnosticStage(), fallbackStage)
		detail = diagnostic.DiagnosticDetail()
	}
	if detail == "" && err != nil {
		detail = err.Error()
	}
	if detail == "" {
		detail = fmt.Sprintf("阶段 %s 未提供底层错误文本", stage)
	}
	detail, _ = traceevent.SanitizeDetail(detail)
	if detail == "" {
		detail = fmt.Sprintf("阶段 %s 失败", stage)
	}
	c.mu.Lock()
	c.diagnosticStage = stage
	c.diagnosticDetail = detail
	c.mu.Unlock()
	return stage, detail
}

func (c *Controller) runConnect(ctx context.Context, generation uint64) (Status, ProcessInstance, <-chan error, bool) {
	if err := contextError(ctx); err != nil {
		c.traceStateFailure(generation, traceevent.ComponentController, traceevent.StageRequestReceived, "连接请求已取消", err, nil)
		return failure(ErrorCanceled), nil, nil, false
	}
	c.mu.Lock()
	processMayStillBeRunning := c.processStarted
	previousInstance := c.processInstance
	c.mu.Unlock()
	if processMayStillBeRunning {
		err := errors.New("previous core termination is not proven")
		startedAt := c.traceStart(generation, traceevent.ComponentCore, traceevent.StageCoreStart, "检查核心进程所有权")
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedAt, "无法启动新的核心进程", err, nil)
		return failure(ErrorRestoreFailed), previousInstance, nil, true
	}
	startedAt := c.traceStart(generation, traceevent.ComponentController, traceevent.StagePolicyValidation, "验证访问策略")
	if err := c.deps.ValidatePolicy(c.policy); err != nil {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StagePolicyValidation, startedAt, "访问策略验证失败", err, nil)
		return failure(ErrorInvalidPolicy), nil, nil, false
	}
	c.traceSuccess(generation, traceevent.ComponentController, traceevent.StagePolicyValidation, startedAt, "访问策略验证通过", "", nil)
	startedAt = c.traceStart(generation, traceevent.ComponentController, traceevent.StageBinaryVerification, "验证客户端核心")
	if c.deps.VerifyExecutable == nil || c.deps.ExecutablePath == "" {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageBinaryVerification, startedAt, "客户端核心验证失败", errors.New("binary verifier or executable path is unavailable"), nil)
		return failure(ErrorInvalidBinary), nil, nil, false
	}
	if err := c.deps.VerifyExecutable(c.deps.ExecutablePath); err != nil {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageBinaryVerification, startedAt, "客户端核心验证失败", err, nil)
		return failure(ErrorInvalidBinary), nil, nil, false
	}
	c.traceSuccess(generation, traceevent.ComponentController, traceevent.StageBinaryVerification, startedAt, "客户端核心验证通过", "", nil)
	credential := Credential{}
	if c.policy.SchemaVersion == 1 {
		startedAt = c.traceStart(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, "加载受保护凭据")
		if c.deps.LoadCredential == nil {
			c.traceFailure(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, startedAt, "受保护凭据不可用", errors.New("credential loader is unavailable"), nil)
			return failure(ErrorCredential), nil, nil, false
		}
		var err error
		credential, err = c.deps.LoadCredential(ctx, c.policy.Credential)
		if err != nil {
			c.traceFailure(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, startedAt, "受保护凭据不可用", err, nil)
			return failure(ErrorCredential), nil, nil, false
		}
		defer clearBytes(credential.Password)
		if credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(c.deps.Now()) {
			c.traceFailure(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, startedAt, "受保护凭据已过期", errors.New("credential expiry is invalid"), nil)
			return failure(ErrorExpiredCredential), nil, nil, false
		}
		c.traceSuccess(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, startedAt, "受保护凭据加载完成", "", nil)
	}
	if err := contextError(ctx); err != nil {
		startedAt = c.traceStart(generation, traceevent.ComponentController, traceevent.StageNetworkCapture, "保存当前网络状态")
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageNetworkCapture, startedAt, "网络状态保存已取消", err, nil)
		return failure(ErrorCanceled), nil, nil, false
	}

	c.mu.Lock()
	hasSnapshot := c.hasSnapshot
	c.mu.Unlock()
	startedAt = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageNetworkCapture, "保存当前网络状态")
	if !hasSnapshot {
		if c.network == nil {
			c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageNetworkCapture, startedAt, "无法保存当前网络状态", errors.New("network manager is unavailable"), nil)
			return failure(ErrorNetworkCapture), nil, nil, false
		}
		snapshot, err := c.network.Capture(ctx)
		if err != nil {
			c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageNetworkCapture, startedAt, "无法保存当前网络状态", err, nil)
			return failure(ErrorNetworkCapture), nil, nil, false
		}
		c.mu.Lock()
		c.snapshot = snapshot
		c.hasSnapshot = true
		c.mu.Unlock()
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageNetworkCapture, startedAt, "当前网络状态已保存", "", nil)
	startedAt = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageFirewallPublish, "发布防泄漏规则")
	failures, err := c.network.InstallPublicTCPBlock(ctx)
	if err != nil {
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageFirewallPublish, startedAt, "防泄漏规则发布失败", err, nil)
		return failure(ErrorPublicTCPBlock), nil, nil, false
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageFirewallPublish, startedAt, "防泄漏规则已发布", "", nil)
	startedAt = c.traceStart(generation, traceevent.ComponentController, traceevent.StageConfigRender, "生成受控核心配置")
	if c.deps.RenderConfig == nil || c.deps.WriteConfigAtomic == nil || c.deps.ConfigPath == "" {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageConfigRender, startedAt, "受控核心配置生成失败", errors.New("configuration renderer or destination is unavailable"), nil)
		return failure(ErrorRender), nil, failures, false
	}
	config, err := c.deps.RenderConfig(c.policy, credential)
	if err != nil {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageConfigRender, startedAt, "受控核心配置生成失败", err, nil)
		return failure(ErrorRender), nil, failures, false
	}
	defer clearBytes(config)
	if err := c.deps.WriteConfigAtomic(c.deps.ConfigPath, config); err != nil {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageConfigRender, startedAt, "受控核心配置写入失败", err, nil)
		return failure(ErrorRender), nil, failures, false
	}
	c.traceSuccess(generation, traceevent.ComponentController, traceevent.StageConfigRender, startedAt, "受控核心配置已生成", "", nil)
	if err := contextError(ctx); err != nil {
		startedAt = c.traceStart(generation, traceevent.ComponentCore, traceevent.StageCoreStart, "启动访问核心")
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedAt, "访问核心启动已取消", err, nil)
		return failure(ErrorCanceled), nil, failures, false
	}
	startedAt = c.traceStart(generation, traceevent.ComponentCore, traceevent.StageCoreStart, "启动访问核心")
	if c.process == nil {
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedAt, "访问核心启动失败", errors.New("process supervisor is unavailable"), nil)
		return failure(ErrorCoreStart), nil, failures, false
	}
	// Start owns the core lifetime until Disconnect. The transition deadline
	// still bounds Ready below, but must not terminate a successfully connected
	// core when the connect operation itself returns.
	instance, startResult := c.process.Start(context.WithoutCancel(ctx), c.deps.ExecutablePath, c.deps.ConfigPath)
	if startResult.Err != nil {
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedAt, "访问核心启动失败", startResult.Err, nil)
		return failure(ErrorCoreStart), instance, failures, !startResult.TerminationProven
	}
	if instance == nil {
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedAt, "访问核心启动失败", errors.New("process supervisor returned no instance"), nil)
		return failure(ErrorCoreStart), nil, failures, false
	}
	c.traceSuccess(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedAt, "访问核心已启动", "", nil)
	started := true
	startedAt = c.traceStart(generation, traceevent.ComponentCore, traceevent.StageCoreReady, "等待访问核心就绪")
	if err := instance.Ready(ctx); err != nil {
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreReady, startedAt, "访问核心未就绪", err, nil)
		unproven := !c.stopInstance(context.Background(), generation, instance).Proven
		return failure(codeForContext(ctx, ErrorCoreNotReady)), instance, failures, unproven
	}
	c.traceSuccess(generation, traceevent.ComponentCore, traceevent.StageCoreReady, startedAt, "访问核心已就绪", "", nil)
	startedAt = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageTUNReady, "等待 TUN 接口就绪")
	if err := c.network.WaitTUNReady(ctx); err != nil {
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageTUNReady, startedAt, "TUN 接口未就绪", err, nil)
		unproven := !c.stopInstance(context.Background(), generation, instance).Proven
		return failure(codeForContext(ctx, ErrorCoreNotReady)), instance, failures, unproven
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageTUNReady, startedAt, "TUN 接口已就绪", "", nil)
	if err := contextError(ctx); err != nil {
		startedAt = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageRouteActivation, "启用安全路由")
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageRouteActivation, startedAt, "安全路由启用已取消", err, nil)
		unproven := !c.stopInstance(context.Background(), generation, instance).Proven
		return failure(ErrorCanceled), instance, failures, unproven
	}
	startedAt = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageRouteActivation, "启用安全路由")
	if err := c.network.ActivateTUNRoutes(ctx); err != nil {
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageRouteActivation, startedAt, "安全路由启用失败", err, nil)
		unproven := !c.stopInstance(context.Background(), generation, instance).Proven
		return failure(ErrorRouteActivationFailed), instance, failures, unproven
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageRouteActivation, startedAt, "安全路由已启用", "", nil)
	c.emitTrace(traceevent.Event{Generation: generation, Level: traceevent.LevelInfo, Component: traceevent.ComponentController, Stage: traceevent.StageConnected, Event: traceevent.EventState, Message: "海外访问已连接"})
	return Status{State: accessmodel.StateConnected, Message: "海外访问已连接"}, instance, failures, started
}

func (c *Controller) runDisconnect(ctx context.Context, generation uint64, recovery bool) (Status, bool) {
	var recoveryStarted time.Time
	if recovery {
		recoveryStarted = c.traceStart(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, "恢复服务遗留网络状态")
	} else {
		c.emitTrace(traceevent.Event{Generation: generation, Level: traceevent.LevelInfo, Component: traceevent.ComponentController, Stage: traceevent.StageRequestReceived, Event: traceevent.EventState, Message: "收到断开请求"})
	}
	c.mu.Lock()
	started := c.processStarted
	instance := c.processInstance
	hasSnapshot := c.hasSnapshot
	snapshot := c.snapshot
	reconciled := c.reconciled
	c.mu.Unlock()
	c.stopLifecycleMonitor()

	if started && instance != nil {
		termination := c.stopInstance(ctx, generation, instance)
		if !termination.Proven {
			// Restoring routes, DNS, or the leak block is unsafe until the whole
			// supervised process tree is proven terminated.
			if recovery {
				c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务遗留核心无法停止", termination.Err, nil)
			}
			return failure(ErrorRestoreFailed), false
		}
	}
	restoreStarted := c.traceStart(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, "恢复产品拥有的网络状态")
	if hasSnapshot {
		if c.network == nil {
			err := errors.New("network manager is unavailable")
			c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, restoreStarted, "网络状态恢复失败", err, nil)
			if recovery {
				c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务恢复失败", err, nil)
			}
			return failure(ErrorRestoreFailed), false
		}
		if err := c.network.Restore(ctx, snapshot); err != nil {
			c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, restoreStarted, "网络状态恢复失败", err, nil)
			if recovery {
				c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务恢复失败", err, nil)
			}
			return failure(ErrorRestoreFailed), false
		}
	} else if !reconciled {
		if c.network == nil {
			err := errors.New("network manager is unavailable")
			c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, restoreStarted, "网络状态协调失败", err, nil)
			if recovery {
				c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务恢复失败", err, nil)
			}
			return failure(ErrorRestoreFailed), false
		}
		if err := c.network.Reconcile(ctx); err != nil {
			c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, restoreStarted, "网络状态协调失败", err, nil)
			if recovery {
				c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务恢复失败", err, nil)
			}
			return failure(ErrorRestoreFailed), false
		}
	}
	c.traceSuccess(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, restoreStarted, "产品网络状态已恢复", "", nil)
	if reporter, ok := c.network.(residueReporter); ok {
		residueStarted := c.traceStart(generation, traceevent.ComponentRecovery, traceevent.StageResidueVerify, "检查连接残留")
		residue, err := reporter.Residue(ctx)
		if err != nil {
			c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageResidueVerify, residueStarted, "连接残留检查失败", err, nil)
			if recovery {
				c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务恢复失败", err, nil)
			}
			return failure(ErrorRestoreFailed), false
		}
		if !residue.IsZero() {
			err := errors.New("product-owned network residue remains")
			c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageResidueVerify, residueStarted, "连接残留未清零", err, &residue)
			if recovery {
				c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务恢复后仍有残留", err, &residue)
			}
			return failure(ErrorRestoreFailed), false
		}
		c.traceSuccess(generation, traceevent.ComponentRecovery, traceevent.StageResidueVerify, residueStarted, "连接残留已清零", "", &residue)
	}
	if recovery {
		c.traceSuccess(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务遗留状态恢复完成", "", nil)
	}
	return Status{State: accessmodel.StateDisconnected, Message: "海外访问已关闭"}, true
}

type residueReporter interface {
	Residue(context.Context) (traceevent.Residue, error)
}

func (c *Controller) traceStart(generation uint64, component, stage, message string) time.Time {
	startedAt := c.deps.Now()
	c.emitTrace(traceevent.Event{Generation: generation, Level: traceevent.LevelInfo, Component: component, Stage: stage, Event: traceevent.EventStarted, Message: message})
	return startedAt
}

func (c *Controller) traceSuccess(generation uint64, component, stage string, startedAt time.Time, message, detail string, residue *traceevent.Residue) {
	c.traceTerminal(generation, traceevent.LevelInfo, component, stage, traceevent.EventSucceeded, startedAt, message, detail, residue)
}

func (c *Controller) traceFailure(generation uint64, component, stage string, startedAt time.Time, message string, err error, residue *traceevent.Residue) {
	_, detail := c.recordDiagnostic(stage, err)
	c.traceTerminal(generation, traceevent.LevelError, component, stage, traceevent.EventFailed, startedAt, message, detail, residue)
}

func (c *Controller) traceStateFailure(generation uint64, component, stage, message string, err error, residue *traceevent.Residue) {
	_, detail := c.recordDiagnostic(stage, err)
	c.emitTrace(traceevent.Event{
		Generation: generation, Level: traceevent.LevelError, Component: component, Stage: stage,
		Event: traceevent.EventState, Message: message, Detail: detail, Residue: residue,
	})
}

func (c *Controller) traceTerminal(generation uint64, level, component, stage, event string, startedAt time.Time, message, detail string, residue *traceevent.Residue) {
	elapsed := c.deps.Now().Sub(startedAt).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	c.emitTrace(traceevent.Event{
		Generation: generation, Level: level, Component: component, Stage: stage, Event: event,
		ElapsedMS: &elapsed, Message: message, Detail: detail, Residue: residue,
	})
}

func (c *Controller) emitTrace(event traceevent.Event) {
	if c.deps.Trace == nil {
		return
	}
	event.Message, _ = traceevent.SanitizeDetail(event.Message)
	event.Detail, event.DetailTruncated = traceevent.SanitizeDetail(event.Detail)
	c.deps.Trace.Record(event)
}

func (c *Controller) stopInstance(ctx context.Context, generation uint64, instance ProcessInstance) ProcessTermination {
	startedAt := c.traceStart(generation, traceevent.ComponentCore, traceevent.StageCoreStop, "停止访问核心")
	termination := instance.Stop(ctx)
	if !termination.Proven {
		err := termination.Err
		if err == nil {
			err = errors.New("core process tree termination is not proven")
		}
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStop, startedAt, "访问核心停止失败", err, nil)
		return termination
	}
	detail := ""
	if termination.Err != nil {
		detail = "核心返回退出错误，但进程树已确认停止"
	}
	c.traceSuccess(generation, traceevent.ComponentCore, traceevent.StageCoreStop, startedAt, "访问核心已停止", detail, nil)
	return termination
}

func normalizeDiagnosticStage(stage, fallback string) string {
	switch stage {
	case traceevent.StageRequestReceived,
		traceevent.StagePolicyValidation,
		traceevent.StageBinaryVerification,
		traceevent.StageCredentialLoad,
		traceevent.StageNetworkCapture,
		traceevent.StageAdapterScan,
		traceevent.StageFirewallPublish,
		traceevent.StageActiveStoreVerify,
		traceevent.StageEmergencyProtection,
		traceevent.StageConfigRender,
		traceevent.StageCoreStart,
		traceevent.StageCoreReady,
		traceevent.StageTUNReady,
		traceevent.StageRouteActivation,
		traceevent.StageConnected,
		traceevent.StageCoreStop,
		traceevent.StageNetworkRestore,
		traceevent.StageResidueVerify,
		traceevent.StageServiceRecovery,
		traceevent.StageLoggingDegraded:
		return stage
	case "ip_interface_scan", "adapter_identity_join":
		return traceevent.StageAdapterScan
	default:
		return fallback
	}
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
	var failureReason error
	select {
	case termination = <-instance.Done():
		failureReason = termination.Err
		if failureReason == nil {
			failureReason = errors.New("core process exited unexpectedly")
		}
	case failureReason = <-failures:
		if failureReason == nil {
			failureReason = errors.New("network protection readiness was lost")
		}
		termination = c.stopInstance(context.Background(), generation, instance)
	case <-ctx.Done():
		return
	}
	c.mu.Lock()
	if c.generation != generation || c.status.State != accessmodel.StateConnected {
		c.mu.Unlock()
		return
	}
	c.status = failure(ErrorReadinessLost)
	if termination.Proven {
		c.processStarted = false
	}
	c.mu.Unlock()
	c.traceStateFailure(generation, traceevent.ComponentCore, traceevent.StageConnected, "安全连接运行状态已丢失", failureReason, nil)
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
