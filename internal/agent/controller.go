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
	ErrorVPNConflict           = "vpn_conflict"
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

// Connection phases surfaced by Status.Phase. Each maps to one of the six
// user-visible connection steps.
const (
	PhaseFingerprintSnapshot = "fingerprint_snapshot"
	PhaseFirewall            = "firewall"
	PhaseCore                = "core"
	PhaseTUN                 = "tun"
	PhaseRouteDNS            = "route_dns"
	PhaseConnected           = "connected"
)

const connectionTotalSteps = 6

type Status struct {
	State      accessmodel.ConnectionState `json:"state"`
	ErrorCode  string                      `json:"error_code,omitempty"`
	Message    string                      `json:"message,omitempty"`
	Phase      string                      `json:"phase,omitempty"`
	Step       int                         `json:"step,omitempty"`
	TotalSteps int                         `json:"total_steps,omitempty"`
	ElapsedMS  int64                       `json:"elapsed_ms,omitempty"`
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

// NetworkManager owns all operating-system network mutations. Prepare builds
// the reusable disabled protection pool; every mutation afterwards belongs to
// one connection transaction that Restore reverses. Implementations must make
// restore and reconcile idempotent and prove zero active residue.
type NetworkManager interface {
	Prepare(context.Context) (PreparedNetwork, error)
	Capture(context.Context, PreparedNetwork) (any, error)
	EnableProtection(context.Context, PreparedNetwork) error
	WaitTUNReady(context.Context) error
	ActivateTUNRoutes(context.Context) error
	StartMonitor(context.Context, PreparedNetwork) (<-chan error, error)
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
		if c.status.State == accessmodel.StateFailedSafe && c.transition == nil {
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
		c.status = Status{State: accessmodel.StateConnecting, Message: "正在建立安全连接", Phase: PhaseFingerprintSnapshot, Step: 1, TotalSteps: connectionTotalSteps}
		c.diagnosticStage = ""
		c.diagnosticDetail = ""
		c.mu.Unlock()
		c.emitTrace(traceevent.Event{Generation: generation, Level: traceevent.LevelInfo, Component: traceevent.ComponentController, Stage: traceevent.StageRequestReceived, Event: traceevent.EventState, Message: "收到连接请求"})

		startedAt := c.deps.Now()
		outcome := c.runConnect(operationContext, generation, startedAt)
		cancel()

		c.mu.Lock()
		if c.generation == generation {
			c.status = outcome.status
			c.processStarted = outcome.processStarted
			c.processInstance = outcome.instance
			c.snapshot = outcome.snapshot
			c.hasSnapshot = outcome.hasSnapshot
			if outcome.restored {
				c.reconciled = true
			}
		}
		connected := outcome.status.State == accessmodel.StateConnected && c.generation == generation
		var monitorContext context.Context
		var monitorDone chan struct{}
		if connected {
			var monitorCancel context.CancelFunc
			monitorContext, monitorCancel = context.WithCancel(traceevent.WithGeneration(context.Background(), generation))
			monitorDone = make(chan struct{})
			c.monitorCancel = monitorCancel
			c.monitorDone = monitorDone
		}
		c.transition = nil
		close(active.done)
		c.mu.Unlock()
		if connected {
			c.startRuntimeMonitor(monitorContext, generation, outcome.instance, monitorDone, outcome.prepared)
		}
		return outcome.status
	}
}

// startRuntimeMonitor launches the connected-generation runtime monitor. The
// monitor_start trace pair is emitted synchronously so it can never interleave
// with a later generation, and StartMonitor runs only after the status is
// connected.
func (c *Controller) startRuntimeMonitor(ctx context.Context, generation uint64, instance ProcessInstance, done chan struct{}, prepared PreparedNetwork) {
	monitorStarted := c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageMonitorStart, "正在启动运行期监控")
	failures, err := c.network.StartMonitor(ctx, prepared)
	if err != nil {
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageMonitorStart, monitorStarted, "运行期监控启动失败", err, nil)
		go c.automaticRestore(generation, ErrorReadinessLost, err)
		return
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageMonitorStart, monitorStarted, "运行期监控已启动", "", nil)
	go c.monitorLifecycle(ctx, generation, instance, failures, done)
}

func (c *Controller) Disconnect(ctx context.Context) Status {
	return c.disconnect(ctx, false)
}

// Recover reconciles state left by a previous service instance. It is safe
// to call repeatedly; only a failed reconciliation is retried.
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
		c.status = Status{State: accessmodel.StateRestoring, Message: "正在恢复普通网络"}
		c.mu.Unlock()

		outcome := c.runDisconnect(operationContext, generation, recovery)
		cancel()

		c.mu.Lock()
		if c.generation == generation {
			c.status = outcome.status
			if outcome.restored {
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
		return outcome.status
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

type connectOutcome struct {
	status         Status
	instance       ProcessInstance
	processStarted bool
	restored       bool
	snapshot       any
	hasSnapshot    bool
	prepared       PreparedNetwork
}

type disconnectOutcome struct {
	status   Status
	restored bool
	err      error
}

func (c *Controller) phaseStatus(phase string, step int, startedAt time.Time, connected bool) Status {
	elapsed := c.deps.Now().Sub(startedAt).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	return Status{
		State:      accessmodel.StateConnecting,
		Message:    "正在建立安全连接",
		Phase:      phase,
		Step:       step,
		TotalSteps: connectionTotalSteps,
		ElapsedMS:  elapsed,
	}
}

// runConnect executes the six-step connection transaction. Any failure at or
// after the first persisted product state runs restoreTransaction before the
// status is returned, so the pipe response always describes a provably safe
// machine: prepared with the original error code, or failed_safe.
func (c *Controller) runConnect(ctx context.Context, generation uint64, startedAt time.Time) connectOutcome {
	preChecks := func(code string) connectOutcome {
		return connectOutcome{status: safeFailure(code)}
	}
	if err := contextError(ctx); err != nil {
		c.traceStateFailure(generation, traceevent.ComponentController, traceevent.StageRequestReceived, "连接请求已取消", err, nil)
		return preChecks(ErrorCanceled)
	}
	c.mu.Lock()
	processMayStillBeRunning := c.processStarted
	previousInstance := c.processInstance
	c.mu.Unlock()
	if processMayStillBeRunning {
		err := errors.New("previous core termination is not proven")
		startedTrace := c.traceStart(generation, traceevent.ComponentCore, traceevent.StageCoreStart, "检查核心进程所有权")
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedTrace, "无法启动新的核心进程", err, nil)
		return c.restoreAfterFailure(ctx, generation, ErrorRestoreFailed, PreparedNetwork{}, true, previousInstance, nil, false)
	}
	startedTrace := c.traceStart(generation, traceevent.ComponentController, traceevent.StagePolicyValidation, "验证访问策略")
	if err := c.deps.ValidatePolicy(c.policy); err != nil {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StagePolicyValidation, startedTrace, "访问策略验证失败", err, nil)
		return preChecks(ErrorInvalidPolicy)
	}
	c.traceSuccess(generation, traceevent.ComponentController, traceevent.StagePolicyValidation, startedTrace, "访问策略验证通过", "", nil)
	startedTrace = c.traceStart(generation, traceevent.ComponentController, traceevent.StageBinaryVerification, "验证客户端核心")
	if c.deps.VerifyExecutable == nil || c.deps.ExecutablePath == "" {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageBinaryVerification, startedTrace, "客户端核心验证失败", errors.New("binary verifier or executable path is unavailable"), nil)
		return preChecks(ErrorInvalidBinary)
	}
	if err := c.deps.VerifyExecutable(c.deps.ExecutablePath); err != nil {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageBinaryVerification, startedTrace, "客户端核心验证失败", err, nil)
		return preChecks(ErrorInvalidBinary)
	}
	c.traceSuccess(generation, traceevent.ComponentController, traceevent.StageBinaryVerification, startedTrace, "客户端核心验证通过", "", nil)
	credential := Credential{}
	if c.policy.SchemaVersion == 1 {
		startedTrace = c.traceStart(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, "加载受保护凭据")
		if c.deps.LoadCredential == nil {
			c.traceFailure(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, startedTrace, "受保护凭据不可用", errors.New("credential loader is unavailable"), nil)
			return preChecks(ErrorCredential)
		}
		var err error
		credential, err = c.deps.LoadCredential(ctx, c.policy.Credential)
		if err != nil {
			c.traceFailure(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, startedTrace, "受保护凭据不可用", err, nil)
			return preChecks(ErrorCredential)
		}
		defer clearBytes(credential.Password)
		if credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(c.deps.Now()) {
			c.traceFailure(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, startedTrace, "受保护凭据已过期", errors.New("credential expiry is invalid"), nil)
			return preChecks(ErrorExpiredCredential)
		}
		c.traceSuccess(generation, traceevent.ComponentController, traceevent.StageCredentialLoad, startedTrace, "受保护凭据加载完成", "", nil)
	}

	// Step 1: prepare the reusable baseline and capture the active snapshot.
	c.mu.Lock()
	if err := c.setStatusLocked(c.phaseStatus(PhaseFingerprintSnapshot, 1, startedAt, false)); err != nil {
		c.mu.Unlock()
		c.traceStateFailure(generation, traceevent.ComponentController, traceevent.StageNetworkPrepare, "连接请求已取消", err, nil)
		return preChecks(ErrorCanceled)
	}
	c.mu.Unlock()
	if c.network == nil {
		err := errors.New("network manager is unavailable")
		startedTrace = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageNetworkPrepare, "正在读取当前网络配置与网卡清单")
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageNetworkPrepare, startedTrace, "网络保护配置不可用", err, nil)
		return preChecks(ErrorPreparedUnavailable)
	}
	startedTrace = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageNetworkPrepare, "正在读取当前网络配置与网卡清单")
	prepared, err := c.network.Prepare(ctx)
	if err != nil {
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageNetworkPrepare, startedTrace, "网络保护配置不可用", err, nil)
		code := ErrorPreparedUnavailable
		if errors.Is(err, errVPNConflict) {
			code = ErrorVPNConflict
		}
		if contextError(ctx) != nil {
			code = ErrorCanceled
		}
		return c.restoreAfterFailure(ctx, generation, code, PreparedNetwork{}, false, nil, nil, false)
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageNetworkPrepare, startedTrace, "网络保护配置已就绪", fmt.Sprintf("generation=%d adapters=%d rules=%d", prepared.Generation, prepared.AdapterCount, prepared.RuleCount), nil)
	startedTrace = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageNetworkCapture, "正在读取当前网络配置")
	snapshot, err := c.network.Capture(ctx, prepared)
	if err != nil {
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageNetworkCapture, startedTrace, "无法读取当前网络配置", err, nil)
		code := codeForContext(ctx, ErrorNetworkCapture)
		return c.restoreAfterFailure(ctx, generation, code, PreparedNetwork{}, false, nil, nil, false)
	}
	c.mu.Lock()
	c.snapshot = snapshot
	c.hasSnapshot = true
	c.mu.Unlock()
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageNetworkCapture, startedTrace, "当前网络配置已确认", "", nil)

	// Step 2: enable and verify the prepared leak protection.
	c.mu.Lock()
	_ = c.setStatusLocked(c.phaseStatus(PhaseFirewall, 2, startedAt, false))
	c.mu.Unlock()
	startedTrace = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageFirewallEnable, "正在启用防泄漏保护")
	if err := c.network.EnableProtection(ctx, prepared); err != nil {
		code := ErrorFirewallEnable
		if diagnosticStage(err) == traceevent.StageFirewallVerify {
			code = ErrorFirewallVerify
		}
		if contextError(ctx) != nil {
			code = ErrorCanceled
		}
		stage := traceevent.StageFirewallEnable
		if code == ErrorFirewallVerify {
			stage = traceevent.StageFirewallVerify
		}
		c.traceFailure(generation, traceevent.ComponentNetwork, stage, startedTrace, "防泄漏保护启用失败", err, nil)
		return c.restoreAfterFailure(ctx, generation, code, prepared, false, nil, snapshot, true)
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageFirewallEnable, startedTrace, "防泄漏保护已启用", fmt.Sprintf("rules=%d", prepared.RuleCount), nil)

	// Step 3: render the controlled configuration and start the core.
	c.mu.Lock()
	_ = c.setStatusLocked(c.phaseStatus(PhaseCore, 3, startedAt, false))
	c.mu.Unlock()
	startedTrace = c.traceStart(generation, traceevent.ComponentController, traceevent.StageConfigRender, "生成受控核心配置")
	if c.deps.RenderConfig == nil || c.deps.WriteConfigAtomic == nil || c.deps.ConfigPath == "" {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageConfigRender, startedTrace, "受控核心配置生成失败", errors.New("configuration renderer or destination is unavailable"), nil)
		return c.restoreAfterFailure(ctx, generation, ErrorRender, prepared, false, nil, snapshot, true)
	}
	config, err := c.deps.RenderConfig(c.policy, credential)
	if err != nil {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageConfigRender, startedTrace, "受控核心配置生成失败", err, nil)
		return c.restoreAfterFailure(ctx, generation, ErrorRender, prepared, false, nil, snapshot, true)
	}
	defer clearBytes(config)
	if err := c.deps.WriteConfigAtomic(c.deps.ConfigPath, config); err != nil {
		c.traceFailure(generation, traceevent.ComponentController, traceevent.StageConfigRender, startedTrace, "受控核心配置写入失败", err, nil)
		return c.restoreAfterFailure(ctx, generation, ErrorRender, prepared, false, nil, snapshot, true)
	}
	c.traceSuccess(generation, traceevent.ComponentController, traceevent.StageConfigRender, startedTrace, "受控核心配置已生成", "", nil)
	startedTrace = c.traceStart(generation, traceevent.ComponentCore, traceevent.StageCoreStart, "启动访问核心")
	if c.process == nil {
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedTrace, "访问核心启动失败", errors.New("process supervisor is unavailable"), nil)
		return c.restoreAfterFailure(ctx, generation, ErrorCoreStart, prepared, false, nil, snapshot, true)
	}
	// Start owns the core lifetime until Disconnect. The transition deadline
	// still bounds Ready below, but must not terminate a successfully connected
	// core when the connect operation itself returns.
	instance, startResult := c.process.Start(context.WithoutCancel(ctx), c.deps.ExecutablePath, c.deps.ConfigPath)
	if startResult.Err != nil {
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedTrace, "访问核心启动失败", startResult.Err, nil)
		return c.restoreAfterFailure(ctx, generation, codeForContext(ctx, ErrorCoreStart), prepared, !startResult.TerminationProven, instance, snapshot, true)
	}
	if instance == nil {
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedTrace, "访问核心启动失败", errors.New("process supervisor returned no instance"), nil)
		return c.restoreAfterFailure(ctx, generation, ErrorCoreStart, prepared, false, nil, snapshot, true)
	}
	c.traceSuccess(generation, traceevent.ComponentCore, traceevent.StageCoreStart, startedTrace, "访问核心已启动", "", nil)
	startedOutcome := connectOutcome{processStarted: true, snapshot: snapshot, hasSnapshot: true, prepared: prepared, instance: instance}
	startedTrace = c.traceStart(generation, traceevent.ComponentCore, traceevent.StageCoreReady, "等待访问核心就绪")
	if err := instance.Ready(ctx); err != nil {
		c.traceFailure(generation, traceevent.ComponentCore, traceevent.StageCoreReady, startedTrace, "访问核心未就绪", err, nil)
		return c.restoreAfterFailure(ctx, generation, codeForContext(ctx, ErrorCoreNotReady), prepared, true, instance, snapshot, true)
	}
	c.traceSuccess(generation, traceevent.ComponentCore, traceevent.StageCoreReady, startedTrace, "访问核心已就绪", "", nil)

	// Step 4: own the fixed TUN identity created by the core.
	c.mu.Lock()
	_ = c.setStatusLocked(c.phaseStatus(PhaseTUN, 4, startedAt, false))
	c.mu.Unlock()
	startedTrace = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageTUNReady, "正在等待 sing-box TUN 网卡")
	if err := c.network.WaitTUNReady(ctx); err != nil {
		code := ErrorTUNNotFound
		stage := traceevent.StageTUNReady
		switch {
		case contextError(ctx) != nil:
			code = ErrorCanceled
		case errors.Is(err, errTUNIdentityMismatch):
			code = ErrorTUNIdentityMismatch
		case errors.Is(err, errTUNNotFound):
			code = ErrorTUNNotFound
		}
		c.traceFailure(generation, traceevent.ComponentNetwork, stage, startedTrace, tunFailureMessage(code), err, nil)
		return c.restoreAfterFailure(ctx, generation, code, prepared, true, instance, snapshot, true)
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageTUNReady, startedTrace, "TUN 网卡已就绪", "", nil)

	// Step 5: switch DNS, interface metric, and the safe routes.
	c.mu.Lock()
	_ = c.setStatusLocked(c.phaseStatus(PhaseRouteDNS, 5, startedAt, false))
	c.mu.Unlock()
	startedTrace = c.traceStart(generation, traceevent.ComponentNetwork, traceevent.StageRouteActivation, "正在切换 DNS 与安全路由")
	if err := c.network.ActivateTUNRoutes(ctx); err != nil {
		c.traceFailure(generation, traceevent.ComponentNetwork, traceevent.StageRouteActivation, startedTrace, "安全路由启用失败", err, nil)
		return c.restoreAfterFailure(ctx, generation, codeForContext(ctx, ErrorRouteActivationFailed), prepared, true, instance, snapshot, true)
	}
	c.traceSuccess(generation, traceevent.ComponentNetwork, traceevent.StageRouteActivation, startedTrace, "安全路由已启用", "", nil)

	// Step 6: connected; the caller starts the runtime monitor.
	elapsed := c.deps.Now().Sub(startedAt).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	status := Status{State: accessmodel.StateConnected, Message: "海外访问已连接", Phase: PhaseConnected, Step: connectionTotalSteps, TotalSteps: connectionTotalSteps, ElapsedMS: elapsed}
	c.emitTrace(traceevent.Event{Generation: generation, Level: traceevent.LevelInfo, Component: traceevent.ComponentController, Stage: traceevent.StageConnected, Event: traceevent.EventState, Message: "海外访问已连接"})
	startedOutcome.status = status
	return startedOutcome
}

func tunFailureMessage(code string) string {
	switch code {
	case ErrorTUNIdentityMismatch:
		return "TUN 网卡身份与受控定义不符"
	case ErrorCanceled:
		return "TUN 等待已取消"
	default:
		return "TUN 网卡在截止时间内未出现"
	}
}

func diagnosticStage(err error) string {
	var diagnostic stagedDiagnosticError
	if errors.As(err, &diagnostic) {
		return diagnostic.DiagnosticStage()
	}
	return ""
}

// restoreAfterFailure reverses the connection transaction in strict order and
// proves zero active residue. It returns prepared with the original error code
// when the restore is provably complete, and failed_safe otherwise.
func (c *Controller) restoreAfterFailure(ctx context.Context, generation uint64, code string, prepared PreparedNetwork, processStarted bool, instance ProcessInstance, snapshot any, hasSnapshot bool) connectOutcome {
	startedTrace := c.traceStart(generation, traceevent.ComponentRecovery, traceevent.StageAutomaticRestore, "正在自动恢复普通网络")
	outcome := c.restoreTransaction(context.WithoutCancel(ctx), generation, processStarted, instance, snapshot, hasSnapshot)
	if outcome.restored {
		status := safeFailure(code)
		c.traceSuccess(generation, traceevent.ComponentRecovery, traceevent.StageAutomaticRestore, startedTrace, "自动恢复完成，活动残留已清零", "", nil)
		return connectOutcome{status: status, instance: nil, restored: true, snapshot: nil, hasSnapshot: false, prepared: prepared, processStarted: false}
	}
	c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageAutomaticRestore, startedTrace, "自动恢复无法证明完成", outcome.err, nil)
	return connectOutcome{status: failedSafeStatus(), instance: instance, restored: false, snapshot: snapshot, hasSnapshot: hasSnapshot, prepared: prepared, processStarted: processStarted && instance != nil}
}

// restoreTransaction is the single idempotent reverse-order restoration used
// by Disconnect, Recover, failed Connect, and runtime monitor triggers.
func (c *Controller) restoreTransaction(ctx context.Context, generation uint64, processStarted bool, instance ProcessInstance, snapshot any, hasSnapshot bool) disconnectOutcome {
	c.stopLifecycleMonitor()
	if processStarted && instance != nil {
		termination := c.stopInstance(ctx, generation, instance)
		if !termination.Proven {
			// Restoring routes, DNS, or the leak block is unsafe until the whole
			// supervised process tree is proven terminated.
			return disconnectOutcome{status: failedSafeStatus(), restored: false, err: termination.Err}
		}
	}
	restoreStarted := c.traceStart(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, "正在恢复普通网络")
	if c.network == nil {
		err := errors.New("network manager is unavailable")
		c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, restoreStarted, "普通网络恢复失败", err, nil)
		return disconnectOutcome{status: failedSafeStatus(), restored: false, err: err}
	}
	var restoreErr error
	if hasSnapshot {
		restoreErr = c.network.Restore(ctx, snapshot)
	} else {
		restoreErr = c.network.Reconcile(ctx)
	}
	if restoreErr != nil {
		c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, restoreStarted, "普通网络恢复失败", restoreErr, nil)
		return disconnectOutcome{status: failedSafeStatus(), restored: false, err: restoreErr}
	}
	c.traceSuccess(generation, traceevent.ComponentRecovery, traceevent.StageNetworkRestore, restoreStarted, "普通网络已恢复", "", nil)
	if reporter, ok := c.network.(residueReporter); ok {
		residueStarted := c.traceStart(generation, traceevent.ComponentRecovery, traceevent.StageResidueVerify, "正在检查连接残留")
		residue, err := reporter.Residue(ctx)
		if err != nil {
			c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageResidueVerify, residueStarted, "连接残留检查失败", err, nil)
			return disconnectOutcome{status: failedSafeStatus(), restored: false, err: err}
		}
		if !residue.IsZero() {
			err := errors.New("product-owned network residue remains")
			c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageResidueVerify, residueStarted, "连接残留未清零", err, &residue)
			return disconnectOutcome{status: failedSafeStatus(), restored: false, err: err}
		}
		c.traceSuccess(generation, traceevent.ComponentRecovery, traceevent.StageResidueVerify, residueStarted, "活动残留已清零", "", &residue)
	}
	return disconnectOutcome{status: preparedStatus("普通网络已恢复"), restored: true}
}

func (c *Controller) runDisconnect(ctx context.Context, generation uint64, recovery bool) disconnectOutcome {
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

	if !hasSnapshot && !started && reconciled {
		outcome := disconnectOutcome{status: preparedStatus("海外访问已关闭"), restored: true}
		if recovery {
			c.traceSuccess(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务遗留状态恢复完成", "", nil)
		}
		return outcome
	}
	outcome := c.restoreTransaction(ctx, generation, started, instance, snapshot, hasSnapshot)
	if outcome.restored {
		if recovery {
			c.traceSuccess(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务遗留状态恢复完成", "", nil)
		}
		return outcome
	}
	if recovery {
		err := outcome.err
		if err == nil {
			err = errors.New("service recovery could not prove a safe state")
		}
		c.traceFailure(generation, traceevent.ComponentRecovery, traceevent.StageServiceRecovery, recoveryStarted, "服务恢复失败", err, nil)
	}
	return outcome
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
		traceevent.StageNetworkPrepare,
		traceevent.StageNetworkFingerprint,
		traceevent.StageNetworkCapture,
		traceevent.StageAdapterScan,
		traceevent.StageFirewallPrepare,
		traceevent.StageFirewallEnable,
		traceevent.StageFirewallVerify,
		traceevent.StageFirewallPublish,
		traceevent.StageActiveStoreVerify,
		traceevent.StageEmergencyProtection,
		traceevent.StageConfigRender,
		traceevent.StageCoreStart,
		traceevent.StageCoreReady,
		traceevent.StageTUNReady,
		traceevent.StageRouteActivation,
		traceevent.StageConnected,
		traceevent.StageMonitorStart,
		traceevent.StageCoreStop,
		traceevent.StageAutomaticRestore,
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

func (c *Controller) setStatusLocked(status Status) error {
	c.status = status
	return nil
}

// monitorLifecycle owns the runtime monitor after connected. A core exit or a
// monitor-reported protection failure triggers one generation-owned automatic
// restoration; the resulting status is prepared with the causal error code,
// or failed_safe when the restore cannot be proven.
func (c *Controller) monitorLifecycle(ctx context.Context, generation uint64, instance ProcessInstance, failures <-chan error, done chan struct{}) {
	defer close(done)
	var failureReason error
	select {
	case termination := <-instance.Done():
		failureReason = termination.Err
		if failureReason == nil {
			failureReason = errors.New("core process exited unexpectedly")
		}
	case failureReason = <-failures:
		if failureReason == nil {
			failureReason = errors.New("network protection readiness was lost")
		}
	case <-ctx.Done():
		return
	}
	code := c.monitorFailureCode(failureReason)
	c.automaticRestore(generation, code, failureReason)
}

func (c *Controller) monitorFailureCode(reason error) string {
	if errors.Is(reason, errNetworkChanged) {
		return ErrorNetworkChanged
	}
	if diagnosticStage(reason) == traceevent.StageFirewallVerify || errors.Is(reason, errFirewallAudit) {
		return ErrorFirewallVerify
	}
	return ErrorReadinessLost
}

// automaticRestore runs the reverse-order restoration outside of a user
// transition. It takes the transition slot so concurrent Connect/Disconnect
// requests serialize against the restore.
func (c *Controller) automaticRestore(generation uint64, code string, reason error) {
	c.mu.Lock()
	if c.generation != generation || c.status.State != accessmodel.StateConnected {
		c.mu.Unlock()
		return
	}
	if c.transition != nil {
		c.mu.Unlock()
		return
	}
	active := &transition{kind: "restore", done: make(chan struct{})}
	c.transition = active
	c.status = Status{State: accessmodel.StateRestoring, Message: "正在恢复普通网络"}
	monitorCancel := c.monitorCancel
	c.monitorCancel = nil
	c.monitorDone = nil
	instance := c.processInstance
	started := c.processStarted
	snapshot := c.snapshot
	hasSnapshot := c.hasSnapshot
	c.mu.Unlock()
	if monitorCancel != nil {
		monitorCancel()
	}
	c.traceStateFailure(generation, traceevent.ComponentCore, traceevent.StageConnected, "安全连接运行状态已丢失", reason, nil)

	restoreContext, cancel := context.WithCancel(traceevent.WithGeneration(context.Background(), generation))
	outcome := c.restoreTransaction(restoreContext, generation, started, instance, snapshot, hasSnapshot)
	cancel()

	c.mu.Lock()
	if c.generation == generation {
		c.status = outcome.status
		if outcome.restored {
			c.status = safeFailure(code)
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

func preparedStatus(message string) Status {
	return Status{State: accessmodel.StatePrepared, Message: message}
}

// safeFailure reports a provably safe, connectable machine together with the
// error code of the last failed attempt.
func safeFailure(code string) Status {
	return Status{State: accessmodel.StatePrepared, ErrorCode: code, Message: failureMessages[code]}
}

func failedSafeStatus() Status {
	return Status{State: accessmodel.StateFailedSafe, ErrorCode: ErrorAutomaticRestore, Message: failureMessages[ErrorAutomaticRestore]}
}

var failureMessages = map[string]string{
	ErrorInvalidPolicy:         "客户端策略无效",
	ErrorInvalidBinary:         "客户端核心验证失败",
	ErrorCredential:            "访问凭据不可用",
	ErrorExpiredCredential:     "访问凭据已过期",
	ErrorPreparedUnavailable:   "网络保护配置不可用",
	ErrorVPNConflict:           "检测到其他 VPN/代理正在运行",
	ErrorNetworkChanged:        "网络环境已变化",
	ErrorNetworkCapture:        "无法读取当前网络配置",
	ErrorFirewallEnable:        "无法启用防泄漏保护",
	ErrorFirewallVerify:        "防泄漏规则核对失败",
	ErrorPublicTCPBlock:        "无法建立防泄漏保护",
	ErrorRender:                "无法生成受控配置",
	ErrorCoreStart:             "无法启动访问核心",
	ErrorCoreNotReady:          "访问服务器不可用",
	ErrorTUNNotFound:           "TUN 网卡未出现",
	ErrorTUNIdentityMismatch:   "TUN 网卡身份异常",
	ErrorRouteActivationFailed: "无法启用安全路由",
	ErrorReadinessLost:         "安全连接已中断",
	ErrorRestoreFailed:         "无法完整恢复网络状态",
	ErrorAutomaticRestore:      "自动恢复未完成，已保持应急防护",
	ErrorCanceled:              "操作已取消",
}

func canceledStatus(current Status) Status {
	status := safeFailure(ErrorCanceled)
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
