// Package agent coordinates the fail-closed overseas access lifecycle.
package agent

import (
	"context"
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
	InstallPublicTCPBlock(context.Context) error
	WaitTUNReady(context.Context) error
	ActivateTUNRoutes(context.Context) error
	Restore(context.Context, any) error
	Reconcile(context.Context) error
}

// ProcessSupervisor is a reusable facade. A production implementation may
// allocate a fresh single-use supervisor.Process for every Start call.
type ProcessSupervisor interface {
	Start(context.Context, string, string) error
	Ready(context.Context) error
	Stop(context.Context) error
	Wait() error
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

	mu             sync.Mutex
	status         Status
	generation     uint64
	transition     *transition
	snapshot       any
	hasSnapshot    bool
	processStarted bool
	reconciled     bool
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
		c.mu.Unlock()

		status, started := c.runConnect(operationContext)
		cancel()

		c.mu.Lock()
		if c.generation == generation {
			c.status = status
			c.processStarted = started
		}
		c.transition = nil
		close(active.done)
		connected := status.State == accessmodel.StateConnected && c.generation == generation
		c.mu.Unlock()
		if connected {
			go c.monitorProcess(generation)
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
	}
}

func (c *Controller) runConnect(ctx context.Context) (Status, bool) {
	if err := contextError(ctx); err != nil {
		return failure(ErrorCanceled), false
	}
	c.mu.Lock()
	processMayStillBeRunning := c.processStarted
	c.mu.Unlock()
	if processMayStillBeRunning {
		return failure(ErrorRestoreFailed), true
	}
	if err := c.deps.ValidatePolicy(c.policy); err != nil {
		return failure(ErrorInvalidPolicy), false
	}
	if c.deps.VerifyExecutable == nil || c.deps.ExecutablePath == "" {
		return failure(ErrorInvalidBinary), false
	}
	if err := c.deps.VerifyExecutable(c.deps.ExecutablePath); err != nil {
		return failure(ErrorInvalidBinary), false
	}
	if c.deps.LoadCredential == nil {
		return failure(ErrorCredential), false
	}
	credential, err := c.deps.LoadCredential(ctx, c.policy.Credential)
	if err != nil {
		return failure(ErrorCredential), false
	}
	defer clearBytes(credential.Password)
	if credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(c.deps.Now()) {
		return failure(ErrorExpiredCredential), false
	}
	if err := contextError(ctx); err != nil {
		return failure(ErrorCanceled), false
	}

	c.mu.Lock()
	hasSnapshot := c.hasSnapshot
	c.mu.Unlock()
	if !hasSnapshot {
		if c.network == nil {
			return failure(ErrorNetworkCapture), false
		}
		snapshot, err := c.network.Capture(ctx)
		if err != nil {
			return failure(ErrorNetworkCapture), false
		}
		c.mu.Lock()
		c.snapshot = snapshot
		c.hasSnapshot = true
		c.mu.Unlock()
	}
	if err := c.network.InstallPublicTCPBlock(ctx); err != nil {
		return failure(ErrorPublicTCPBlock), false
	}
	if c.deps.RenderConfig == nil || c.deps.WriteConfigAtomic == nil || c.deps.ConfigPath == "" {
		return failure(ErrorRender), false
	}
	config, err := c.deps.RenderConfig(c.policy, credential)
	if err != nil {
		return failure(ErrorRender), false
	}
	defer clearBytes(config)
	if err := c.deps.WriteConfigAtomic(c.deps.ConfigPath, config); err != nil {
		return failure(ErrorRender), false
	}
	if err := contextError(ctx); err != nil {
		return failure(ErrorCanceled), false
	}
	if c.process == nil {
		return failure(ErrorCoreStart), false
	}
	// Start owns the core lifetime until Disconnect. The transition deadline
	// still bounds Ready below, but must not terminate a successfully connected
	// core when the connect operation itself returns.
	if err := c.process.Start(context.WithoutCancel(ctx), c.deps.ExecutablePath, c.deps.ConfigPath); err != nil {
		return failure(ErrorCoreStart), false
	}
	started := true
	if err := c.process.Ready(ctx); err != nil {
		return failure(codeForContext(ctx, ErrorCoreNotReady)), c.stopCouldNotBeProven()
	}
	if err := c.network.WaitTUNReady(ctx); err != nil {
		return failure(codeForContext(ctx, ErrorCoreNotReady)), c.stopCouldNotBeProven()
	}
	if err := contextError(ctx); err != nil {
		return failure(ErrorCanceled), c.stopCouldNotBeProven()
	}
	if err := c.network.ActivateTUNRoutes(ctx); err != nil {
		return failure(ErrorRouteActivationFailed), c.stopCouldNotBeProven()
	}
	return Status{State: accessmodel.StateConnected, Message: "海外访问已连接"}, started
}

func (c *Controller) stopCouldNotBeProven() bool {
	return c.process.Stop(context.Background()) != nil
}

func (c *Controller) runDisconnect(ctx context.Context) (Status, bool) {
	c.mu.Lock()
	started := c.processStarted
	hasSnapshot := c.hasSnapshot
	snapshot := c.snapshot
	reconciled := c.reconciled
	c.mu.Unlock()

	var stopErr error
	if started && c.process != nil {
		stopErr = c.process.Stop(ctx)
	}
	if stopErr != nil {
		// Restoring routes, DNS, or the leak block is unsafe until the whole
		// supervised process tree is proven terminated.
		return failure(ErrorRestoreFailed), false
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

func (c *Controller) monitorProcess(generation uint64) {
	err := c.process.Wait()
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation || c.status.State != accessmodel.StateConnected {
		return
	}
	c.status = failure(ErrorReadinessLost)
	c.processStarted = false
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
