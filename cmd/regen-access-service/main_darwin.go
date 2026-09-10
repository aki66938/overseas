//go:build darwin

package main

import (
	"context"
	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/diagnosticmode"
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"corp.example/overseas-access-gateway/internal/localapi"
	mac "corp.example/overseas-access-gateway/internal/platform/darwin"
	"corp.example/overseas-access-gateway/internal/singconfig"
	"corp.example/overseas-access-gateway/internal/traceevent"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type dispatcher interface {
	Dispatch(context.Context, localapi.Request, bool) localapi.Response
}
type dispatchGate struct {
	mu      sync.RWMutex
	stopped bool
	handler dispatcher
}

func (g *dispatchGate) Dispatch(ctx context.Context, r localapi.Request, admin bool) localapi.Response {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.stopped {
		return localapi.Response{Version: localapi.Version, ID: r.ID, ErrorCode: "permission_denied"}
	}
	return g.handler.Dispatch(ctx, r, admin)
}
func (g *dispatchGate) stop() { g.mu.Lock(); g.stopped = true; g.mu.Unlock() }

type protectedSupervisor struct {
	inner *mac.PersistentProcessSupervisor
}

func (p protectedSupervisor) Start(ctx context.Context, exe, config string) (agent.ProcessInstance, agent.ProcessStartResult) {
	if err := mac.VerifyInstalledLaunch(exe, config); err != nil {
		return nil, agent.ProcessStartResult{Err: err, TerminationProven: true}
	}
	return p.inner.Start(ctx, exe, config)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "regen-access service failed:", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--core-helper" {
		return mac.RunCoreHelper()
	}
	restoreOnly := len(os.Args) == 2 && os.Args[1] == "--restore"
	if len(os.Args) > 1 && !restoreOnly {
		return errors.New("unsupported service argument")
	}
	cfg, err := mac.LoadInstalledServiceConfig()
	if err != nil {
		return err
	}
	lock, err := mac.AcquireDaemonLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	process := mac.NewPersistentProcessSupervisor()
	diagnostics := diagnosticmode.New(traceevent.RecorderConfig{Directory: mac.StateDirectory + "/logs", MemoryCapacity: 2048, MaxFileBytes: 2 * 1024 * 1024, RetainFiles: 5, Now: time.Now})
	defer diagnostics.Close()
	var controller *agent.Controller
	probes := lineprobe.NewScheduler(nil, nil, func(g uint64, q string) bool { return controller.UpdateLineQuality(g, q) })
	controller = agent.NewController(cfg.Policy, mac.NewNetworkManager(mac.StateDirectory), protectedSupervisor{process}, agent.WithDependencies(agent.Dependencies{
		ExecutablePath: mac.CorePath, ConfigPath: mac.RenderedConfigPath, ValidatePolicy: accessmodel.Validate, VerifyExecutable: mac.VerifyInstalledCore,
		RenderConfig: func(p accessmodel.Policy, _ agent.Credential) ([]byte, error) {
			return singconfig.RenderClient(singconfig.ClientInput{Platform: "darwin", Node: p.Nodes[0], CorporateCIDRs: p.CorporateCIDRs, CorporateDNS: p.CorporateDNS, InternalSuffixes: p.InternalSuffixes})
		},
		WriteConfigAtomic: mac.WriteInstalledConfig, Now: time.Now, Trace: diagnostics, ConnectedLifetime: probes.Start,
	}))
	recovery, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	if err := mac.RecoverOwnedCore(recovery); err != nil {
		cancel()
		return err
	}
	status := controller.Recover(recovery)
	cancel()
	if status.State != accessmodel.StatePrepared {
		return errors.New("startup network recovery incomplete")
	}
	if restoreOnly {
		return nil
	}
	if err = mac.RemoveStaleServiceSocket(cfg.OwnerUID); err != nil {
		return err
	}
	gate := &dispatchGate{handler: agent.NewLocalHandler(controller, probes, diagnostics)}
	server, err := mac.NewSocketServer(gate, cfg.OwnerUID)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	err = server.Serve(ctx)
	// Serve cancels and joins all requests before return. No dispatcher may begin
	// another lifecycle while independent cleanup is running.
	gate.stop()
	cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if controller.Disconnect(cleanup).State != accessmodel.StatePrepared {
		return errors.Join(err, errors.New("shutdown recovery incomplete"))
	}
	return err
}
