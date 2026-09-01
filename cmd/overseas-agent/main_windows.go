//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/coreverify"
	"corp.example/overseas-access-gateway/internal/runtimeowner"
	"corp.example/overseas-access-gateway/internal/secret"
	"corp.example/overseas-access-gateway/internal/singconfig"
	"corp.example/overseas-access-gateway/internal/supervisor"
	"corp.example/overseas-access-gateway/internal/traceevent"
	"golang.org/x/sys/windows/svc"
	"gopkg.in/yaml.v3"
)

const (
	serviceName        = "RegenBioOverseasAccessAgent"
	serviceExitConfig  = 1
	serviceExitPipe    = 2
	serviceExitRestore = 3
	serviceStopTimeout = 20 * time.Second

	installDirectory = `C:\Program Files\RegenBio\OverseasAccess`
	dataDirectory    = `C:\ProgramData\RegenBio\OverseasAccess`
	bootstrapPath    = dataDirectory + `\agent.yaml`
	corePath         = installDirectory + `\sing-box.exe`
	renderedPath     = dataDirectory + `\sing-box.json`
	networkStatePath = dataDirectory + `\network-state.json`
	traceDirectory   = dataDirectory + `\logs`

	traceMemoryCapacity = 2048
	traceMaxFileBytes   = 2 * 1024 * 1024
	traceRetainFiles    = 5
)

type controllerLifecycle interface {
	agent.PipeController
	Recover(context.Context) agent.Status
}

type pipeRunner interface {
	ListenAndServe(context.Context) error
}

type serviceTrace interface {
	traceevent.Sink
	traceevent.Source
	Close() error
}

type serviceHandler struct {
	controller controllerLifecycle
	pipe       pipeRunner
	trace      serviceTrace
	traceClose sync.Once
}

func (s *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	defer s.closeTrace()
	s.recordService(traceevent.LevelInfo, "Windows 服务开始启动")
	changes <- svc.Status{State: svc.StartPending}
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), serviceStopTimeout)
	recovery := s.controller.Recover(recoveryContext)
	cancelRecovery()
	if recovery.State != accessmodel.StateDisconnected {
		s.recordService(traceevent.LevelError, "Windows 服务启动恢复失败")
		changes <- svc.Status{State: svc.StopPending}
		return true, serviceExitRestore
	}

	pipeContext, cancelPipe := context.WithCancel(context.Background())
	defer cancelPipe()
	pipeErrors := make(chan error, 1)
	go func() { pipeErrors <- s.pipe.ListenAndServe(pipeContext) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	s.recordService(traceevent.LevelInfo, "Windows 服务正在运行")

	for {
		select {
		case request, ok := <-requests:
			if !ok {
				return s.stop(changes, cancelPipe)
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			case svc.Stop, svc.Shutdown:
				return s.stop(changes, cancelPipe)
			}
		case err := <-pipeErrors:
			if err == nil && pipeContext.Err() != nil {
				return false, 0
			}
			changes <- svc.Status{State: svc.StopPending}
			s.recordService(traceevent.LevelError, "本地控制通道意外停止")
			if status := disconnectWithTimeout(s.controller); status.State != accessmodel.StateDisconnected {
				s.recordService(traceevent.LevelError, "控制通道停止后的网络恢复失败")
				return true, serviceExitRestore
			}
			s.recordService(traceevent.LevelError, "Windows 服务因控制通道故障停止")
			return true, serviceExitPipe
		}
	}
}

func (s *serviceHandler) stop(changes chan<- svc.Status, cancelPipe context.CancelFunc) (bool, uint32) {
	changes <- svc.Status{State: svc.StopPending}
	s.recordService(traceevent.LevelInfo, "Windows 服务正在停止")
	cancelPipe()
	if status := disconnectWithTimeout(s.controller); status.State != accessmodel.StateDisconnected {
		s.recordService(traceevent.LevelError, "Windows 服务停止时网络恢复失败")
		return true, serviceExitRestore
	}
	s.recordService(traceevent.LevelInfo, "Windows 服务已停止")
	return false, 0
}

func (s *serviceHandler) recordService(level, message string) {
	if s.trace == nil {
		return
	}
	generation := uint64(0)
	if s.controller != nil {
		generation = s.controller.Diagnostics().Generation
	}
	s.trace.Record(traceevent.Event{
		Generation: generation, Level: level, Component: traceevent.ComponentService,
		Stage: traceevent.StageServiceRecovery, Event: traceevent.EventState, Message: message,
	})
}

func (s *serviceHandler) closeTrace() {
	if s.trace == nil {
		return
	}
	s.traceClose.Do(func() { _ = s.trace.Close() })
}

func disconnectWithTimeout(controller controllerLifecycle) agent.Status {
	ctx, cancel := context.WithTimeout(context.Background(), serviceStopTimeout)
	defer cancel()
	return controller.Disconnect(ctx)
}

type bootstrapConfig struct {
	Policy          accessmodel.Policy `yaml:"policy"`
	CoreSHA256      string             `yaml:"core_sha256"`
	SignerAllowlist []string           `yaml:"signer_allowlist"`
}

type encryptedCredential struct {
	Method    string    `json:"method"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
}

func main() {
	handler, err := buildService()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "overseas access service configuration is invalid")
		os.Exit(serviceExitConfig)
	}
	defer handler.closeTrace()
	if err := svc.Run(serviceName, handler); err != nil {
		handler.recordService(traceevent.LevelError, "Windows 服务意外停止")
		handler.closeTrace()
		_, _ = fmt.Fprintln(os.Stderr, "overseas access service stopped unexpectedly")
		os.Exit(serviceExitPipe)
	}
}

func buildService() (*serviceHandler, error) {
	contents, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, err
	}
	var bootstrap bootstrapConfig
	if err := yaml.Unmarshal(contents, &bootstrap); err != nil {
		return nil, err
	}
	recorder, err := traceevent.NewRecorder(traceevent.RecorderConfig{
		Directory: traceDirectory, MemoryCapacity: traceMemoryCapacity,
		MaxFileBytes: traceMaxFileBytes, RetainFiles: traceRetainFiles, Now: time.Now,
	})
	if err != nil {
		return nil, err
	}
	keepRecorder := false
	defer func() {
		if !keepRecorder {
			_ = recorder.Close()
		}
	}()
	verify := func(path string) error {
		return coreverify.Verify(path, bootstrap.CoreSHA256, bootstrap.SignerAllowlist)
	}
	process := &supervisedCore{verifyExecutable: verify}
	network, err := agent.NewWindowsNetworkManager(bootstrap.Policy, networkStatePath, agent.WithWindowsTraceSink(recorder))
	if err != nil {
		return nil, err
	}
	dependencies := agent.Dependencies{
		ExecutablePath:    corePath,
		ConfigPath:        renderedPath,
		ValidatePolicy:    accessmodel.Validate,
		VerifyExecutable:  verify,
		LoadCredential:    loadCredential,
		RenderConfig:      renderClientConfig,
		WriteConfigAtomic: writeConfigAtomic,
		Now:               time.Now,
		Trace:             recorder,
	}
	controller := agent.NewController(bootstrap.Policy, network, process, agent.WithDependencies(dependencies))
	handler := &serviceHandler{
		controller: controller,
		pipe:       agent.NewPipeServer(controller, agent.WithTraceSource(recorder)),
		trace:      recorder,
	}
	keepRecorder = true
	return handler, nil
}

func loadCredential(ctx context.Context, reference accessmodel.CredentialRef) (agent.Credential, error) {
	select {
	case <-ctx.Done():
		return agent.Credential{}, ctx.Err()
	default:
	}
	plaintext, err := secret.LoadMachine(reference.Path)
	if err != nil {
		return agent.Credential{}, err
	}
	defer clear(plaintext)
	var encoded encryptedCredential
	if err := json.Unmarshal(plaintext, &encoded); err != nil {
		return agent.Credential{}, err
	}
	password := []byte(encoded.Password)
	return agent.Credential{Method: encoded.Method, Password: password, ExpiresAt: encoded.ExpiresAt}, nil
}

func renderClientConfig(policy accessmodel.Policy, credential agent.Credential) ([]byte, error) {
	nodes := append([]accessmodel.Node(nil), policy.Nodes...)
	sort.Slice(nodes, func(left, right int) bool {
		if nodes[left].Priority == nodes[right].Priority {
			return nodes[left].ID < nodes[right].ID
		}
		return nodes[left].Priority < nodes[right].Priority
	})
	if len(nodes) == 0 {
		return nil, errors.New("no node is configured")
	}
	return singconfig.RenderClient(singconfig.ClientInput{
		Node:             nodes[0],
		CorporateCIDRs:   policy.CorporateCIDRs,
		CorporateDNS:     policy.CorporateDNS,
		InternalSuffixes: policy.InternalSuffixes,
	})
}

func writeConfigAtomic(path string, contents []byte) error {
	return runtimeowner.Publish(path, func(temporaryPath string) error {
		temporary, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		closed := false
		defer func() {
			if !closed {
				_ = temporary.Close()
			}
		}()
		if err := temporary.Chmod(0o600); err != nil {
			return err
		}
		if _, err := temporary.Write(contents); err != nil {
			return err
		}
		if err := temporary.Sync(); err != nil {
			return err
		}
		if err := temporary.Close(); err != nil {
			return err
		}
		closed = true
		return nil
	})
}

type supervisedCore struct {
	verifyExecutable func(string) error
}

type supervisedProcessInstance struct {
	process *supervisor.Process
	done    chan agent.ProcessTermination
}

func (s *supervisedCore) Start(ctx context.Context, executable, config string) (agent.ProcessInstance, agent.ProcessStartResult) {
	process := &supervisor.Process{
		ReadyTimeout:     10 * time.Second,
		StopTimeout:      3 * time.Second,
		LogWriter:        io.Discard,
		MaxLogBytes:      64 * 1024,
		VerifyExecutable: s.verifyExecutable,
	}
	instance := &supervisedProcessInstance{process: process, done: make(chan agent.ProcessTermination, 1)}
	// supervisor.Process invokes VerifyExecutable inside its suspended-launch
	// boundary immediately before CreateProcess.
	if err := process.Start(ctx, executable, config); err != nil {
		return instance, agent.ProcessStartResult{Err: err, TerminationProven: process.TerminationProven()}
	}
	go func() {
		err := process.Wait()
		instance.done <- agent.ProcessTermination{Err: err, Proven: process.TerminationProven()}
	}()
	return instance, agent.ProcessStartResult{}
}

func (s *supervisedProcessInstance) Ready(ctx context.Context) error {
	return s.process.Ready(ctx)
}

func (s *supervisedProcessInstance) Stop(ctx context.Context) agent.ProcessTermination {
	err := s.process.Stop(ctx)
	return agent.ProcessTermination{Err: err, Proven: s.process.TerminationProven()}
}

func (s *supervisedProcessInstance) Done() <-chan agent.ProcessTermination { return s.done }

func clear(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
