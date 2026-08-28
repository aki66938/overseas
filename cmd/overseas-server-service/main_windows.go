//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"time"

	"corp.example/overseas-access-gateway/internal/coreverify"
	"corp.example/overseas-access-gateway/internal/supervisor"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName = "RegenBioOverseasAccessServer"

	installRoot  = `C:\Program Files\RegenBio\OverseasAccessServer`
	dataRoot     = `C:\ProgramData\RegenBio\OverseasAccessServer`
	corePath     = installRoot + `\sing-box.exe`
	configPath   = dataRoot + `\config.json`
	manifestPath = dataRoot + `\runtime-manifest.json`

	serviceExitConfig    = 1
	serviceExitStart     = 2
	serviceExitReadiness = 3
	serviceExitProcess   = 4
	serviceExitCleanup   = 5

	readyAddress = "127.0.0.1:18443"
	readyTimeout = 15 * time.Second
	stopTimeout  = 20 * time.Second
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type runtimeManifest struct {
	SchemaVersion   int      `json:"schema_version"`
	Kind            string   `json:"kind"`
	SingBoxSHA256   string   `json:"sing_box_sha256"`
	SignerAllowlist []string `json:"signer_allowlist"`
}

type managedProcess interface {
	Start(context.Context) error
	Ready(context.Context) error
	Stop(context.Context) error
	Wait() error
	TerminationProven() bool
}

type serviceHandler struct {
	process managedProcess
}

func (s *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// The supervisor binds child lifetime to a cancelable Start context. The
	// service lifetime is instead controlled exclusively by SCM Stop/Shutdown.
	startErr := s.process.Start(context.Background())
	if startErr != nil {
		return s.failWithCleanup(changes, serviceExitStart)
	}

	readyContext, cancelReady := context.WithTimeout(context.Background(), readyTimeout)
	readyErr := s.process.Ready(readyContext)
	cancelReady()
	if readyErr != nil {
		return s.failWithCleanup(changes, serviceExitReadiness)
	}

	waitResult := make(chan error, 1)
	go func() { waitResult <- s.process.Wait() }()
	select {
	case <-waitResult:
		changes <- svc.Status{State: svc.StopPending}
		if !s.process.TerminationProven() {
			return true, serviceExitCleanup
		}
		return true, serviceExitProcess
	default:
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case request, ok := <-requests:
			if !ok {
				return s.stop(changes)
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			case svc.Stop, svc.Shutdown:
				return s.stop(changes)
			}
		case <-waitResult:
			changes <- svc.Status{State: svc.StopPending}
			if !s.process.TerminationProven() {
				return true, serviceExitCleanup
			}
			return true, serviceExitProcess
		}
	}
}

func (s *serviceHandler) failWithCleanup(changes chan<- svc.Status, failureCode uint32) (bool, uint32) {
	changes <- svc.Status{State: svc.StopPending}
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	err := s.process.Stop(ctx)
	cancel()
	if err != nil || !s.process.TerminationProven() {
		return true, serviceExitCleanup
	}
	return true, failureCode
}

func (s *serviceHandler) stop(changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StopPending}
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	err := s.process.Stop(ctx)
	cancel()
	if err != nil || !s.process.TerminationProven() {
		return true, serviceExitCleanup
	}
	return false, 0
}

type supervisedServer struct {
	process *supervisor.Process
}

func (s *supervisedServer) Start(ctx context.Context) error {
	return s.process.Start(ctx, corePath, configPath)
}

func (s *supervisedServer) Ready(ctx context.Context) error { return s.process.Ready(ctx) }
func (s *supervisedServer) Stop(ctx context.Context) error  { return s.process.Stop(ctx) }
func (s *supervisedServer) Wait() error                     { return s.process.Wait() }
func (s *supervisedServer) TerminationProven() bool         { return s.process.TerminationProven() }

func main() {
	process, err := buildManagedProcess()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "server service configuration is invalid")
		os.Exit(serviceExitConfig)
	}
	if err := svc.Run(serviceName, &serviceHandler{process: process}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "server service stopped unexpectedly")
		os.Exit(serviceExitProcess)
	}
}

func buildManagedProcess() (managedProcess, error) {
	manifest, err := loadRuntimeManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	verify := func(path string) error {
		if path != corePath {
			return errors.New("refusing to verify an unexpected executable path")
		}
		return coreverify.Verify(path, manifest.SingBoxSHA256, manifest.SignerAllowlist)
	}
	process := &supervisor.Process{
		ReadyTimeout:     readyTimeout,
		StopTimeout:      3 * time.Second,
		ReadyProbe:       probeServerPort,
		LogWriter:        io.Discard,
		MaxLogBytes:      64 * 1024,
		VerifyExecutable: verify,
	}
	return &supervisedServer{process: process}, nil
}

func loadRuntimeManifest(path string) (runtimeManifest, error) {
	var manifest runtimeManifest
	file, err := os.Open(path)
	if err != nil {
		return manifest, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if manifest.SchemaVersion != 1 || manifest.Kind != "RegenBioOverseasAccessServerRuntime" {
		return manifest, errors.New("unsupported server runtime manifest")
	}
	if !sha256Pattern.MatchString(manifest.SingBoxSHA256) {
		return manifest, errors.New("runtime manifest has an invalid sing-box SHA-256")
	}
	return manifest, nil
}

func probeServerPort(ctx context.Context) error {
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "tcp", readyAddress)
	if err != nil {
		return err
	}
	return connection.Close()
}
