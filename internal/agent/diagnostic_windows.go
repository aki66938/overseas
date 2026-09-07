//go:build windows

package agent

import (
	"net"
	"runtime"

	"golang.org/x/sys/windows"
)

func WithDiagnosticMode(mode diagnosticEnabler) PipeOption {
	return func(server *PipeServer) { server.diagnosticMode = mode }
}

var impersonatePipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// pipeAdministrator must run AFTER the bounded request read: Windows uses
// the identity associated with the last message read from this exact pipe.
func pipeAdministrator(connection net.Conn) bool {
	fd, ok := connection.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	if impersonatePipeClient.Find() != nil {
		return false
	}
	result := make(chan bool)
	go func() {
		runtime.LockOSThread()
		r, _, _ := impersonatePipeClient.Call(fd.Fd())
		if r == 0 {
			runtime.UnlockOSThread()
			result <- false
			return
		}
		member := false
		var token windows.Token
		if windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token) == nil {
			sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
			if err == nil {
				member, err = token.IsMember(sid)
				member = member && err == nil
			}
			if token.Close() != nil {
				member = false
			}
		}
		if windows.RevertToSelf() != nil {
			// Never return this impersonated thread to Go's pool. This dedicated
			// goroutine exits still locked; Go terminates its OS thread. Rejecting
			// this request leaves the tunnel service alive to perform recovery.
			result <- false
			return
		}
		runtime.UnlockOSThread()
		result <- member
	}()
	return <-result
}
