//go:build windows

package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/diagnosticmode"
	"corp.example/overseas-access-gateway/internal/localapi"
	"corp.example/overseas-access-gateway/internal/traceevent"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"path/filepath"
)

func TestDiagnosticEnableAuthenticatesRealPipePeer(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := windows.Token(0).IsMember(sid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		level winio.PipeImpLevel
		want  bool
	}{
		{"anonymous rejects administrator claim", winio.PipeImpLevelAnonymous, false},
		{"identification uses actual token", winio.PipeImpLevelIdentification, admin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := diagnosticmode.New(traceevent.RecorderConfig{Directory: filepath.Join(t.TempDir(), "logs"), MemoryCapacity: 8, MaxFileBytes: 2 << 20, RetainFiles: 5})
			defer g.Close()
			server := NewPipeServer(&fakePipeController{diagnostics: Diagnostics{State: accessmodel.StatePrepared}}, WithDiagnosticMode(g))
			response := realDiagnosticTransaction(t, server, tc.level)
			if (response.ErrorCode == "") != tc.want || g.Enabled(time.Now()) != tc.want {
				t.Fatalf("admin=%v response=%+v enabled=%v", admin, response, g.Enabled(time.Now()))
			}
			if !tc.want && response.ErrorCode != "permission_denied" {
				t.Fatalf("error=%q", response.ErrorCode)
			}
		})
	}
	t.Logf("actual enabled administrator membership: %v", admin)
}

func realDiagnosticTransaction(t *testing.T, server *PipeServer, level winio.PipeImpLevel) localapi.Response {
	t.Helper()
	path := fmt.Sprintf(`\\.\pipe\regen-diagnostic-test-%x`, rand.Text())
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: PipeSecurityDescriptor})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			server.serveConnection(connection)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := winio.DialPipeAccessImpLevel(ctx, path, windows.GENERIC_READ|windows.GENERIC_WRITE, level)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = connection.Write([]byte("{\"version\":1,\"id\":\"admin-test\",\"action\":\"diagnostic-enable\",\"duration_minutes\":15,\"administrator\":true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	response, err := localapi.DecodeResponse(frame, "admin-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return response
}

func TestDiagnosticEnableRejectsUnverifiableTransport(t *testing.T) {
	server := NewPipeServer(&fakePipeController{diagnostics: Diagnostics{State: accessmodel.StatePrepared}})
	frame, ok := rawVersionedPipeLine(t, server, []byte("{\"version\":1,\"id\":\"unverified\",\"action\":\"diagnostic-enable\",\"duration_minutes\":15}\n"))
	if !ok {
		t.Fatal("no response")
	}
	response, err := localapi.DecodeResponse(frame, "unverified")
	if err != nil || response.ErrorCode != "permission_denied" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}

func TestDiagnosticEnableRejectsDenyOnlyAdministratorToken(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	disable := windows.SIDAndAttributes{Sid: sid}
	var original windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &original); err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	var restricted windows.Token
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	r, _, err := proc.Call(uintptr(original), 0, 1, uintptr(unsafe.Pointer(&disable)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		t.Fatal(err)
	}
	defer restricted.Close()
	var token windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	runtime.LockOSThread()
	if err := windows.SetThreadToken(nil, token); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			t.Errorf("revert failed: %v", err)
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
	}()
	member, err := windows.Token(0).IsMember(sid)
	if err != nil || member {
		t.Fatalf("restricted membership=%v err=%v", member, err)
	}
	server := NewPipeServer(&fakePipeController{diagnostics: Diagnostics{State: accessmodel.StatePrepared}})
	response := realDiagnosticTransaction(t, server, winio.PipeImpLevelIdentification)
	if response.ErrorCode != "permission_denied" {
		t.Fatalf("deny-only token accepted: %+v", response)
	}
}
