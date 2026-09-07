//go:build linux

package linux

import (
	"bufio"
	"context"
	"corp.example/overseas-access-gateway/internal/localapi"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type socketHandler struct{ admin chan bool }

func (h *socketHandler) Dispatch(_ context.Context, r localapi.Request, admin bool) localapi.Response {
	h.admin <- admin
	code := ""
	if r.Action == localapi.ActionDiagnosticEnable && !admin {
		code = "permission_denied"
	}
	return localapi.Response{Version: 1, ID: r.ID, Status: localapi.Status{State: "idle", Quality: "unknown"}, ErrorCode: code}
}

func TestSocketFixedPeerAndOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private root-owned socket fixture requires uid0")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	h := &socketHandler{admin: make(chan bool, 1)}
	s, err := newSocketServer(path, os.Getgid(), h)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("socket shutdown hung")
		}
	}()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write([]byte("{\"version\":1,\"id\":\"test\",\"action\":\"status\"}\n"))
	frame, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localapi.DecodeResponse(frame, "test"); err != nil {
		t.Fatal(err)
	}
	if !<-h.admin {
		t.Fatal("root peer not authenticated")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		t.Fatalf("socket mode=%v", info.Mode())
	}
}

func TestSocketRejectsUnsafeParentAndExistingPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private root-owned socket fixture requires uid0")
	}
	for _, kind := range []string{"writable-parent", "file", "symlink", "live-socket"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			os.Chmod(dir, 0750)
			path := filepath.Join(dir, "control.sock")
			switch kind {
			case "writable-parent":
				os.Chmod(dir, 0777)
			case "file":
				os.WriteFile(path, []byte("foreign"), 0600)
			case "symlink":
				os.Symlink("foreign", path)
			case "live-socket":
				l, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
			}
			s, err := newSocketServer(path, os.Getgid(), &socketHandler{admin: make(chan bool, 1)})
			if err == nil {
				s.listener.Close()
				t.Fatal("unsafe socket accepted")
			}
			if kind != "writable-parent" {
				if _, err := os.Lstat(path); err != nil {
					t.Fatalf("foreign path removed: %v", err)
				}
			}
		})
	}
}
