//go:build linux

package linux

import (
	"bufio"
	"context"
	"corp.example/overseas-access-gateway/internal/localapi"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSocketUnprivilegedHelper(t *testing.T) {
	path := os.Getenv("REGEN_ACCESS_TEST_SOCKET")
	if path == "" {
		return
	}
	for _, action := range []string{"status", "diagnostic-enable"} {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		request := "{\"version\":1,\"id\":\"ordinary\",\"action\":\"" + action + "\""
		if action == "diagnostic-enable" {
			request += ",\"duration_minutes\":15"
		}
		conn.Write([]byte(request + "}\n"))
		frame, err := bufio.NewReader(conn).ReadBytes('\n')
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		response, err := localapi.DecodeResponse(frame, "ordinary")
		if err != nil {
			t.Fatal(err)
		}
		if action == "status" && response.ErrorCode != "" {
			t.Fatal("ordinary status denied")
		}
		if action == "diagnostic-enable" && response.ErrorCode != "permission_denied" {
			t.Fatal("ordinary diagnostics allowed")
		}
	}
}

func TestSocketAuthenticatesOrdinaryGroupPeer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("uid0 required to launch unprivileged fixture")
	}
	dir, err := os.MkdirTemp("", "regen-access-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Chown(dir, 0, 65534); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "peer-test")
	if err = os.WriteFile(helper, contents, 0755); err != nil {
		t.Fatal(err)
	}
	h := &socketHandler{admin: make(chan bool, 2)}
	path := filepath.Join(dir, "control.sock")
	s, err := newSocketServer(path, 65534, h)
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
		case <-time.After(time.Second):
			t.Error("shutdown hung")
		}
	}()
	command := exec.Command(helper, "-test.run=^TestSocketUnprivilegedHelper$", "-test.v")
	command.Env = append(os.Environ(), "REGEN_ACCESS_TEST_SOCKET="+path)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ordinary peer: %v: %s", err, output)
	}
	for i := 0; i < 2; i++ {
		select {
		case admin := <-h.admin:
			if admin {
				t.Fatal("ordinary peer authenticated as root")
			}
		default:
			t.Fatal("missing authenticated request")
		}
	}
}

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
