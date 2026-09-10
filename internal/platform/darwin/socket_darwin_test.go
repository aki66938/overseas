//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/localapi"
)

type recordingHandler struct{ administrator chan bool }

func (h *recordingHandler) Dispatch(_ context.Context, request localapi.Request, administrator bool) localapi.Response {
	h.administrator <- administrator
	errorCode := ""
	if request.Action == localapi.ActionDiagnosticEnable && !administrator {
		errorCode = "permission_denied"
	}
	return localapi.Response{Version: localapi.Version, ID: request.ID, ErrorCode: errorCode,
		Status: localapi.Status{State: localapi.StateIdle, Quality: localapi.QualityUnknown}}
}

func TestNewSocketServerRejectsInvalidOwnerUID(t *testing.T) {
	for _, uid := range []int{-1, 0, 1, 499, 500, 987654, 4294967294} {
		if server, err := NewSocketServer(&recordingHandler{make(chan bool, 1)}, uid); err == nil {
			server.listener.Close()
			t.Fatalf("owner UID %d accepted", uid)
		}
	}
}

func TestValidateOwnerUIDUsesDarwinAccountDatabase(t *testing.T) {
	uid := os.Getuid()
	if uid < 501 {
		t.Skip("regular Darwin login account required")
	}
	if err := validateOwnerUID(uid); err != nil {
		t.Fatalf("current regular account rejected: %v", err)
	}
	for _, invalid := range []int{987654, 4294967294} {
		if err := validateOwnerUID(invalid); err == nil {
			t.Fatalf("invalid or reserved UID %d accepted", invalid)
		}
	}
}

func TestSocketCredentialHelper(t *testing.T) {
	path := os.Getenv("REGEN_ACCESS_TEST_SOCKET")
	if path == "" {
		return
	}
	conn, err := net.Dial("unix", path)
	if os.Getenv("REGEN_ACCESS_EXPECT_DENIED") == "1" {
		if err == nil {
			conn.Close()
			t.Fatal("non-owner connected to private socket")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("REGEN_ACCESS_EXPECT_PEER_REJECT") == "1" {
		if _, err := conn.Write([]byte("{\"version\":1,\"id\":\"intruder\",\"action\":\"status\"}\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := bufio.NewReader(conn).ReadByte(); err == nil {
			t.Fatal("server answered unauthorized peer")
		}
		return
	}
	if _, err := conn.Write([]byte("{\"version\":1,\"id\":\"owner\",\"action\":\"status\"}\n")); err != nil {
		t.Fatal(err)
	}
	frame, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localapi.DecodeResponse(frame, "owner"); err != nil {
		t.Fatal(err)
	}
}

func TestSocketAuthenticatesOwnerAndRejectsNonOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native root fixture required for real UID subprocesses")
	}
	dir, err := os.MkdirTemp("/tmp", "regen-access-darwin-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
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
	if err := os.WriteFile(helper, contents, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	handler := &recordingHandler{make(chan bool, 1)}
	server, err := newSocketServer(path, 501, handler)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("shutdown hung")
		}
	}()

	runHelper := func(uid uint32, denied bool) {
		t.Helper()
		command := exec.Command(helper, "-test.run=^TestSocketCredentialHelper$", "-test.v")
		command.Env = append(os.Environ(), "REGEN_ACCESS_TEST_SOCKET="+path)
		if denied {
			command.Env = append(command.Env, "REGEN_ACCESS_EXPECT_DENIED=1")
		}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: 20}}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("UID %d helper: %v: %s", uid, err, output)
		}
	}
	runHelper(501, false)
	if <-handler.administrator {
		t.Fatal("owner peer authenticated as administrator")
	}
	runHelper(502, true)
}

func TestSocketRejectsNonOwnerAfterAccept(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native root fixture required for real UID subprocess")
	}
	dir, err := os.MkdirTemp("/tmp", "regen-access-darwin-post-accept-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
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
	if err := os.WriteFile(helper, contents, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	handler := &recordingHandler{make(chan bool, 1)}
	server, err := newSocketServer(path, 501, handler)
	if err != nil {
		t.Fatal(err)
	}
	// Test-only relaxation gets UID 502 past filesystem DAC so LOCAL_PEERCRED
	// rejection, rather than connect(2), is what closes the connection.
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	command := exec.Command(helper, "-test.run=^TestSocketCredentialHelper$", "-test.v")
	command.Env = append(os.Environ(), "REGEN_ACCESS_TEST_SOCKET="+path, "REGEN_ACCESS_EXPECT_PEER_REJECT=1")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 502, Gid: 20}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("UID 502 helper: %v: %s", err, output)
	}
	select {
	case <-handler.administrator:
		t.Fatal("non-owner request reached handler")
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown hung")
	}
}

func TestSocketRejectsUnsafeParentAndExistingPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native root fixture required")
	}
	for _, kind := range []string{"writable-parent", "file", "symlink", "live-socket"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "control.sock")
			switch kind {
			case "writable-parent":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("foreign", path); err != nil {
					t.Fatal(err)
				}
			case "live-socket":
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			}
			server, err := newSocketServer(path, 501, &recordingHandler{make(chan bool, 1)})
			if err == nil {
				server.listener.Close()
				t.Fatal("unsafe path accepted")
			}
			if kind != "writable-parent" {
				if _, err := os.Lstat(path); err != nil {
					t.Fatalf("foreign path removed: %v", err)
				}
			}
		})
	}
}

func TestRootSocketRoundTripAndOwnedCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native root fixture required")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	handler := &recordingHandler{make(chan bool, 1)}
	server, err := newSocketServer(path, 501, handler)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode %v", info.Mode())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	conn, err := dialSocket(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("{\"version\":1,\"id\":\"root\",\"action\":\"status\"}\n")); err != nil {
		t.Fatal(err)
	}
	frame, err := bufio.NewReader(conn).ReadBytes('\n')
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localapi.DecodeResponse(frame, "root"); err != nil {
		t.Fatal(err)
	}
	if !<-handler.administrator {
		t.Fatal("root peer was not administrative")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown hung")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("owned socket not cleaned up: %v", err)
	}
}

func TestSocketBoundsFramesAndCancelsIdleClient(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native root fixture required")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	handler := &recordingHandler{make(chan bool, 1)}
	server, err := newSocketServer(path, 501, handler)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()

	oversized, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversized.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := oversized.Write([]byte(strings.Repeat("x", localapi.MaxFrameBytes+1) + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(oversized).ReadByte(); err == nil {
		t.Fatal("oversized frame received a response")
	}
	oversized.Close()
	select {
	case <-handler.administrator:
		t.Fatal("oversized frame reached handler")
	default:
	}

	idle, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not close idle client")
	}
	idle.Close()
}
