//go:build linux

package linux

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/localapi"
	"golang.org/x/sys/unix"
)

const SocketPath = "/run/regen-access/control.sock"

type localDispatcher interface {
	Dispatch(context.Context, localapi.Request, bool) localapi.Response
}
type SocketServer struct {
	listener *net.UnixListener
	path     string
	identity os.FileInfo
	handler  localDispatcher
}

// NewSocketServer requires systemd's root-owned RuntimeDirectory to exist.
// Existing sockets are never unlinked: a stopped service must clean its own
// socket or an administrator must inspect the stale path before retrying.
func NewSocketServer(handler localDispatcher) (*SocketServer, error) {
	group, err := user.LookupGroup("regen-access")
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return nil, err
	}
	return newSocketServer(SocketPath, gid, handler)
}

func socketParent(path string, gid int) error {
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(dir, &stat); err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || int(stat.Gid) != gid || info.Mode().Perm() != 0750 {
		return errors.New("unsafe runtime directory")
	}
	return nil
}

func newSocketServer(path string, gid int, handler localDispatcher) (*SocketServer, error) {
	if os.Geteuid() != 0 || handler == nil {
		return nil, errors.New("socket service requires root and handler")
	}
	if err := socketParent(path, gid); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return nil, errors.New("socket path already exists or cannot be inspected")
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return nil, err
	}
	identity, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			removeSocket(path, identity)
		}
	}()
	if err = os.Chown(path, 0, gid); err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0660); err != nil {
		return nil, err
	}
	if err = unix.Listen(fd, 16); err != nil {
		return nil, err
	}
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "control.sock")
	listener, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return nil, err
	}
	native, ok := listener.(*net.UnixListener)
	if !ok {
		listener.Close()
		return nil, errors.New("unexpected socket listener")
	}
	native.SetUnlinkOnClose(false)
	success = true
	return &SocketServer{listener: native, path: path, identity: identity, handler: handler}, nil
}

func removeSocket(path string, identity os.FileInfo) {
	if current, err := os.Lstat(path); err == nil && os.SameFile(current, identity) {
		os.Remove(path)
	}
}

func (s *SocketServer) Serve(ctx context.Context) error {
	defer s.listener.Close()
	defer removeSocket(s.path, s.identity)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var clients sync.WaitGroup
	defer clients.Wait()
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			s.listener.Close()
		case <-stopped:
		}
	}()
	slots := make(chan struct{}, 16)
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			cancel()
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		clients.Add(1)
		go func() { defer clients.Done(); defer func() { <-slots }(); s.serveConnection(ctx, conn) }()
	}
}

func (s *SocketServer) serveConnection(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(agent.PipeOperationTimeout)); err != nil {
		return
	}
	peer, err := socketPeer(conn)
	if err != nil {
		return
	}
	frame, err := bufio.NewReader(io.LimitReader(conn, localapi.MaxFrameBytes+1)).ReadBytes('\n')
	if err != nil || len(frame) > localapi.MaxFrameBytes {
		return
	}
	request, err := localapi.DecodeRequest(frame)
	if err != nil {
		return
	}
	budget := agent.PipeTimeoutForAction(request.Action)
	if err := conn.SetDeadline(time.Now().Add(budget)); err != nil {
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	response := s.handler.Dispatch(requestCtx, request, peer.Uid == 0)
	encoded, err := localapi.EncodeResponse(response)
	if err != nil {
		return
	}
	conn.SetWriteDeadline(time.Now().Add(agent.PipeOperationTimeout))
	conn.Write(encoded)
}

func socketPeer(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *unix.Ucred
	var credErr error
	if err = raw.Control(func(fd uintptr) { peer, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, err
	}
	return peer, credErr
}

// DialSocket authenticates the service before sending any local API request.
func DialSocket(ctx context.Context) (net.Conn, error) {
	group, err := user.LookupGroup("regen-access")
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return nil, err
	}
	if err := socketParent(SocketPath, gid); err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(SocketPath, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != 0 || int(stat.Gid) != gid || stat.Mode&0777 != 0660 {
		return nil, errors.New("unsafe service socket")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return nil, err
	}
	peer, err := socketPeer(conn.(*net.UnixConn))
	if err != nil || peer.Uid != 0 {
		conn.Close()
		return nil, errors.New("service peer is not root")
	}
	return conn, nil
}
