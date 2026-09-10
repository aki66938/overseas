//go:build darwin

package darwin

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
	"strings"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/localapi"
	"golang.org/x/sys/unix"
)

const SocketPath = "/var/run/regen-access/control.sock"

type localDispatcher interface {
	Dispatch(context.Context, localapi.Request, bool) localapi.Response
}

type SocketServer struct {
	listener *net.UnixListener
	path     string
	identity os.FileInfo
	ownerUID uint32
	handler  localDispatcher
}

// NewSocketServer binds the fixed launchd socket for one non-system account.
func NewSocketServer(handler localDispatcher, ownerUID int) (*SocketServer, error) {
	return newSocketServer(SocketPath, ownerUID, handler)
}

func validateOwnerUID(ownerUID int) error {
	// Darwin reserves low IDs for system accounts and uses very high unsigned
	// IDs for identities such as nobody. The selected owner must resolve to a
	// real, ordinary local/directory-service login account.
	if ownerUID < 501 || uint64(ownerUID) > uint64(^uint32(0)>>1) {
		return errors.New("invalid socket owner UID")
	}
	account, err := user.LookupId(strconv.Itoa(ownerUID))
	if err != nil {
		return errors.New("socket owner UID does not resolve")
	}
	resolvedUID, err := strconv.Atoi(account.Uid)
	if err != nil || resolvedUID != ownerUID || account.Username == "" || strings.HasPrefix(account.Username, "_") || account.Username == "nobody" {
		return errors.New("socket owner is a system account")
	}
	return nil
}

func socketParent(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(dir, &stat); err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0755 {
		return errors.New("unsafe socket parent")
	}
	return nil
}

func newSocketServer(path string, ownerUID int, handler localDispatcher) (*SocketServer, error) {
	if err := validateOwnerUID(ownerUID); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 || handler == nil {
		return nil, errors.New("socket service requires root and handler")
	}
	if err := socketParent(path); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return nil, errors.New("socket path already exists or cannot be inspected")
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return nil, err
	}
	identity, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			removeOwnedSocket(path, identity)
		}
	}()
	if err := os.Chown(path, ownerUID, 0); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	if err := unix.Listen(fd, 16); err != nil {
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
	return &SocketServer{listener: native, path: path, identity: identity, ownerUID: uint32(ownerUID), handler: handler}, nil
}

func removeOwnedSocket(path string, identity os.FileInfo) {
	if current, err := os.Lstat(path); err == nil && os.SameFile(current, identity) {
		_ = os.Remove(path)
	}
}

func (s *SocketServer) Serve(ctx context.Context) error {
	defer s.listener.Close()
	defer removeOwnedSocket(s.path, s.identity)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var clients sync.WaitGroup
	defer clients.Wait()
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
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
			_ = conn.Close()
			continue
		}
		clients.Add(1)
		go func() { defer clients.Done(); defer func() { <-slots }(); s.serveConnection(ctx, conn) }()
	}
}

func (s *SocketServer) serveConnection(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(agent.PipeOperationTimeout)); err != nil {
		return
	}
	uid, err := socketPeerUID(conn)
	if err != nil || (uid != 0 && uid != s.ownerUID) {
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
	response := s.handler.Dispatch(requestCtx, request, uid == 0)
	encoded, err := localapi.EncodeResponse(response)
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(agent.PipeOperationTimeout))
	_, _ = conn.Write(encoded)
}

func socketPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Xucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credentialErr != nil {
		return 0, credentialErr
	}
	return credential.Uid, nil
}

// DialSocket verifies both the filesystem endpoint and the root service peer.
func DialSocket(ctx context.Context) (net.Conn, error) {
	return dialSocket(ctx, SocketPath)
}

func dialSocket(ctx context.Context, path string) (net.Conn, error) {
	if err := socketParent(path); err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return nil, err
	}
	callerUID := uint32(os.Geteuid())
	ownerIsCaller := stat.Uid == callerUID || callerUID == 0
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || validateOwnerUID(int(stat.Uid)) != nil || !ownerIsCaller || stat.Gid != 0 || stat.Mode&0777 != 0600 {
		return nil, errors.New("unsafe service socket")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	native, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, errors.New("unexpected socket connection")
	}
	peerUID, err := socketPeerUID(native)
	if err != nil || peerUID != 0 {
		conn.Close()
		return nil, errors.New("service peer is not root")
	}
	return conn, nil
}
