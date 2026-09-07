package clientapi

import (
	"context"
	"net"

	linuxplatform "corp.example/overseas-access-gateway/internal/platform/linux"
)

const controlEndpoint = linuxplatform.SocketPath

func defaultDialPipe(ctx context.Context, _ string) (net.Conn, error) {
	return linuxplatform.DialSocket(ctx)
}
func defaultDialAdminPipe(ctx context.Context, _ string) (net.Conn, error) {
	// Diagnostic authority is decided by SO_PEERCRED on the same Unix socket.
	return linuxplatform.DialSocket(ctx)
}
