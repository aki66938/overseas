//go:build darwin

package clientapi

import (
	"context"
	"net"

	darwinplatform "corp.example/overseas-access-gateway/internal/platform/darwin"
)

const controlEndpoint = darwinplatform.SocketPath

func defaultDialPipe(ctx context.Context, _ string) (net.Conn, error) {
	return darwinplatform.DialSocket(ctx)
}

func defaultDialAdminPipe(ctx context.Context, _ string) (net.Conn, error) {
	return darwinplatform.DialSocket(ctx)
}
