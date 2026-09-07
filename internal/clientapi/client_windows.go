//go:build windows

package clientapi

import (
	"context"
	"corp.example/overseas-access-gateway/internal/agent"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const controlEndpoint = agent.PipeName

func defaultDialPipe(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}

func defaultDialAdminPipe(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeAccessImpLevel(ctx, path, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}
