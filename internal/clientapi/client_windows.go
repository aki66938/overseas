//go:build windows

package clientapi

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

func defaultDialPipe(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}
