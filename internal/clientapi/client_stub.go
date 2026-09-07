//go:build !windows

package clientapi

import (
	"context"
	"fmt"
	"net"
)

// Shared protocol decoding remains available; only this native transport
// capability is unsupported until a platform-specific adapter is supplied.
func defaultDialPipe(context.Context, string) (net.Conn, error) {
	return nil, fmt.Errorf("%w: named pipes require Windows", ErrServiceUnavailable)
}

func defaultDialAdminPipe(ctx context.Context, path string) (net.Conn, error) {
	return defaultDialPipe(ctx, path)
}
