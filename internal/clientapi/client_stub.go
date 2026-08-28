//go:build !windows

package clientapi

import (
	"context"
	"fmt"
	"net"
)

func defaultDialPipe(context.Context, string) (net.Conn, error) {
	return nil, fmt.Errorf("%w: named pipes require Windows", ErrServiceUnavailable)
}
