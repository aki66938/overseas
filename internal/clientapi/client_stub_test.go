//go:build !windows

package clientapi

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPlatformTransportExplicitlyUnsupported(t *testing.T) {
	for name, dial := range map[string]dialPipeFunc{"ordinary": defaultDialPipe, "admin": defaultDialAdminPipe} {
		conn, err := dial(context.Background(), "unused")
		if conn != nil || !errors.Is(err, ErrServiceUnavailable) || !strings.Contains(err.Error(), "require Windows") {
			t.Errorf("%s transport = %v, %v; want unsupported service", name, conn, err)
		}
	}
}
