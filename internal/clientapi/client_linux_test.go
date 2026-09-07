//go:build linux

package clientapi

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestLinuxV1UsesFixedSocketEndpoint(t *testing.T) {
	for _, action := range []string{"status", "diagnostic-enable"} {
		path := ""
		dial := func(_ context.Context, p string) (net.Conn, error) { path = p; return nil, errors.New("offline") }
		c := New(WithDialPipe(dial))
		c.dialAdminPipe = dial
		if action == "status" {
			c.StatusV1(context.Background())
		} else {
			c.DiagnosticEnableV1(context.Background(), 15)
		}
		if path != "/run/regen-access/control.sock" {
			t.Fatalf("%s endpoint=%q", action, path)
		}
	}
}
