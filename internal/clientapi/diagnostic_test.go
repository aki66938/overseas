package clientapi

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"corp.example/overseas-access-gateway/internal/localapi"
)

func TestDiagnosticEnableV1UsesAdministratorDialAndValidatesDuration(t *testing.T) {
	called := false
	c := New(WithDialPipe(func(context.Context, string) (net.Conn, error) { t.Fatal("used anonymous dialer"); return nil, nil }))
	c.dialAdminPipe = func(context.Context, string) (net.Conn, error) {
		called = true
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			var request localapi.Request
			if err := json.NewDecoder(server).Decode(&request); err != nil {
				return
			}
			if request.Action != localapi.ActionDiagnosticEnable || request.DurationMinutes != 30 {
				t.Errorf("request=%+v", request)
			}
			json.NewEncoder(server).Encode(localapi.Response{Version: 1, ID: request.ID, Status: localapi.Status{State: localapi.StateIdle, Quality: localapi.QualityUnknown}})
		}()
		return client, nil
	}
	if err := c.DiagnosticEnableV1(context.Background(), 16); err == nil || called {
		t.Fatal("invalid duration dialed")
	}
	if err := c.DiagnosticEnableV1(context.Background(), 30); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("administrator dialer unused")
	}
}
