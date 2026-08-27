package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/config"
)

func TestRunSuccessfulHTTPSProbe(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "approved target reached")
	}))
	defer server.Close()

	result := run(contextWithDeadline(t), targetFor(server), nil, localResolver, dialServer(server), trustedTLSConfig(t, server))

	if result.ErrorCode != "" {
		t.Fatalf("ErrorCode = %q, want empty", result.ErrorCode)
	}
	if result.TargetName != "operator-approved-test" {
		t.Fatalf("TargetName = %q", result.TargetName)
	}
	if len(result.ResolvedIPs) != 1 || result.ResolvedIPs[0] != "127.0.0.1" {
		t.Fatalf("ResolvedIPs = %v, want loopback", result.ResolvedIPs)
	}
	if result.SelectedIP != "127.0.0.1" {
		t.Fatalf("SelectedIP = %q, want loopback", result.SelectedIP)
	}
	if result.TCPLatency <= 0 {
		t.Fatalf("TCPLatency = %s, want positive", result.TCPLatency)
	}
	if result.TLSStatus != "validated" {
		t.Fatalf("TLSStatus = %q, want validated", result.TLSStatus)
	}
	if result.HTTPStatus != http.StatusOK {
		t.Fatalf("HTTPStatus = %d, want 200", result.HTTPStatus)
	}
	if result.Bytes != int64(len("approved target reached")) {
		t.Fatalf("Bytes = %d, want response body size", result.Bytes)
	}
	if result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		t.Fatalf("invalid timestamps: start=%s finish=%s", result.StartedAt, result.FinishedAt)
	}
}

func TestRunReportsDNSFailure(t *testing.T) {
	result := run(contextWithDeadline(t), config.Target{Name: "operator-approved-test", URL: "https://approved.example.invalid/"}, nil,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("resolver unavailable")
		},
		nil,
		nil,
	)

	if result.ErrorCode != "dns_failed" {
		t.Fatalf("ErrorCode = %q, want dns_failed", result.ErrorCode)
	}
}

func TestRunReportsTCPFailure(t *testing.T) {
	result := run(contextWithDeadline(t), config.Target{Name: "operator-approved-test", URL: "https://approved.example.invalid/"}, nil,
		localResolver,
		func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connect timeout") },
		nil,
	)

	if result.ErrorCode != "tcp_failed" {
		t.Fatalf("ErrorCode = %q, want tcp_failed", result.ErrorCode)
	}
}

func TestRunReportsTLSValidationFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer server.Close()

	result := run(contextWithDeadline(t), targetFor(server), nil, localResolver, dialServer(server), nil)

	if result.ErrorCode != "tls_failed" {
		t.Fatalf("ErrorCode = %q, want tls_failed", result.ErrorCode)
	}
	if result.TLSStatus != "failed" {
		t.Fatalf("TLSStatus = %q, want failed", result.TLSStatus)
	}
}

func TestRunReportsRejectedHTTPStatusWithoutFollowingRedirect(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/not-approved", http.StatusFound)
			return
		}
	}))
	defer server.Close()

	result := run(contextWithDeadline(t), targetFor(server), nil, localResolver, dialServer(server), trustedTLSConfig(t, server))

	if result.ErrorCode != "http_rejected" {
		t.Fatalf("ErrorCode = %q, want http_rejected", result.ErrorCode)
	}
	if result.HTTPStatus != http.StatusFound {
		t.Fatalf("HTTPStatus = %d, want 302", result.HTTPStatus)
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want redirect disabled", requests)
	}
}

func TestRunCapsResponseBodyAt64KiB(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 70*1024))
	}))
	defer server.Close()

	result := run(contextWithDeadline(t), targetFor(server), nil, localResolver, dialServer(server), trustedTLSConfig(t, server))

	if result.ErrorCode != "" {
		t.Fatalf("ErrorCode = %q, want empty", result.ErrorCode)
	}
	if result.Bytes != 64*1024 {
		t.Fatalf("Bytes = %d, want 65536", result.Bytes)
	}
}

func contextWithDeadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}

func targetFor(server *httptest.Server) config.Target {
	return config.Target{Name: "operator-approved-test", URL: server.URL}
}

func localResolver(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func dialServer(server *httptest.Server) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, network, _ string) (net.Conn, error) {
		return net.Dial(network, server.Listener.Addr().String())
	}
}

func trustedTLSConfig(t *testing.T, server *httptest.Server) *tls.Config {
	t.Helper()
	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("TLS server client did not provide a TLS configuration")
	}
	return transport.TLSClientConfig.Clone()
}
