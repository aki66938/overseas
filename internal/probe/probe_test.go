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

	result := run(contextWithDeadline(t), targetFor(server), nil, time.Second, localResolver, dialServer(server), trustedTLSConfig(t, server))

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
	result := run(contextWithDeadline(t), config.Target{Name: "operator-approved-test", URL: "https://approved.example.invalid/"}, nil, time.Second,
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
	result := run(contextWithDeadline(t), config.Target{Name: "operator-approved-test", URL: "https://approved.example.invalid/"}, nil, time.Second,
		localResolver,
		staticDialer(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connect timeout") }),
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

	result := run(contextWithDeadline(t), targetFor(server), nil, time.Second, localResolver, dialServer(server), nil)

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

	result := run(contextWithDeadline(t), targetFor(server), nil, time.Second, localResolver, dialServer(server), trustedTLSConfig(t, server))

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

	result := run(contextWithDeadline(t), targetFor(server), nil, time.Second, localResolver, dialServer(server), trustedTLSConfig(t, server))

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

func TestRunDerivesDeadlineWithoutCallerDeadlineAndDoesNotFallbackDial(t *testing.T) {
	const timeout = 20 * time.Millisecond
	var observedDeadline time.Time
	dialCalls := 0

	result := run(context.Background(), config.Target{Name: "operator-approved-test", URL: "https://approved.example.invalid/"}, net.ParseIP("127.0.0.2"), timeout,
		func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				return nil, errors.New("resolver context had no deadline")
			}
			observedDeadline = deadline
			<-ctx.Done()
			return nil, ctx.Err()
		},
		dialerFactory(func(time.Duration, net.IP) dialFunc {
			return func(context.Context, string, string) (net.Conn, error) {
				dialCalls++
				return nil, errors.New("unexpected fallback dial")
			}
		}),
		nil,
	)

	if observedDeadline.IsZero() {
		t.Fatal("resolver did not receive a derived deadline")
	}
	if result.ErrorCode != "context_deadline" {
		t.Fatalf("ErrorCode = %q, want context_deadline", result.ErrorCode)
	}
	if result.StartedAt.IsZero() || result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		t.Fatalf("invalid timestamps: start=%s finish=%s", result.StartedAt, result.FinishedAt)
	}
	if dialCalls != 0 {
		t.Fatalf("dial calls = %d, want no fallback dial after deadline", dialCalls)
	}
}

func TestRunPassesAndBindsRequestedSourceIPToInjectedDialerFactory(t *testing.T) {
	serverSource := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			t.Errorf("split remote address: %v", err)
			return
		}
		serverSource <- host
		_, _ = io.WriteString(w, "approved target reached")
	}))
	defer server.Close()

	wantSource := net.ParseIP("127.0.0.2")
	var factorySource net.IP
	result := run(contextWithDeadline(t), targetFor(server), wantSource, time.Second, localResolver,
		dialerFactory(func(_ time.Duration, source net.IP) dialFunc {
			factorySource = append(net.IP(nil), source...)
			dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: source}}
			return func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, server.Listener.Addr().String())
			}
		}),
		trustedTLSConfig(t, server),
	)

	if result.ErrorCode != "" {
		t.Fatalf("ErrorCode = %q, want empty", result.ErrorCode)
	}
	if !factorySource.Equal(wantSource) {
		t.Fatalf("factory source = %v, want %v", factorySource, wantSource)
	}
	select {
	case gotSource := <-serverSource:
		if gotSource != wantSource.String() {
			t.Fatalf("server observed source = %q, want %q", gotSource, wantSource)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe a connection")
	}
}

func dialServer(server *httptest.Server) dialerFactory {
	return func(_ time.Duration, _ net.IP) dialFunc {
		return func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
	}
}

func staticDialer(dial func(context.Context, string, string) (net.Conn, error)) dialerFactory {
	return func(time.Duration, net.IP) dialFunc {
		return dial
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
