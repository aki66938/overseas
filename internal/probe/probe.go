// Package probe runs bounded HTTPS checks against configured, approved targets.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"time"

	"corp.example/overseas-access-gateway/internal/config"
)

const (
	defaultTimeout = 10 * time.Second
	maxBodyBytes   = int64(64 * 1024)
)

// Result is the JSON-serializable evidence produced for one approved target.
type Result struct {
	TargetName  string        `json:"target_name"`
	TargetURL   string        `json:"target_url"`
	ResolvedIPs []string      `json:"resolved_ips"`
	SelectedIP  string        `json:"selected_ip"`
	TCPLatency  time.Duration `json:"tcp_latency"`
	TLSStatus   string        `json:"tls_status"`
	HTTPStatus  int           `json:"http_status"`
	Bytes       int64         `json:"bytes"`
	StartedAt   time.Time     `json:"started_at"`
	FinishedAt  time.Time     `json:"finished_at"`
	ErrorCode   string        `json:"error_code,omitempty"`
}

// Artifact binds one complete approved-target probe interval to a PoC run.
type Artifact struct {
	SchemaVersion int       `json:"schema_version"`
	RunID         string    `json:"run_id"`
	ConfigDigest  string    `json:"config_digest"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Results       []Result  `json:"results"`
}

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)

type dialFunc func(context.Context, string, string) (net.Conn, error)

// dialerFactory receives the requested source IP so every dial path can bind
// to it. It must not introduce an unbound fallback dial.
type dialerFactory func(time.Duration, net.IP) dialFunc

// Run checks target using source when it is non-nil. The context deadline
// bounds DNS, TCP, TLS, and HTTP work and is also used as the TCP dial timeout.
func Run(ctx context.Context, target config.Target, source net.IP) Result {
	return run(ctx, target, source, defaultTimeout, net.DefaultResolver.LookupNetIP, defaultDialerFactory, nil)
}

func run(
	ctx context.Context,
	target config.Target,
	source net.IP,
	timeout time.Duration,
	lookup lookupFunc,
	makeDialer dialerFactory,
	tlsConfig *tls.Config,
) (result Result) {
	ctx, cancel := contextWithTimeoutIfMissing(ctx, timeout)
	defer cancel()

	result.TargetName = target.Name
	result.TargetURL = target.URL
	result.TLSStatus = "not_attempted"
	result.StartedAt = time.Now().UTC()
	defer func() { result.FinishedAt = time.Now().UTC() }()

	if err := ctx.Err(); err != nil {
		result.ErrorCode = contextErrorCode(err)
		return result
	}

	parsed, err := url.Parse(target.URL)
	if err != nil || parsed.Hostname() == "" {
		result.ErrorCode = "dns_failed"
		return result
	}

	ips, err := lookup(ctx, "ip", parsed.Hostname())
	if err != nil || len(ips) == 0 {
		result.ErrorCode = errorCodeForContext(ctx, "dns_failed")
		return result
	}
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
	}
	if len(result.ResolvedIPs) == 0 {
		result.ErrorCode = "dns_failed"
		return result
	}
	result.SelectedIP = result.ResolvedIPs[0]

	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	selectedAddress := net.JoinHostPort(result.SelectedIP, port)
	dialTimeout := timeout
	if deadline, ok := ctx.Deadline(); ok {
		dialTimeout = time.Until(deadline)
	}
	dial := makeDialer(dialTimeout, source)

	configuredTLS := tlsConfig
	if configuredTLS == nil {
		configuredTLS = &tls.Config{}
	} else {
		configuredTLS = configuredTLS.Clone()
	}
	if configuredTLS.MinVersion < tls.VersionTLS12 {
		configuredTLS.MinVersion = tls.VersionTLS12
	}

	var tlsErr error
	transport := &http.Transport{
		TLSClientConfig: configuredTLS,
		DialContext: func(callCtx context.Context, network, _ string) (net.Conn, error) {
			started := time.Now()
			conn, dialErr := dial(callCtx, network, selectedAddress)
			if dialErr == nil {
				result.TCPLatency = time.Since(started)
				if result.TCPLatency <= 0 {
					// A successful loopback dial can complete within one clock
					// tick on Windows. Preserve the positive-duration result
					// invariant without pretending to have finer measurement.
					result.TCPLatency = time.Nanosecond
				}
			}
			return conn, dialErr
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		result.ErrorCode = "dns_failed"
		return result
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		TLSHandshakeDone: func(_ tls.ConnectionState, handshakeErr error) {
			tlsErr = handshakeErr
			if handshakeErr == nil {
				result.TLSStatus = "validated"
			} else {
				result.TLSStatus = "failed"
			}
		},
	}))

	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			result.ErrorCode = contextErrorCode(ctx.Err())
		} else if tlsErr != nil {
			result.ErrorCode = "tls_failed"
		} else {
			result.ErrorCode = "tcp_failed"
		}
		return result
	}
	defer response.Body.Close()

	result.HTTPStatus = response.StatusCode
	result.Bytes, err = io.Copy(io.Discard, io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		result.ErrorCode = errorCodeForContext(ctx, "body_failed")
		return result
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		result.ErrorCode = "http_rejected"
	}
	return result
}

func contextWithTimeoutIfMissing(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func defaultDialerFactory(timeout time.Duration, source net.IP) dialFunc {
	dialer := net.Dialer{Timeout: timeout}
	if source != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: append(net.IP(nil), source...)}
	}
	return dialer.DialContext
}

func errorCodeForContext(ctx context.Context, fallback string) string {
	if err := ctx.Err(); err != nil {
		return contextErrorCode(err)
	}
	return fallback
}

func contextErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "context_deadline"
	}
	return "tcp_failed"
}
