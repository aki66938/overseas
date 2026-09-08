package lineprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type Result struct {
	ID         string    `json:"id"`
	LatencyMS  int64     `json:"latency_ms"`
	Reachable  bool      `json:"reachable"`
	HTTPStatus int       `json:"http_status"`
	ErrorCode  string    `json:"error_code,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
	// Nil means the service did not provide round history (older API response).
	// An authoritative zero is different from absent; abnormal starts at three.
	ConsecutiveFailures *int `json:"consecutive_failures,omitempty"`
}

type Prober struct {
	transport http.RoundTripper
	now       func() time.Time
}

// NewProber permits transport injection for local TLS tests. The production
// transport never uses environment proxies or pooled connections: the OS-owned
// route and DNS path are measured anew. TLS verification remains enabled.
func NewProber(transport http.RoundTripper, now func() time.Time) *Prober {
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DisableKeepAlives: true,
			DialContext:         (&net.Dialer{Timeout: RoundBudget}).DialContext,
			TLSHandshakeTimeout: RoundBudget, ResponseHeaderTimeout: RoundBudget,
			// Gemini's verified responses exceed 25 KiB. Keep a finite cap
			// without rejecting these ordinary security/cookie headers.
			MaxResponseHeaderBytes: 64 * 1024}
	}
	if now == nil {
		now = time.Now
	}
	return &Prober{transport: transport, now: now}
}

func (p *Prober) Probe(ctx context.Context, target Target) Result {
	result := Result{ID: target.ID}
	// Also bound callers outside the scheduler. The shared round context can
	// cancel earlier; fallback GET shares this same deadline.
	ctx, cancel := context.WithTimeout(ctx, RoundBudget)
	defer cancel()
	client := &http.Client{Transport: p.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		// Report the selected request's DNS-to-headers measurement, not the
		// sum of HEAD and fallback GET. Both share the outer budget.
		started := p.now()
		result.CheckedAt = started
		request, err := http.NewRequestWithContext(ctx, method, target.URL, nil)
		if err != nil || request.URL.Scheme != "https" || request.URL.User != nil {
			result.ErrorCode = "invalid_target"
			return result
		}
		request.Close = true
		response, err := client.Do(request)
		result.LatencyMS = p.now().Sub(started).Milliseconds()
		if result.LatencyMS < 0 {
			result.LatencyMS = 0
		}
		if result.LatencyMS > RoundBudget.Milliseconds() {
			result.LatencyMS = RoundBudget.Milliseconds()
		}
		if err != nil {
			// Some upstreams close HEAD without a complete response. Retry
			// once with GET, sharing the existing deadline and TLS policy.
			if method == http.MethodHead && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
				continue
			}
			result.Reachable = false
			result.ErrorCode = probeError(err)
			return result
		}
		result.Reachable = response.StatusCode >= 200 && response.StatusCode < 500
		result.HTTPStatus = response.StatusCode
		if !result.Reachable {
			result.ErrorCode = "http_server_error"
		}
		// Headers finish the measurement. Reading zero response-body bytes
		// stays within the 1024-byte cap and cannot wait on a stalled body.
		response.Body.Close()
		if response.StatusCode != http.StatusMethodNotAllowed || method == http.MethodGet {
			return result
		}
	}
	return result
}

func probeError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &cert) || errors.As(err, &unknown) {
		return "tls_error"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "timeout"
	}
	return "network_error"
}
