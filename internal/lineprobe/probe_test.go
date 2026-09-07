package lineprobe

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeTLSStatusesAndNoRedirect(t *testing.T) {
	for _, status := range []int{200, 302, 403, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "HEAD" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.ContentLength > 0 {
					t.Error("request carries unexpected data")
				}
				w.Header().Set("Location", "https://redirect.invalid/")
				w.WriteHeader(status)
			}))
			defer server.Close()
			p := NewProber(server.Client().Transport, time.Now)
			got := p.Probe(context.Background(), Target{ID: "google", URL: server.URL})
			wantError := ""
			if status >= 500 {
				wantError = "http_server_error"
			}
			if got.Reachable != (status < 500) || got.HTTPStatus != status || got.ErrorCode != wantError || got.CheckedAt.IsZero() || calls.Load() != 1 {
				t.Fatalf("result=%+v calls=%d", got, calls.Load())
			}
		})
	}
}

func TestProbeTLSValidationAndTimeout(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	p := NewProber(nil, time.Now)
	if got := p.Probe(context.Background(), Target{ID: "google", URL: server.URL}); got.Reachable || got.ErrorCode != "tls_error" {
		t.Fatalf("untrusted result=%+v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	p = NewProber(server.Client().Transport, time.Now)
	if got := p.Probe(ctx, Target{ID: "google", URL: server.URL}); got.Reachable || got.ErrorCode != "timeout" {
		t.Fatalf("timeout result=%+v", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type countBody struct{ n int }

func (b *countBody) Read(p []byte) (int, error) { b.n += len(p); return len(p), nil }
func (b *countBody) Close() error               { return nil }

func TestProbe405BoundedFallbackAndLatency(t *testing.T) {
	body := &countBody{}
	now := time.Unix(100, 0)
	calls := 0
	p := NewProber(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		now = now.Add(1200 * time.Millisecond)
		if calls == 1 {
			if r.Method != "HEAD" {
				t.Fatal(r.Method)
			}
			return &http.Response{StatusCode: 405, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}
		if r.Method != "GET" {
			t.Fatal(r.Method)
		}
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
	}), func() time.Time { return now })
	got := p.Probe(context.Background(), Target{ID: "google", URL: "https://www.google.com/"})
	if calls != 2 || body.n > 1024 || got.HTTPStatus != 200 || got.LatencyMS != 2400 {
		t.Fatalf("result=%+v read=%d calls=%d", got, body.n, calls)
	}
}

func TestProductionTransportAndFixedTargets(t *testing.T) {
	p := NewProber(nil, nil)
	tr := p.transport.(*http.Transport)
	if tr.Proxy != nil || !tr.DisableKeepAlives || (tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify) {
		t.Fatal("unsafe production transport")
	}
	expected := []string{"https://www.google.com/", "https://www.pinterest.com/", "https://gemini.google.com/", "https://chatgpt.com/", "https://claude.ai/"}
	targets := Targets()
	if len(targets) != 5 {
		t.Fatal(targets)
	}
	for i, target := range targets {
		if target.URL != expected[i] {
			t.Fatal(target)
		}
	}
	targets[0].URL = "changed"
	if Targets()[0].URL != expected[0] {
		t.Fatal("mutable target registry")
	}
}

func TestFallbackFailureIsNotReachable(t *testing.T) {
	calls := 0
	p := NewProber(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{StatusCode: 405, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}
		return nil, errors.New("connection failed")
	}), nil)
	got := p.Probe(context.Background(), Targets()[0])
	if got.Reachable || got.ErrorCode != "network_error" {
		t.Fatal(got)
	}
}
