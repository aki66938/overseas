package lineprobe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLargeResponseHeadersRemainBounded(t *testing.T) {
	for _, size := range []int{26 * 1024, 80 * 1024} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Large", strings.Repeat("x", size))
			w.WriteHeader(200)
		}))
		p := NewProber(nil, nil)
		p.transport.(*http.Transport).TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		got := p.Probe(context.Background(), Target{ID: "gemini", URL: server.URL})
		server.Close()
		if got.Reachable != (size < 64*1024) {
			t.Fatalf("header bytes=%d result=%+v", size, got)
		}
	}
}

func TestPrematureHEADCloseFallsBackToGET(t *testing.T) {
	for _, early := range []error{io.EOF, io.ErrUnexpectedEOF} {
		calls := 0
		body := &countBody{}
		var deadline context.Context
		p := NewProber(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				deadline = r.Context()
				if r.Method != "HEAD" {
					t.Fatal(r.Method)
				}
				return nil, early
			}
			if r.Method != "GET" || r.Context() != deadline {
				t.Fatal("fallback changed method budget")
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
		}), nil)
		got := p.Probe(context.Background(), Target{ID: "gemini", URL: "https://gemini.google.com/"})
		if !got.Reachable || got.ErrorCode != "" || calls != 2 || body.n != 0 {
			t.Fatalf("result=%+v calls=%d body=%d", got, calls, body.n)
		}
	}
}

func TestRepeatedPrematureCloseStillFails(t *testing.T) {
	calls := 0
	p := NewProber(roundTripFunc(func(r *http.Request) (*http.Response, error) { calls++; return nil, io.EOF }), nil)
	got := p.Probe(context.Background(), Target{ID: "gemini", URL: "https://gemini.google.com/"})
	if got.Reachable || got.ErrorCode != "network_error" || calls != 2 {
		t.Fatalf("result=%+v calls=%d", got, calls)
	}
}
