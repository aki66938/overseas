//go:build windows

package supervisor

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func TestDisabledDiagnosticTailStillForwardsOutput(t *testing.T) {
	var output bytes.Buffer
	process := &Process{DisableDiagnosticTail: true, LogWriter: &output}
	process.configureOutput(1024)
	process.redactor.Write([]byte("child failure\n"))
	if process.DiagnosticTail() != "" {
		t.Fatal("disabled tail collected output")
	}
	if output.String() != "child failure\n" {
		t.Fatal("output did not reach gated destination")
	}
}

type separateOutputs struct {
	mu      sync.Mutex
	streams []*closedOutput
}
type closedOutput struct {
	bytes.Buffer
	closed bool
}

func (s *separateOutputs) Write(p []byte) (int, error) { return len(p), nil }
func (s *separateOutputs) NewOutputStream() io.Writer {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := &closedOutput{}
	s.streams = append(s.streams, w)
	return w
}
func (w *closedOutput) Close() error { w.closed = true; return nil }

func TestNativeOutputUsesSeparateStreamsAndClosesBothOnStop(t *testing.T) {
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "write-secret", "secret": "hidden"})
	output := &separateOutputs{}
	p := verifiedProcess(&Process{DisableDiagnosticTail: true, LogWriter: output, Secrets: []string{"hidden"}, ReadyTimeout: time.Second, StopTimeout: time.Second, ReadyProbe: fileProbe(ready)})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())
	if err := p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if len(output.streams) != 2 {
		t.Fatalf("got %d output streams", len(output.streams))
	}
	for i, w := range output.streams {
		if !w.closed {
			t.Fatalf("stream %d still open after Stop", i)
		}
		if bytes.Contains(w.Bytes(), []byte("hidden")) {
			t.Fatal("secret survived redaction")
		}
	}
	if !bytes.Contains(output.streams[0].Bytes(), []byte("stdout")) || bytes.Contains(output.streams[0].Bytes(), []byte("stderr")) || !bytes.Contains(output.streams[1].Bytes(), []byte("stderr")) {
		t.Fatal("stdout/stderr mixed")
	}
}

func TestNativeOutputClosesBothStreamsOnReadinessTimeout(t *testing.T) {
	cfg, ready := writeFakeConfig(t, map[string]any{"mode": "write-secret", "secret": "hidden", "suppress_ready": true})
	output := &separateOutputs{}
	p := verifiedProcess(&Process{DisableDiagnosticTail: true, LogWriter: output, ReadyTimeout: 100 * time.Millisecond, StopTimeout: 100 * time.Millisecond, ReadyProbe: fileProbe(ready)})
	if err := p.Start(context.Background(), fakeConnectEXE, cfg); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())
	if err := p.Ready(context.Background()); err == nil {
		t.Fatal("expected readiness failure")
	}
	if err := p.Wait(); err != nil {
		t.Fatal(err)
	}
	if len(output.streams) != 2 || !output.streams[0].closed || !output.streams[1].closed {
		t.Fatal("readiness failure left an output stream running")
	}
}
