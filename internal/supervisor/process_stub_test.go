//go:build !windows

package supervisor

import (
	"context"
	"errors"
	"testing"
)

func TestProcessIsUnsupported(t *testing.T) {
	p := Process{VerifyExecutable: func(string) error { return nil }}
	if err := p.Start(context.Background(), "/bin/false", "/tmp/config"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Start error = %v, want ErrUnsupported", err)
	}
	if err := p.Ready(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Ready error = %v, want ErrUnsupported", err)
	}
	if err := p.Stop(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Stop error = %v, want ErrUnsupported", err)
	}
	if err := p.Wait(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Wait error = %v, want ErrUnsupported", err)
	}
}
