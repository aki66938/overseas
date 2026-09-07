package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type diagnosticClient struct {
	minutes int
	err     error
}

func (c *diagnosticClient) DiagnosticEnableV1(_ context.Context, minutes int) error {
	c.minutes = minutes
	return c.err
}

func TestDiagnosticCommand(t *testing.T) {
	for _, minutes := range []string{"15", "30", "60"} {
		var out bytes.Buffer
		c := &diagnosticClient{}
		if code := run([]string{"diagnostic-enable", minutes}, c, &out); code != 0 || c.minutes == 0 {
			t.Fatalf("code=%d output=%s", code, &out)
		}
	}
	for _, args := range [][]string{nil, {"diagnostic-enable"}, {"diagnostic-enable", "16"}, {"diagnostic-disable"}, {"diagnostic-enable", "15", "--admin"}} {
		var out bytes.Buffer
		c := &diagnosticClient{}
		if code := run(args, c, &out); code == 0 || c.minutes != 0 {
			t.Fatalf("accepted %v", args)
		}
	}
	var out bytes.Buffer
	c := &diagnosticClient{err: errors.New("permission_denied")}
	if code := run([]string{"diagnostic-enable", "15"}, c, &out); code == 0 {
		t.Fatal("rejection succeeded")
	}
}
