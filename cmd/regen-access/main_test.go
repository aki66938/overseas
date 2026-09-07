package main

import (
	"bytes"
	"context"
	"corp.example/overseas-access-gateway/internal/clientapi"
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"corp.example/overseas-access-gateway/internal/localapi"
	"errors"
	"testing"
	"time"
)

type diagnosticClient struct {
	minutes int
	err     error
}

type commandClient struct {
	diagnosticClient
	called   string
	response localapi.Response
}

func (c *commandClient) ConnectV1(context.Context) (localapi.Status, error) {
	c.called = "connect"
	return c.response.Status, c.err
}
func (c *commandClient) DisconnectV1(context.Context) (localapi.Status, error) {
	c.called = "disconnect"
	return c.response.Status, c.err
}
func (c *commandClient) StatusDetailsV1(context.Context) (localapi.Response, error) {
	c.called = "status"
	return c.response, c.err
}
func (c *commandClient) ProbeV1(context.Context) (localapi.Response, error) {
	c.called = "probe"
	return c.response, c.err
}

func TestCommandsGolden(t *testing.T) {
	for _, action := range []string{"connect", "disconnect", "status", "probe"} {
		t.Run(action, func(t *testing.T) {
			c := &commandClient{response: localapi.Response{Status: localapi.Status{State: "connected", Quality: "good"}}}
			var out bytes.Buffer
			if code := run([]string{action}, c, &out); code != 0 || c.called != action || out.String() != "State: connected\nQuality: good\n" {
				t.Fatalf("code=%d called=%q output=%q", code, c.called, out.String())
			}
		})
	}
}

func TestCommandFailureGolden(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status localapi.Status
		want   string
	}{
		{clientapi.ErrServiceUnavailable, localapi.Status{}, "Service unavailable.\n"},
		{nil, localapi.Status{State: "needs_action", Quality: "unknown", ErrorCode: "restore_failed"}, "State: needs_action\nQuality: unknown\nError: restore_failed\n"},
		{errors.New("private path /secret"), localapi.Status{}, "Request failed.\n"},
	} {
		c := &commandClient{diagnosticClient: diagnosticClient{err: tc.err}, response: localapi.Response{Status: tc.status}}
		var out bytes.Buffer
		if code := run([]string{"connect"}, c, &out); code != 1 || out.String() != tc.want {
			t.Fatalf("code=%d output=%q want=%q", code, out.String(), tc.want)
		}
	}
}

func TestStatusDurationAndProbeGolden(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	c := &commandClient{response: localapi.Response{Status: localapi.Status{State: "connected", Quality: "slow", ConnectedAt: now.Add(-65 * time.Second).UTC().Format(time.RFC3339)}, ProbeResults: []lineprobe.Result{{ID: "google", LatencyMS: 123, Reachable: true}, {ID: "claude", ErrorCode: "timeout"}}}}
	var out bytes.Buffer
	code := runAt([]string{"status"}, c, &out, now)
	want := "State: connected\nQuality: slow\nConnected: 1m5s\ngoogle: 123 ms\nclaude: timeout\n"
	if code != 0 || out.String() != want {
		t.Fatalf("code=%d output=%q want=%q", code, out.String(), want)
	}
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
