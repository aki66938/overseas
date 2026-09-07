package clientapi

import (
	"bufio"
	"context"
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"corp.example/overseas-access-gateway/internal/localapi"
	"net"
	"testing"
	"time"
)

func TestProbeV1ReturnsBoundedResults(t *testing.T) {
	server, connection := net.Pipe()
	defer connection.Close()
	go func() {
		defer server.Close()
		line, _ := bufio.NewReader(server).ReadBytes('\n')
		r, _ := localapi.DecodeRequest(line)
		if r.Action != "probe" {
			t.Error(r)
		}
		frame, _ := localapi.EncodeResponse(localapi.Response{Version: 1, ID: r.ID, Status: localapi.Status{State: localapi.StateConnected, Quality: localapi.QualityGood, Generation: 2}, ProbeGeneration: 2, ProbeResults: []lineprobe.Result{{ID: "google", Reachable: true, HTTPStatus: 200, CheckedAt: time.Now()}}})
		server.Write(frame)
	}()
	client := New(WithDialPipe(func(context.Context, string) (net.Conn, error) { return connection, nil }))
	got, err := client.ProbeV1(context.Background())
	if err != nil || len(got.ProbeResults) != 1 || got.ProbeGeneration != 2 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestStatusDetailsV1ReturnsExplicitHistoricalResults(t *testing.T) {
	server, connection := net.Pipe()
	defer connection.Close()
	go func() {
		defer server.Close()
		line, _ := bufio.NewReader(server).ReadBytes('\n')
		r, _ := localapi.DecodeRequest(line)
		if r.Action != "status" {
			t.Error(r)
		}
		frame, _ := localapi.EncodeResponse(localapi.Response{Version: 1, ID: r.ID, Status: localapi.Status{State: localapi.StateIdle, Quality: localapi.QualityUnknown, Generation: 3}, ProbeGeneration: 2, ProbeHistorical: true, ProbeResults: []lineprobe.Result{{ID: "google", Reachable: true, HTTPStatus: 200, CheckedAt: time.Now()}}})
		server.Write(frame)
	}()
	client := New(WithDialPipe(func(context.Context, string) (net.Conn, error) { return connection, nil }))
	got, err := client.StatusDetailsV1(context.Background())
	if err != nil || len(got.ProbeResults) != 1 || got.ProbeGeneration != 2 || !got.ProbeHistorical {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestNewStatusClientSeesAuthoritativeFailureCount(t *testing.T) {
	server, connection := net.Pipe()
	defer connection.Close()
	go func() {
		defer server.Close()
		line, _ := bufio.NewReader(server).ReadBytes('\n')
		r, _ := localapi.DecodeRequest(line)
		count := 3
		frame, _ := localapi.EncodeResponse(localapi.Response{Version: 1, ID: r.ID, Status: localapi.Status{State: localapi.StateConnected, Quality: localapi.QualityFailed, Generation: 2}, ProbeGeneration: 2, ProbeResults: []lineprobe.Result{{ID: "google", ErrorCode: "timeout", CheckedAt: time.Now(), ConsecutiveFailures: &count}}})
		server.Write(frame)
	}()
	client := New(WithDialPipe(func(context.Context, string) (net.Conn, error) { return connection, nil }))
	got, err := client.StatusDetailsV1(context.Background())
	if err != nil || len(got.ProbeResults) != 1 || got.ProbeResults[0].ConsecutiveFailures == nil || *got.ProbeResults[0].ConsecutiveFailures != 3 {
		t.Fatalf("%+v %v", got, err)
	}
}
