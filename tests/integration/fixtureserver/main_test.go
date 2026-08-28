package main

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSentinelReturnsNonceBoundIdentityReceipt(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- serveReceipt(server, "public/1", "") }()
	if err := json.NewEncoder(client).Encode(map[string]string{"nonce": "nonce-1"}); err != nil {
		t.Fatal(err)
	}
	var response receipt
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if response.Nonce != "nonce-1" || response.Identity != "public/1" || response.ViaFakeUpstream != "" {
		t.Fatalf("receipt = %#v", response)
	}
}

func TestPublicDataAndHealthListenersShareOneFailureDomain(t *testing.T) {
	data := listenLocal(t)
	health := listenLocal(t)
	done := make(chan error, 1)
	go func() { done <- serveSentinelListeners(data, health, "public/1") }()
	for _, endpoint := range []string{data.Addr().String(), health.Addr().String()} {
		connection, err := net.DialTimeout("tcp4", endpoint, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(connection).Encode(map[string]string{"nonce": "pair-nonce"}); err != nil {
			t.Fatal(err)
		}
		var response receipt
		if err := json.NewDecoder(connection).Decode(&response); err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
		if response.Identity != "public/1" || response.Nonce != "pair-nonce" {
			t.Fatalf("receipt = %#v", response)
		}
	}
	_ = data.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("data-listener failure did not terminate paired health listener")
	}
	if connection, err := net.DialTimeout("tcp4", health.Addr().String(), 100*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("health listener survived loss of its paired data listener")
	}
}

func TestFakeUpstreamCONNECTAddsTraversalReceipt(t *testing.T) {
	target := listenLocal(t)
	targetDone := make(chan error, 1)
	go func() {
		connection, err := target.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		targetDone <- serveReceipt(connection, "public/1", "")
	}()

	proxy := listenLocal(t)
	proxyDone := make(chan error, 1)
	go func() {
		connection, err := proxy.Accept()
		if err != nil {
			proxyDone <- err
			return
		}
		proxyDone <- serveCONNECT(connection, "fake-upstream/1", target.Addr().String())
	}()

	connection, err := net.DialTimeout("tcp", proxy.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	if _, err := connection.Write([]byte("CONNECT " + target.Addr().String() + " HTTP/1.1\r\nHost: " + target.Addr().String() + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q, %v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if err := json.NewEncoder(connection).Encode(map[string]string{"nonce": "nonce-2"}); err != nil {
		t.Fatal(err)
	}
	var response receipt
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	_ = proxy.Close()
	_ = target.Close()
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	if response.Nonce != "nonce-2" || response.Identity != "public/1" || response.ViaFakeUpstream != "fake-upstream/1" {
		t.Fatalf("receipt = %#v", response)
	}
}

func TestFakeUpstreamRefusesUnapprovedCONNECTTarget(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- serveCONNECT(server, "fake-upstream/1", "127.0.0.1:18080") }()
	_, _ = client.Write([]byte("CONNECT 127.0.0.1:18081 HTTP/1.1\r\nHost: 127.0.0.1:18081\r\n\r\n"))
	status, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.Contains(status, "403") {
		t.Fatalf("status = %q, %v", status, err)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("serveCONNECT accepted an unapproved target")
	}
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}
