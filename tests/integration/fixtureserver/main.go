// fixture-sentinel provides the isolated TCP sentinels and instrumented HTTP
// CONNECT upstream used by the privileged Windows integration fixture.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const connectionTimeout = 10 * time.Second

type receipt struct {
	Nonce           string `json:"nonce"`
	Identity        string `json:"identity"`
	ViaFakeUpstream string `json:"via_fake_upstream,omitempty"`
}

func main() {
	mode := flag.String("mode", "", "sentinel or fake-upstream")
	listen := flag.String("listen", "", "listener address")
	health := flag.String("health-listen", "", "paired sentinel health listener")
	control := flag.String("control-listen", "", "fake-upstream control listener")
	identity := flag.String("identity", "", "fixture identity")
	target := flag.String("target", "", "sole approved CONNECT target")
	flag.Parse()
	if flag.NArg() != 0 || *listen == "" || *identity == "" {
		os.Exit(64)
	}
	var err error
	switch *mode {
	case "sentinel":
		if *health == "" {
			os.Exit(64)
		}
		err = serveSentinelPair(*listen, *health, *identity)
	case "fake-upstream":
		if *control == "" || *target == "" {
			os.Exit(64)
		}
		err = serveFakeUpstream(*listen, *control, *identity, *target)
	default:
		os.Exit(64)
	}
	if err != nil {
		os.Exit(1)
	}
}

func serveSentinelPair(dataAddress, healthAddress, identity string) error {
	data, err := net.Listen("tcp4", dataAddress)
	if err != nil {
		return err
	}
	health, err := net.Listen("tcp4", healthAddress)
	if err != nil {
		data.Close()
		return err
	}
	return serveSentinelListeners(data, health, identity)
}

func serveSentinelListeners(data, health net.Listener, identity string) error {
	errorsChannel := make(chan error, 2)
	for _, listener := range []net.Listener{data, health} {
		current := listener
		go func() {
			errorsChannel <- acceptLoop(current, func(connection net.Conn) error { return serveReceipt(connection, identity, "") })
		}()
	}
	err := <-errorsChannel
	_ = data.Close()
	_ = health.Close()
	return err
}

func serveListener(address string, handler func(net.Conn) error) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() { _ = handler(connection) }()
	}
}

func serveFakeUpstream(listen, control, identity, target string) error {
	proxyListener, err := net.Listen("tcp4", listen)
	if err != nil {
		return err
	}
	defer proxyListener.Close()
	controlListener, err := net.Listen("tcp4", control)
	if err != nil {
		return err
	}
	defer controlListener.Close()
	errorsChannel := make(chan error, 2)
	go func() {
		errorsChannel <- acceptLoop(proxyListener, func(connection net.Conn) error { return serveCONNECT(connection, identity, target) })
	}()
	go func() {
		errorsChannel <- acceptLoop(controlListener, func(connection net.Conn) error { return serveReceipt(connection, identity, identity) })
	}()
	return <-errorsChannel
}

func acceptLoop(listener net.Listener, handler func(net.Conn) error) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() { _ = handler(connection) }()
	}
}

func serveReceipt(connection net.Conn, identity, via string) error {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(connectionTimeout))
	var request struct {
		Nonce string `json:"nonce"`
	}
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(connection, 4097)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	if request.Nonce == "" || len(request.Nonce) > 128 || strings.IndexFunc(request.Nonce, func(value rune) bool { return value < 0x20 || value == 0x7f }) >= 0 {
		return errors.New("invalid nonce")
	}
	return json.NewEncoder(connection).Encode(receipt{Nonce: request.Nonce, Identity: identity, ViaFakeUpstream: via})
}

func serveCONNECT(connection net.Conn, identity, approvedTarget string) error {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(connectionTimeout))
	reader := bufio.NewReader(io.LimitReader(connection, 16*1024))
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	if request.Body != nil {
		_ = request.Body.Close()
	}
	if request.Method != http.MethodConnect || request.Host != approvedTarget {
		_, _ = io.WriteString(connection, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return errors.New("CONNECT target is not approved")
	}
	target, err := net.DialTimeout("tcp4", approvedTarget, connectionTimeout)
	if err != nil {
		_, _ = io.WriteString(connection, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return err
	}
	defer target.Close()
	_ = target.SetDeadline(time.Now().Add(connectionTimeout))
	if _, err := io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	var probe map[string]string
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&probe); err != nil {
		return err
	}
	if len(probe) != 1 || probe["nonce"] == "" {
		return errors.New("invalid tunneled probe")
	}
	if err := json.NewEncoder(target).Encode(probe); err != nil {
		return err
	}
	var targetReceipt receipt
	targetDecoder := json.NewDecoder(bufio.NewReader(io.LimitReader(target, 4097)))
	targetDecoder.DisallowUnknownFields()
	if err := targetDecoder.Decode(&targetReceipt); err != nil {
		return err
	}
	if targetReceipt.Nonce != probe["nonce"] || targetReceipt.ViaFakeUpstream != "" {
		return errors.New("target receipt mismatch")
	}
	targetReceipt.ViaFakeUpstream = identity
	if err := json.NewEncoder(connection).Encode(targetReceipt); err != nil {
		return fmt.Errorf("write traversal receipt: %w", err)
	}
	return nil
}
