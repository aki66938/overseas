package singconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

const (
	DefaultMethod    = "2022-blake3-aes-128-gcm"
	tunInterfaceName = "RegenBioOverseasAccess"

	// publicDNSOverTCPServer is the fallback resolver for non-A/AAAA record
	// types; A/AAAA come from the fakeip pool so the tunnel carries no
	// lookup traffic in the common path.
	publicDNSOverTCPServer = "8.8.8.8"
	tunAddress       = "172.19.0.1/30"
	publicDNSServer  = "1.1.1.1"

)

var shadowsocks2022KeyLengths = map[string]int{
	"2022-blake3-aes-128-gcm":       16,
	"2022-blake3-aes-256-gcm":       32,
	"2022-blake3-chacha20-poly1305": 32,
}

type ServerInput struct {
	Listen   string
	Port     uint16
	Method   string
	Password string
	Upstream string
}

type serverConfig struct {
	Inbounds  []serverInbound  `json:"inbounds"`
	Outbounds []serverOutbound `json:"outbounds"`
	Route     routeConfig      `json:"route"`
}

type serverInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort uint16 `json:"listen_port"`
	Network    string `json:"network"`
	Method     string `json:"method"`
	Password   string `json:"password"`
}

type serverOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

type routeConfig struct {
	Rules []routeRule `json:"rules,omitempty"`
	Final string      `json:"final"`
}

type routeRule struct {
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Network      []string `json:"network,omitempty"`
	Port         []int    `json:"port,omitempty"`
	Action       string   `json:"action"`
	Outbound     string   `json:"outbound,omitempty"`
}

func RenderServer(input ServerInput) ([]byte, error) {
	method, password, err := validateMethodAndPassword(input.Method, input.Password)
	if err != nil {
		return nil, err
	}
	if err := validateListenAddress(input.Listen); err != nil {
		return nil, err
	}
	if input.Port < 1024 {
		return nil, fmt.Errorf("server port must be 1024 or higher")
	}

	server, port, err := parseLoopbackUpstream(input.Upstream)
	if err != nil {
		return nil, err
	}

	config := serverConfig{
		Inbounds: []serverInbound{{
			Type:       "shadowsocks",
			Tag:        "server-in",
			Listen:     input.Listen,
			ListenPort: input.Port,
			Network:    "tcp",
			Method:     method,
			Password:   password,
		}},
		Outbounds: []serverOutbound{{
			Type:       "http",
			Tag:        "telecom",
			Server:     server,
			ServerPort: port,
		}},
		Route: routeConfig{
			Final: "telecom",
		},
	}
	return json.Marshal(config)
}

func validateMethodAndPassword(method, password string) (string, string, error) {
	method = strings.TrimSpace(method)
	if method == "" {
		method = DefaultMethod
	}
	requiredLength, ok := shadowsocks2022KeyLengths[method]
	if !ok {
		return "", "", fmt.Errorf("unsupported Shadowsocks method %q", method)
	}

	password = strings.TrimSpace(password)
	if password == "" {
		return "", "", fmt.Errorf("password must not be empty")
	}
	key, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return "", "", fmt.Errorf("password must be a valid base64-encoded key: %w", err)
	}
	if len(key) != requiredLength {
		return "", "", fmt.Errorf("password length for %s must decode to %d bytes", method, requiredLength)
	}
	return method, password, nil
}

func validateListenAddress(value string) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("listen must be a valid IP address")
	}
	if !addr.Is4() {
		return fmt.Errorf("listen must be an IPv4 address for the PoC")
	}
	return nil
}

func parseLoopbackUpstream(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return "", 0, fmt.Errorf("upstream must be host:port")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", 0, fmt.Errorf("upstream host must be an IP address")
	}
	if addr.String() != "127.0.0.1" {
		return "", 0, fmt.Errorf("upstream must be exactly 127.0.0.1:8080 for the PoC")
	}
	if portText != "8080" {
		return "", 0, fmt.Errorf("upstream must be exactly 127.0.0.1:8080 for the PoC")
	}
	return addr.String(), 8080, nil
}
