package singconfig_test

import (
	"encoding/json"
	"testing"

	"corp.example/overseas-access-gateway/internal/singconfig"
)

func TestServerHasOnlyTelecomProxyPath(t *testing.T) {
	config := decodeRenderedConfig(t, mustRenderServer(t, singconfig.ServerInput{
		Listen:   "0.0.0.0",
		Port:     18443,
		Method:   "2022-blake3-aes-128-gcm",
		Password: "MDEyMzQ1Njc4OWFiY2RlZg==",
		Upstream: "127.0.0.1:8080",
	}))

	if len(config.Inbounds) != 1 {
		t.Fatalf("inbounds = %d, want 1", len(config.Inbounds))
	}
	inbound := config.Inbounds[0]
	if got := stringValue(t, inbound["type"]); got != "shadowsocks" {
		t.Fatalf("inbound type = %q, want shadowsocks", got)
	}
	if got := stringValue(t, inbound["network"]); got != "tcp" {
		t.Fatalf("inbound network = %q, want tcp", got)
	}

	if len(config.Outbounds) != 1 {
		t.Fatalf("outbounds = %d, want 1", len(config.Outbounds))
	}
	outbound := config.Outbounds[0]
	if got := stringValue(t, outbound["type"]); got != "http" {
		t.Fatalf("outbound type = %q, want http", got)
	}
	if got := stringValue(t, outbound["tag"]); got != "telecom" {
		t.Fatalf("outbound tag = %q, want telecom", got)
	}
	if got := stringValue(t, outbound["server"]); got != "127.0.0.1" {
		t.Fatalf("outbound server = %q, want 127.0.0.1", got)
	}
	if got := intValue(t, outbound["server_port"]); got != 8080 {
		t.Fatalf("outbound server_port = %d, want 8080", got)
	}

	for _, candidate := range config.Outbounds {
		if got := stringValue(t, candidate["type"]); got == "direct" {
			t.Fatal("server config contains a direct outbound fallback")
		}
	}
	if config.Route.Final != "telecom" {
		t.Fatalf("route.final = %q, want telecom", config.Route.Final)
	}
}

func TestRenderServerRejectsUnsafeInputs(t *testing.T) {
	tests := []singconfig.ServerInput{
		{
			Listen:   "0.0.0.0",
			Port:     18443,
			Method:   "2022-blake3-aes-128-gcm",
			Password: "MDEyMzQ1Njc4OWFiY2RlZg==",
			Upstream: "172.20.9.1:8080",
		},
		{
			Listen:   "0.0.0.0",
			Port:     18443,
			Method:   "2022-blake3-aes-128-gcm",
			Password: "MDEyMzQ1Njc4OWFiY2RlZg==",
			Upstream: "127.0.0.1:9090",
		},
		{
			Listen:   "0.0.0.0",
			Port:     18443,
			Method:   "2022-blake3-aes-128-gcm",
			Password: "not-base64",
			Upstream: "127.0.0.1:8080",
		},
		{
			Listen:   "0.0.0.0",
			Port:     18443,
			Method:   "2022-blake3-aes-128-gcm",
			Password: "AQIDBA==",
			Upstream: "127.0.0.1:8080",
		},
		{
			Listen:   "0.0.0.0",
			Port:     18443,
			Method:   "aes-128-gcm",
			Password: "MDEyMzQ1Njc4OWFiY2RlZg==",
			Upstream: "127.0.0.1:8080",
		},
	}

	for i, input := range tests {
		if _, err := singconfig.RenderServer(input); err == nil {
			t.Fatalf("case %d unexpectedly succeeded", i)
		}
	}
}

type renderedConfig struct {
	Inbounds  []map[string]any `json:"inbounds"`
	Outbounds []map[string]any `json:"outbounds"`
	Route     struct {
		Final string           `json:"final"`
		Rules []map[string]any `json:"rules"`
	} `json:"route"`
	DNS struct {
		Servers []map[string]any `json:"servers"`
		Rules   []map[string]any `json:"rules"`
		Final   string           `json:"final"`
	} `json:"dns"`
}

func decodeRenderedConfig(t *testing.T, contents []byte) renderedConfig {
	t.Helper()

	var config renderedConfig
	if err := json.Unmarshal(contents, &config); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return config
}

func mustRenderServer(t *testing.T, input singconfig.ServerInput) []byte {
	t.Helper()

	contents, err := singconfig.RenderServer(input)
	if err != nil {
		t.Fatalf("RenderServer() error: %v", err)
	}
	return contents
}

func stringValue(t *testing.T, value any) string {
	t.Helper()

	s, ok := value.(string)
	if !ok {
		t.Fatalf("value %#v is not a string", value)
	}
	return s
}

func intValue(t *testing.T, value any) int {
	t.Helper()

	number, ok := value.(float64)
	if !ok {
		t.Fatalf("value %#v is not a number", value)
	}
	return int(number)
}
