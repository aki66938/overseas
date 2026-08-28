package singconfig_test

import (
	"testing"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/singconfig"
)

func TestClientRoutesInternetTCPAndRejectsUDP(t *testing.T) {
	config := decodeRenderedConfig(t, mustRenderClient(t, singconfig.ClientInput{
		Node: accessmodel.Node{
			ID:      "vm101",
			Address: "172.20.9.15",
			Port:    18443,
		},
		CorporateCIDRs:   []string{"172.20.8.0/22"},
		CorporateDNS:     []string{"172.20.10.1"},
		InternalSuffixes: []string{"ad.intra.regen-bio.com"},
		Method:           "2022-blake3-aes-128-gcm",
		Password:         "MDEyMzQ1Njc4OWFiY2RlZg==",
	}))

	if len(config.Inbounds) != 1 {
		t.Fatalf("inbounds = %d, want 1", len(config.Inbounds))
	}
	inbound := config.Inbounds[0]
	if got := stringValue(t, inbound["type"]); got != "tun" {
		t.Fatalf("inbound type = %q, want tun", got)
	}
	if got := stringValue(t, inbound["interface_name"]); got != "RegenBioOverseasAccess" {
		t.Fatalf("interface_name = %q, want RegenBioOverseasAccess", got)
	}
	if got, ok := inbound["auto_route"].(bool); !ok || got {
		t.Fatalf("auto_route = %#v, want false", inbound["auto_route"])
	}

	if len(config.Outbounds) != 2 {
		t.Fatalf("outbounds = %d, want 2", len(config.Outbounds))
	}
	direct := config.Outbounds[0]
	if got := stringValue(t, direct["type"]); got != "direct" {
		t.Fatalf("outbound[0].type = %q, want direct", got)
	}
	tunnel := config.Outbounds[1]
	if got := stringValue(t, tunnel["type"]); got != "shadowsocks" {
		t.Fatalf("outbound[1].type = %q, want shadowsocks", got)
	}
	if got := stringValue(t, tunnel["tag"]); got != "tunnel" {
		t.Fatalf("outbound[1].tag = %q, want tunnel", got)
	}
	if got := stringValue(t, tunnel["network"]); got != "tcp" {
		t.Fatalf("outbound[1].network = %q, want tcp", got)
	}

	if len(config.Route.Rules) != 6 {
		t.Fatalf("route.rules = %d, want 6", len(config.Route.Rules))
	}
	assertRouteRule(t, config.Route.Rules[0], []string{"172.20.9.15/32"}, nil, nil, nil, "direct")
	assertRouteRule(t, config.Route.Rules[1], []string{"172.20.8.0/22", "172.20.10.1/32"}, nil, nil, nil, "direct")
	assertRouteRule(t, config.Route.Rules[2], nil, nil, nil, []string{"ad.intra.regen-bio.com"}, "direct")
	assertRouteRule(t, config.Route.Rules[3], nil, []string{"udp"}, []int{443}, nil, "")
	assertRejectAction(t, config.Route.Rules[3])
	assertRouteRule(t, config.Route.Rules[4], nil, []string{"udp"}, nil, nil, "")
	assertRejectAction(t, config.Route.Rules[4])
	assertRouteRule(t, config.Route.Rules[5], nil, []string{"tcp"}, nil, nil, "tunnel")
	if config.Route.Final != "tunnel" {
		t.Fatalf("route.final = %q, want tunnel", config.Route.Final)
	}

	if len(config.DNS.Servers) != 2 {
		t.Fatalf("dns.servers = %d, want 2", len(config.DNS.Servers))
	}
	if got := stringValue(t, config.DNS.Servers[0]["tag"]); got != "corp-dns" {
		t.Fatalf("dns.servers[0].tag = %q, want corp-dns", got)
	}
	if got := stringValue(t, config.DNS.Servers[1]["tag"]); got != "public-dns" {
		t.Fatalf("dns.servers[1].tag = %q, want public-dns", got)
	}
	if len(config.DNS.Rules) != 1 {
		t.Fatalf("dns.rules = %d, want 1", len(config.DNS.Rules))
	}
	if got, ok := config.DNS.ReverseMapping.(bool); !ok || !got {
		t.Fatalf("dns.reverse_mapping = %#v, want true", config.DNS.ReverseMapping)
	}
	rule := config.DNS.Rules[0]
	assertStringSlice(t, rule["domain_suffix"], []string{"ad.intra.regen-bio.com"})
	if got := stringValue(t, rule["action"]); got != "route" {
		t.Fatalf("dns rule action = %q, want route", got)
	}
	if got := stringValue(t, rule["server"]); got != "corp-dns" {
		t.Fatalf("dns rule server = %q, want corp-dns", got)
	}
	if config.DNS.Final != "public-dns" {
		t.Fatalf("dns.final = %q, want public-dns", config.DNS.Final)
	}
}

func TestRenderClientRejectsInvalidNodeOrCredential(t *testing.T) {
	tests := []singconfig.ClientInput{
		{
			Node: accessmodel.Node{
				ID:      "vm101",
				Address: "127.0.0.1",
				Port:    18443,
			},
			CorporateCIDRs:   []string{"172.20.8.0/22"},
			CorporateDNS:     []string{"172.20.10.1"},
			InternalSuffixes: []string{"ad.intra.regen-bio.com"},
			Method:           "2022-blake3-aes-128-gcm",
			Password:         "MDEyMzQ1Njc4OWFiY2RlZg==",
		},
		{
			Node: accessmodel.Node{
				ID:      "vm101",
				Address: "172.20.9.15",
				Port:    443,
			},
			CorporateCIDRs:   []string{"172.20.8.0/22"},
			CorporateDNS:     []string{"172.20.10.1"},
			InternalSuffixes: []string{"ad.intra.regen-bio.com"},
			Method:           "2022-blake3-aes-128-gcm",
			Password:         "MDEyMzQ1Njc4OWFiY2RlZg==",
		},
		{
			Node: accessmodel.Node{
				ID:      "vm101",
				Address: "172.20.9.15",
				Port:    18443,
			},
			CorporateCIDRs:   []string{"172.20.8.0/22"},
			CorporateDNS:     []string{"172.20.10.1"},
			InternalSuffixes: []string{"ad.intra.regen-bio.com"},
			Method:           "2022-blake3-aes-128-gcm",
			Password:         "AQIDBA==",
		},
		{
			Node: accessmodel.Node{
				ID:      "vm101",
				Address: "172.20.9.15",
				Port:    18443,
			},
			CorporateCIDRs:   []string{"172.20.8.0/22"},
			CorporateDNS:     []string{"2001:db8::53"},
			InternalSuffixes: []string{"ad.intra.regen-bio.com"},
			Method:           "2022-blake3-aes-128-gcm",
			Password:         "MDEyMzQ1Njc4OWFiY2RlZg==",
		},
	}

	for i, input := range tests {
		if _, err := singconfig.RenderClient(input); err == nil {
			t.Fatalf("case %d unexpectedly succeeded", i)
		}
	}
}

func TestRenderClientOmitsInternalSuffixDirectRuleWhenNoSuffixesConfigured(t *testing.T) {
	config := decodeRenderedConfig(t, mustRenderClient(t, singconfig.ClientInput{
		Node: accessmodel.Node{
			ID:      "vm101",
			Address: "172.20.9.15",
			Port:    18443,
		},
		CorporateCIDRs: []string{"172.20.8.0/22"},
		CorporateDNS:   []string{"172.20.10.1"},
		Method:         "2022-blake3-aes-128-gcm",
		Password:       "MDEyMzQ1Njc4OWFiY2RlZg==",
	}))

	if len(config.Route.Rules) != 5 {
		t.Fatalf("route.rules = %d, want 5", len(config.Route.Rules))
	}
	assertRouteRule(t, config.Route.Rules[0], []string{"172.20.9.15/32"}, nil, nil, nil, "direct")
	assertRouteRule(t, config.Route.Rules[1], []string{"172.20.8.0/22", "172.20.10.1/32"}, nil, nil, nil, "direct")
	assertRouteRule(t, config.Route.Rules[2], nil, []string{"udp"}, []int{443}, nil, "")
	assertRejectAction(t, config.Route.Rules[2])
	assertRouteRule(t, config.Route.Rules[3], nil, []string{"udp"}, nil, nil, "")
	assertRejectAction(t, config.Route.Rules[3])
	assertRouteRule(t, config.Route.Rules[4], nil, []string{"tcp"}, nil, nil, "tunnel")
	for _, rule := range config.Route.Rules {
		if _, ok := rule["domain_suffix"]; ok {
			t.Fatalf("unexpected domain_suffix direct rule in %#v", rule)
		}
	}
}

func mustRenderClient(t *testing.T, input singconfig.ClientInput) []byte {
	t.Helper()

	contents, err := singconfig.RenderClient(input)
	if err != nil {
		t.Fatalf("RenderClient() error: %v", err)
	}
	return contents
}

func assertRouteRule(t *testing.T, rule map[string]any, wantCIDRs, wantNetwork []string, wantPorts []int, wantDomainSuffix []string, wantOutbound string) {
	t.Helper()

	if wantCIDRs == nil {
		if _, ok := rule["ip_cidr"]; ok {
			t.Fatalf("ip_cidr unexpectedly present in %#v", rule)
		}
	} else {
		assertStringSlice(t, rule["ip_cidr"], wantCIDRs)
	}

	if wantNetwork == nil {
		if _, ok := rule["network"]; ok {
			t.Fatalf("network unexpectedly present in %#v", rule)
		}
	} else {
		assertStringSlice(t, rule["network"], wantNetwork)
	}

	if wantPorts == nil {
		if _, ok := rule["port"]; ok {
			t.Fatalf("port unexpectedly present in %#v", rule)
		}
	} else {
		assertIntSlice(t, rule["port"], wantPorts)
	}

	if wantDomainSuffix == nil {
		if _, ok := rule["domain_suffix"]; ok {
			t.Fatalf("domain_suffix unexpectedly present in %#v", rule)
		}
	} else {
		assertStringSlice(t, rule["domain_suffix"], wantDomainSuffix)
	}

	if wantOutbound == "" {
		if _, ok := rule["outbound"]; ok {
			t.Fatalf("outbound unexpectedly present in %#v", rule)
		}
		return
	}
	if got := stringValue(t, rule["outbound"]); got != wantOutbound {
		t.Fatalf("outbound = %q, want %q", got, wantOutbound)
	}
}

func assertRejectAction(t *testing.T, rule map[string]any) {
	t.Helper()

	if got := stringValue(t, rule["action"]); got != "reject" {
		t.Fatalf("action = %q, want reject", got)
	}
}

func assertStringSlice(t *testing.T, value any, want []string) {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("value %#v is not an array", value)
	}
	if len(items) != len(want) {
		t.Fatalf("slice length = %d, want %d (%#v)", len(items), len(want), items)
	}
	for i, expected := range want {
		if got := stringValue(t, items[i]); got != expected {
			t.Fatalf("slice[%d] = %q, want %q", i, got, expected)
		}
	}
}

func assertIntSlice(t *testing.T, value any, want []int) {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("value %#v is not an array", value)
	}
	if len(items) != len(want) {
		t.Fatalf("slice length = %d, want %d (%#v)", len(items), len(want), items)
	}
	for i, expected := range want {
		if got := intValue(t, items[i]); got != expected {
			t.Fatalf("slice[%d] = %d, want %d", i, got, expected)
		}
	}
}
