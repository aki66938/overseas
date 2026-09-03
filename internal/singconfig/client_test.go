package singconfig_test

import (
	"encoding/json"
	"testing"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/singconfig"
)

func TestClientRoutesInternetTCPAndRejectsUDP(t *testing.T) {
	config := decodeRenderedConfig(t, mustRenderClient(t, singconfig.ClientInput{
		Node: accessmodel.Node{
			ID:        "vm101",
			Transport: "http-connect",
			Address:   "172.20.9.15",
			Port:      8080,
		},
		CorporateCIDRs:   []string{"172.20.8.0/22"},
		CorporateDNS:     []string{"172.20.10.1"},
		InternalSuffixes: []string{"ad.intra.regen-bio.com"},
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
	if got, ok := inbound["auto_route"].(bool); !ok || !got {
		t.Fatalf("auto_route = %#v, want true (sing-box owns routing)", inbound["auto_route"])
	}

	if len(config.Outbounds) != 2 {
		t.Fatalf("outbounds = %d, want 2", len(config.Outbounds))
	}
	direct := config.Outbounds[0]
	if got := stringValue(t, direct["type"]); got != "direct" {
		t.Fatalf("outbound[0].type = %q, want direct", got)
	}
	if got := stringValue(t, direct["domain_resolver"]); got != "corp-dns" {
		t.Fatalf("outbound[0].domain_resolver = %q, want corp-dns", got)
	}
	tunnel := config.Outbounds[1]
	if got := stringValue(t, tunnel["type"]); got != "http" {
		t.Fatalf("outbound[1].type = %q, want http", got)
	}
	if got := stringValue(t, tunnel["tag"]); got != "tunnel" {
		t.Fatalf("outbound[1].tag = %q, want tunnel", got)
	}
	if got := stringValue(t, tunnel["server"]); got != "172.20.9.15" {
		t.Fatalf("outbound[1].server = %q, want 172.20.9.15", got)
	}
	if got := intValue(t, tunnel["server_port"]); got != 8080 {
		t.Fatalf("outbound[1].server_port = %d, want 8080", got)
	}
	for _, forbidden := range []string{"method", "password", "network"} {
		if _, exists := tunnel[forbidden]; exists {
			t.Fatalf("outbound[1].%s unexpectedly present", forbidden)
		}
	}

	if len(config.Route.Rules) != 7 {
		t.Fatalf("route.rules = %d, want 7", len(config.Route.Rules))
	}
	assertRouteRule(t, config.Route.Rules[0], nil, nil, []int{53}, nil, "")
	if got := stringValue(t, config.Route.Rules[0]["action"]); got != "hijack-dns" {
		t.Fatalf("DNS action = %q, want hijack-dns first", got)
	}
	assertRouteRule(t, config.Route.Rules[1], []string{"172.20.9.15/32"}, nil, nil, nil, "direct")
	assertRouteRule(t, config.Route.Rules[2], []string{"172.20.8.0/22", "172.20.10.1/32"}, nil, nil, nil, "direct")
	assertRouteRule(t, config.Route.Rules[3], nil, nil, nil, []string{"ad.intra.regen-bio.com"}, "direct")
	assertRouteRule(t, config.Route.Rules[4], nil, []string{"udp"}, []int{443}, nil, "")
	assertRejectAction(t, config.Route.Rules[4])
	assertRouteRule(t, config.Route.Rules[5], nil, []string{"udp"}, nil, nil, "")
	assertRejectAction(t, config.Route.Rules[5])
	assertRouteRule(t, config.Route.Rules[6], nil, []string{"tcp"}, nil, nil, "tunnel")
	if config.Route.Final != "tunnel" {
		t.Fatalf("route.final = %q, want tunnel", config.Route.Final)
	}

	if len(config.DNS.Servers) != 3 {
		t.Fatalf("dns.servers = %d, want 3", len(config.DNS.Servers))
	}
	if got := stringValue(t, config.DNS.Servers[0]["tag"]); got != "corp-dns" {
		t.Fatalf("dns.servers[0].tag = %q, want corp-dns", got)
	}
	if got := stringValue(t, config.DNS.Servers[1]["tag"]); got != "remote-dns" {
		t.Fatalf("dns.servers[1].tag = %q, want remote-dns", got)
	}
	if got := stringValue(t, config.DNS.Servers[2]["tag"]); got != "fakeip" {
		t.Fatalf("dns.servers[2].tag = %q, want fakeip", got)
	}
	if got := stringValue(t, config.DNS.Servers[2]["inet4_range"]); got != "198.18.0.0/15" {
		t.Fatalf("fakeip inet4_range = %q", got)
	}
	if len(config.DNS.Rules) != 2 {
		t.Fatalf("dns.rules = %d, want 2", len(config.DNS.Rules))
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
	if config.DNS.Final != "remote-dns" {
		t.Fatalf("dns.final = %q, want remote-dns", config.DNS.Final)
	}
}

func TestClientHijacksSystemDNSBeforeRejectingPublicUDP(t *testing.T) {
	config := decodeRenderedConfig(t, mustRenderClient(t, singconfig.ClientInput{
		Node:             accessmodel.Node{ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 8080},
		CorporateCIDRs:   []string{"172.20.8.0/22"},
		CorporateDNS:     []string{"172.20.9.1"},
		InternalSuffixes: []string{"ad.intra.regen-bio.com"},
	}))

	for index, rule := range config.Route.Rules {
		if action, _ := rule["action"].(string); action == "hijack-dns" {
			assertIntSlice(t, rule["port"], []int{53})
			if index >= len(config.Route.Rules)-2 {
				t.Fatalf("DNS hijack rule appears after UDP rejection: index %d", index)
			}
			return
		}
	}
	t.Fatal("route rules do not contain a DNS hijack action")
}

func TestRenderClientRejectsInvalidHTTPNode(t *testing.T) {
	tests := []singconfig.ClientInput{
		{
			Node: accessmodel.Node{
				ID: "vm101", Transport: "http-connect", Address: "127.0.0.1", Port: 8080,
			},
			CorporateCIDRs:   []string{"172.20.8.0/22"},
			CorporateDNS:     []string{"172.20.10.1"},
			InternalSuffixes: []string{"ad.intra.regen-bio.com"},
		},
		{
			Node:             accessmodel.Node{ID: "vm101", Transport: "http-connect", Address: "0.0.0.0", Port: 8080},
			CorporateCIDRs:   []string{"172.20.8.0/22"},
			CorporateDNS:     []string{"172.20.10.1"},
			InternalSuffixes: []string{"ad.intra.regen-bio.com"},
		},
		{
			Node:             accessmodel.Node{ID: "vm101", Transport: "http-connect", Address: "172.20.9.16", Port: 8080},
			CorporateCIDRs:   []string{"172.20.8.0/22"},
			CorporateDNS:     []string{"172.20.10.1"},
			InternalSuffixes: []string{"ad.intra.regen-bio.com"},
		},
		{
			Node:             accessmodel.Node{ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 18443},
			CorporateCIDRs:   []string{"172.20.8.0/22"},
			CorporateDNS:     []string{"172.20.10.1"},
			InternalSuffixes: []string{"ad.intra.regen-bio.com"},
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
			ID:        "vm101",
			Transport: "http-connect",
			Address:   "172.20.9.15",
			Port:      8080,
		},
		CorporateCIDRs: []string{"172.20.8.0/22"},
		CorporateDNS:   []string{"172.20.10.1"},
	}))

	if len(config.Route.Rules) != 6 {
		t.Fatalf("route.rules = %d, want 6", len(config.Route.Rules))
	}
	assertRouteRule(t, config.Route.Rules[0], nil, nil, []int{53}, nil, "")
	if got := stringValue(t, config.Route.Rules[0]["action"]); got != "hijack-dns" {
		t.Fatalf("DNS action = %q, want hijack-dns first", got)
	}
	assertRouteRule(t, config.Route.Rules[1], []string{"172.20.9.15/32"}, nil, nil, nil, "direct")
	assertRouteRule(t, config.Route.Rules[2], []string{"172.20.8.0/22", "172.20.10.1/32"}, nil, nil, nil, "direct")
	assertRouteRule(t, config.Route.Rules[3], nil, []string{"udp"}, []int{443}, nil, "")
	assertRejectAction(t, config.Route.Rules[3])
	assertRouteRule(t, config.Route.Rules[4], nil, []string{"udp"}, nil, nil, "")
	assertRejectAction(t, config.Route.Rules[4])
	assertRouteRule(t, config.Route.Rules[5], nil, []string{"tcp"}, nil, nil, "tunnel")
	for _, rule := range config.Route.Rules {
		if _, ok := rule["domain_suffix"]; ok {
			t.Fatalf("unexpected domain_suffix direct rule in %#v", rule)
		}
	}
}

func TestClientDNSFakeIPConfigPresent(t *testing.T) {
	contents := mustRenderClient(t, singconfig.ClientInput{
		Node:             accessmodel.Node{ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 8080},
		CorporateCIDRs:   []string{"172.20.8.0/22"},
		CorporateDNS:     []string{"172.20.10.1"},
		InternalSuffixes: []string{"ad.intra.regen-bio.com"},
	})
	var root struct {
		DNS json.RawMessage `json:"dns"`
	}
	if err := json.Unmarshal(contents, &root); err != nil {
		t.Fatal(err)
	}
	var dns struct {
		Servers []struct {
			Tag        string `json:"tag"`
			Type       string `json:"type"`
			Inet4Range string `json:"inet4_range"`
		} `json:"servers"`
		Final            string         `json:"final"`
		IndependentCache bool           `json:"independent_cache"`
		FakeIP           map[string]any `json:"fakeip"`
	}
	if err := json.Unmarshal(root.DNS, &dns); err != nil {
		t.Fatal(err)
	}
	if dns.Final != "remote-dns" || dns.FakeIP != nil {
		t.Fatalf("dns config = final %q fakeip %#v (final must be remote-dns; deprecated top-level fakeip block must stay absent)", dns.Final, dns.FakeIP)
	}
	if dns.IndependentCache {
		t.Fatal("dns.independent_cache must stay absent (deprecated)")
	}
	found := false
	for _, server := range dns.Servers {
		if server.Type == "fakeip" && server.Inet4Range == "198.18.0.0/15" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fakeip server missing in %#v", dns.Servers)
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
