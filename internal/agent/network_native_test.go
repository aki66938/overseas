package agent

import (
	"slices"
	"testing"
)

func TestNativeNetworkBaselineNormalizesAndSelectsNodeRoute(t *testing.T) {
	adapters := []ipHelperAdapter{
		{InterfaceIndex: 8, InterfaceGuid: "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}", InterfaceAlias: "Wi-Fi", Status: "Down", DNSServers: []string{"1.1.1.1"}, DNSAutomatic: true},
		{InterfaceIndex: 4, InterfaceGuid: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", InterfaceAlias: "Ethernet", Status: "Up", DNSServers: []string{"172.20.9.2", "172.20.9.1", "172.20.9.1"}, DNSAutomatic: false},
	}
	interfaces := []ipHelperInterface{{InterfaceIndex: 8, AutomaticMetric: true, Metric: 35}, {InterfaceIndex: 4, AutomaticMetric: false, Metric: 10}}
	routes := []ipHelperRoute{
		{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, NextHop: "172.20.10.1", Metric: 25, Protocol: 3},
		{DestinationPrefix: "172.20.8.0/22", InterfaceIndex: 4, NextHop: "0.0.0.0", Metric: 0, Protocol: 3},
		{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 8, NextHop: "192.0.2.1", Metric: 5, Protocol: 3},
	}

	baseline, err := normalizeNativeNetwork(adapters, interfaces, routes, []string{"172.20.9.15", "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if got := baseline.Adapters[0]; got.InterfaceIndex != 4 || !slices.Equal(got.DNSServers, []string{"172.20.9.1", "172.20.9.2"}) {
		t.Fatalf("first adapter = %+v", got)
	}
	if len(baseline.NodeRoutes) != 2 {
		t.Fatalf("node routes = %+v", baseline.NodeRoutes)
	}
	if route := baseline.NodeRoutes[0]; route.NodeAddress != "172.20.9.15" || route.DestinationPrefix != "172.20.8.0/22" || route.BypassRequired {
		t.Fatalf("internal node route = %+v", route)
	}
	if route := baseline.NodeRoutes[1]; route.NodeAddress != "8.8.8.8" || route.DestinationPrefix != "0.0.0.0/0" || route.InterfaceIndex != 4 || !route.BypassRequired || route.EffectiveMetric != 35 {
		t.Fatalf("public node route = %+v", route)
	}
}

func TestNativeFingerprintStableAcrossInputOrder(t *testing.T) {
	adapters := []ipHelperAdapter{
		{InterfaceIndex: 4, InterfaceGuid: "a", InterfaceAlias: "Ethernet", Status: "Up", DNSServers: []string{"172.20.9.2", "172.20.9.1"}},
		{InterfaceIndex: 8, InterfaceGuid: "b", InterfaceAlias: "Wi-Fi", Status: "Down"},
	}
	interfaces := []ipHelperInterface{{InterfaceIndex: 4, Metric: 10}, {InterfaceIndex: 8, Metric: 20}}
	routes := []ipHelperRoute{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, NextHop: "172.20.10.1", Metric: 25}}
	first, err := normalizeNativeNetwork(adapters, interfaces, routes, []string{"8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(adapters)
	slices.Reverse(interfaces)
	second, err := normalizeNativeNetwork(adapters, interfaces, routes, []string{"8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	firstHash, err := fingerprintNativeNetwork(first)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := fingerprintNativeNetwork(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatalf("fingerprints differ: %q vs %q", firstHash, secondHash)
	}
	second.Adapters[0].DNSServers = []string{"9.9.9.9"}
	changedHash, err := fingerprintNativeNetwork(second)
	if err != nil {
		t.Fatal(err)
	}
	if changedHash == firstHash {
		t.Fatal("DNS change did not alter fingerprint")
	}
}

func TestNativeNodeRouteRejectsMissingOrMalformedRoutes(t *testing.T) {
	adapters := []ipHelperAdapter{{InterfaceIndex: 4, InterfaceGuid: "a", InterfaceAlias: "Ethernet", Status: "Up"}}
	interfaces := []ipHelperInterface{{InterfaceIndex: 4, Metric: 10}}
	for _, routes := range [][]ipHelperRoute{
		nil,
		{{DestinationPrefix: "not-a-prefix", InterfaceIndex: 4, NextHop: "172.20.10.1"}},
		{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 99, NextHop: "172.20.10.1"}},
	} {
		if _, err := normalizeNativeNetwork(adapters, interfaces, routes, []string{"8.8.8.8"}); err == nil {
			t.Fatalf("normalizeNativeNetwork(%+v) succeeded", routes)
		}
	}
}

func TestNativeNetworkBaselineCollapsesExactInterfaceDuplicates(t *testing.T) {
	adapters := []ipHelperAdapter{{InterfaceIndex: 4, InterfaceGuid: "a", InterfaceAlias: "Ethernet", Status: "Up"}}
	duplicate := ipHelperInterface{InterfaceIndex: 4, AutomaticMetric: true, Metric: 10}
	routes := []ipHelperRoute{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, NextHop: "172.20.10.1"}}
	baseline, err := normalizeNativeNetwork(adapters, []ipHelperInterface{duplicate, duplicate}, routes, []string{"8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Interfaces) != 1 {
		t.Fatalf("interfaces = %+v", baseline.Interfaces)
	}
	conflict := duplicate
	conflict.Metric = 11
	if _, err := normalizeNativeNetwork(adapters, []ipHelperInterface{duplicate, conflict}, routes, []string{"8.8.8.8"}); err == nil {
		t.Fatal("conflicting duplicate interface was accepted")
	}
}

func TestNativeNetworkBaselineJoinsDuplicateIndicesByLUID(t *testing.T) {
	adapters := []ipHelperAdapter{{InterfaceIndex: 4, LUID: 100, InterfaceGuid: "a", InterfaceAlias: "Ethernet", Status: "Up"}}
	interfaces := []ipHelperInterface{
		{InterfaceIndex: 4, LUID: 200, Metric: 99},
		{InterfaceIndex: 4, LUID: 100, Metric: 10},
	}
	routes := []ipHelperRoute{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, LUID: 100, NextHop: "172.20.10.1"}}
	baseline, err := normalizeNativeNetwork(adapters, interfaces, routes, []string{"8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Interfaces) != 1 || baseline.Interfaces[0].InterfaceMetric != 10 {
		t.Fatalf("interfaces = %+v", baseline.Interfaces)
	}
}
