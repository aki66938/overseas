package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type nativeNetworkReader interface {
	Baseline(context.Context, []string) (WindowsNetworkBaseline, error)
	Fingerprint(context.Context, []string) (string, error)
}

type ipHelperAdapter struct {
	InterfaceIndex int
	LUID           uint64
	InterfaceGuid  string
	InterfaceAlias string
	Status         string
	DNSServers     []string
	DNSAutomatic   bool
}

type ipHelperInterface struct {
	InterfaceIndex      int
	LUID                uint64
	AutomaticMetric     bool
	Metric              int
	DisableDefaultRoute bool
}

type ipHelperRoute struct {
	DestinationPrefix string
	InterfaceIndex    int
	LUID              uint64
	NextHop           string
	Metric            int
	Protocol          int
}

type ipHelperAPI interface {
	Adapters(context.Context) ([]ipHelperAdapter, error)
	IPv4Interfaces(context.Context, []ipHelperAdapter) ([]ipHelperInterface, error)
	IPv4Routes(context.Context) ([]ipHelperRoute, error)
}

type ipHelperNetworkReader struct {
	api ipHelperAPI
}

func (r ipHelperNetworkReader) Baseline(ctx context.Context, nodes []string) (WindowsNetworkBaseline, error) {
	if r.api == nil {
		return WindowsNetworkBaseline{}, errors.New("IP Helper API is required")
	}
	adapters, err := r.api.Adapters(ctx)
	if err != nil {
		return WindowsNetworkBaseline{}, fmt.Errorf("read adapters: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return WindowsNetworkBaseline{}, err
	}
	interfaces, err := r.api.IPv4Interfaces(ctx, adapters)
	if err != nil {
		return WindowsNetworkBaseline{}, fmt.Errorf("read IPv4 interfaces: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return WindowsNetworkBaseline{}, err
	}
	routes, err := r.api.IPv4Routes(ctx)
	if err != nil {
		return WindowsNetworkBaseline{}, fmt.Errorf("read IPv4 routes: %w", err)
	}
	return normalizeNativeNetwork(adapters, interfaces, routes, nodes)
}

func (r ipHelperNetworkReader) Fingerprint(ctx context.Context, nodes []string) (string, error) {
	baseline, err := r.Baseline(ctx, nodes)
	if err != nil {
		return "", err
	}
	return fingerprintNativeNetwork(baseline)
}

func normalizeNativeNetwork(adapters []ipHelperAdapter, interfaces []ipHelperInterface, routes []ipHelperRoute, nodes []string) (WindowsNetworkBaseline, error) {
	if len(adapters) == 0 || len(interfaces) == 0 || len(routes) == 0 {
		return WindowsNetworkBaseline{}, errors.New("native network baseline is incomplete")
	}
	adapterLUIDs := make(map[int]map[uint64]bool, len(adapters))
	baseline := WindowsNetworkBaseline{
		Adapters:   make([]WindowsNativeAdapter, 0, len(adapters)),
		Interfaces: make([]WindowsNativeInterface, 0, len(interfaces)),
		Routes:     make([]WindowsNativeRoute, 0, len(routes)),
	}
	for _, value := range adapters {
		if value.InterfaceIndex <= 0 || strings.TrimSpace(value.InterfaceGuid) == "" || strings.TrimSpace(value.InterfaceAlias) == "" {
			return WindowsNetworkBaseline{}, errors.New("native adapter identity is invalid")
		}
		dns, err := canonicalIPv4Addresses(value.DNSServers)
		if err != nil {
			return WindowsNetworkBaseline{}, fmt.Errorf("native adapter DNS is invalid: %w", err)
		}
		baseline.Adapters = append(baseline.Adapters, WindowsNativeAdapter{
			InterfaceIndex: value.InterfaceIndex, InterfaceLUID: value.LUID, InterfaceGuid: value.InterfaceGuid,
			InterfaceAlias: value.InterfaceAlias, Status: value.Status,
			DNSServers: dns, DNSAutomatic: value.DNSAutomatic,
		})
		if adapterLUIDs[value.InterfaceIndex] == nil {
			adapterLUIDs[value.InterfaceIndex] = make(map[uint64]bool)
		}
		adapterLUIDs[value.InterfaceIndex][value.LUID] = true
	}
	interfaceMetrics := make(map[int]ipHelperInterface, len(interfaces))
	for _, value := range interfaces {
		if value.InterfaceIndex <= 0 || value.Metric < 0 {
			return WindowsNetworkBaseline{}, errors.New("native IPv4 interface is invalid")
		}
		knownLUIDs := adapterLUIDs[value.InterfaceIndex]
		if value.LUID != 0 && len(knownLUIDs) != 0 && !knownLUIDs[value.LUID] {
			continue
		}
		if existing, exists := interfaceMetrics[value.InterfaceIndex]; exists {
			if existing != value {
				return WindowsNetworkBaseline{}, errors.New("native IPv4 interface has conflicting duplicates")
			}
			continue
		}
		interfaceMetrics[value.InterfaceIndex] = value
		baseline.Interfaces = append(baseline.Interfaces, WindowsNativeInterface{
			InterfaceIndex: value.InterfaceIndex, InterfaceLUID: value.LUID, AutomaticMetric: value.AutomaticMetric,
			InterfaceMetric: value.Metric, DisableDefaultRoute: value.DisableDefaultRoute,
		})
	}
	parsedRoutes := make([]struct {
		value     ipHelperRoute
		prefix    netip.Prefix
		effective int
	}, 0, len(routes))
	hasDefault := false
	for _, value := range routes {
		prefix, err := netip.ParsePrefix(value.DestinationPrefix)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || value.InterfaceIndex <= 0 || value.Metric < 0 {
			return WindowsNetworkBaseline{}, errors.New("native IPv4 route is invalid")
		}
		metric, ok := interfaceMetrics[value.InterfaceIndex]
		if !ok {
			continue
		}
		if value.LUID != 0 && metric.LUID != 0 && value.LUID != metric.LUID {
			continue
		}
		nextHop, err := netip.ParseAddr(value.NextHop)
		if err != nil || !nextHop.Is4() {
			return WindowsNetworkBaseline{}, errors.New("native route next hop is invalid")
		}
		if prefix.Bits() == 0 {
			hasDefault = true
		}
		parsedRoutes = append(parsedRoutes, struct {
			value     ipHelperRoute
			prefix    netip.Prefix
			effective int
		}{value: value, prefix: prefix, effective: value.Metric + metric.Metric})
		baseline.Routes = append(baseline.Routes, WindowsNativeRoute{
			DestinationPrefix: prefix.String(), InterfaceIndex: value.InterfaceIndex, InterfaceLUID: value.LUID,
			NextHop: nextHop.String(), RouteMetric: value.Metric, Protocol: value.Protocol,
		})
	}
	if !hasDefault {
		return WindowsNetworkBaseline{}, errors.New("native network has no IPv4 default route")
	}
	canonicalNodes, err := canonicalIPv4Addresses(nodes)
	if err != nil {
		return WindowsNetworkBaseline{}, fmt.Errorf("configured node address is invalid: %w", err)
	}
	for _, node := range canonicalNodes {
		address := netip.MustParseAddr(node)
		var best *struct {
			value     ipHelperRoute
			prefix    netip.Prefix
			effective int
		}
		for index := range parsedRoutes {
			candidate := &parsedRoutes[index]
			if !candidate.prefix.Contains(address) {
				continue
			}
			if best == nil || routeCandidateLess(*candidate, *best) {
				best = candidate
			}
		}
		if best == nil {
			return WindowsNetworkBaseline{}, fmt.Errorf("no route reaches node %s", node)
		}
		metric := interfaceMetrics[best.value.InterfaceIndex]
		baseline.NodeRoutes = append(baseline.NodeRoutes, WindowsNodeRouteSnapshot{
			NodeAddress: node, DestinationPrefix: best.prefix.String(), InterfaceIndex: best.value.InterfaceIndex,
			NextHop: best.value.NextHop, RouteMetric: best.value.Metric, InterfaceMetric: metric.Metric,
			EffectiveMetric: best.effective, BypassRequired: best.prefix.Bits() == 0,
		})
	}
	canonicalizeNativeBaseline(&baseline)
	return baseline, nil
}

func routeCandidateLess(left, right struct {
	value     ipHelperRoute
	prefix    netip.Prefix
	effective int
}) bool {
	if left.prefix.Bits() != right.prefix.Bits() {
		return left.prefix.Bits() > right.prefix.Bits()
	}
	if left.effective != right.effective {
		return left.effective < right.effective
	}
	if left.value.Metric != right.value.Metric {
		return left.value.Metric < right.value.Metric
	}
	if left.value.InterfaceIndex != right.value.InterfaceIndex {
		return left.value.InterfaceIndex < right.value.InterfaceIndex
	}
	return left.value.NextHop < right.value.NextHop
}

func canonicalIPv4Addresses(values []string) ([]string, error) {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !address.Is4() {
			return nil, errors.New("address must be IPv4")
		}
		set[address.String()] = true
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func canonicalizeNativeBaseline(baseline *WindowsNetworkBaseline) {
	sort.Slice(baseline.Adapters, func(i, j int) bool {
		if baseline.Adapters[i].InterfaceGuid != baseline.Adapters[j].InterfaceGuid {
			return baseline.Adapters[i].InterfaceGuid < baseline.Adapters[j].InterfaceGuid
		}
		return baseline.Adapters[i].InterfaceIndex < baseline.Adapters[j].InterfaceIndex
	})
	sort.Slice(baseline.Interfaces, func(i, j int) bool {
		return baseline.Interfaces[i].InterfaceIndex < baseline.Interfaces[j].InterfaceIndex
	})
	sort.Slice(baseline.Routes, func(i, j int) bool {
		left, right := baseline.Routes[i], baseline.Routes[j]
		if left.DestinationPrefix != right.DestinationPrefix {
			return left.DestinationPrefix < right.DestinationPrefix
		}
		if left.InterfaceIndex != right.InterfaceIndex {
			return left.InterfaceIndex < right.InterfaceIndex
		}
		if left.NextHop != right.NextHop {
			return left.NextHop < right.NextHop
		}
		return left.RouteMetric < right.RouteMetric
	})
	sort.Slice(baseline.NodeRoutes, func(i, j int) bool { return baseline.NodeRoutes[i].NodeAddress < baseline.NodeRoutes[j].NodeAddress })
}

func fingerprintNativeNetwork(baseline WindowsNetworkBaseline) (string, error) {
	canonicalizeNativeBaseline(&baseline)
	payload, err := json.Marshal(baseline)
	if err != nil {
		return "", fmt.Errorf("marshal native network fingerprint: %w", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(payload)), nil
}
