package singconfig

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"corp.example/overseas-access-gateway/internal/accessmodel"
)

type ClientInput struct {
	Node             accessmodel.Node
	CorporateCIDRs   []string
	CorporateDNS     []string
	InternalSuffixes []string
	Method           string
	Password         string
}

type clientConfig struct {
	Inbounds  []clientInbound   `json:"inbounds"`
	Outbounds []clientOutbound  `json:"outbounds"`
	Route     clientRouteConfig `json:"route"`
	DNS       clientDNSConfig   `json:"dns"`
}

type clientInbound struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	InterfaceName string   `json:"interface_name"`
	Address       []string `json:"address"`
	AutoRoute     bool     `json:"auto_route"`
}

type clientOutbound struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	Server         string `json:"server,omitempty"`
	ServerPort     uint16 `json:"server_port,omitempty"`
	Method         string `json:"method,omitempty"`
	Password       string `json:"password,omitempty"`
	Network        string `json:"network,omitempty"`
	DomainResolver string `json:"domain_resolver,omitempty"`
}

type clientRouteConfig struct {
	Rules []routeRule `json:"rules"`
	Final string      `json:"final"`
}

type clientDNSConfig struct {
	Servers          []dnsServer `json:"servers"`
	Rules            []dnsRule   `json:"rules,omitempty"`
	Final            string      `json:"final"`
	ReverseMapping   bool        `json:"reverse_mapping"`
	IndependentCache bool        `json:"independent_cache"`
	FakeIP           *dnsFakeIP  `json:"fakeip,omitempty"`
}

type dnsFakeIP struct {
	Enabled    bool   `json:"enabled"`
	Inet4Range string `json:"inet4_range"`
	Inet6Range string `json:"inet6_range"`
}

type dnsServer struct {
	Type       string              `json:"type"`
	Tag        string              `json:"tag"`
	Server     string              `json:"server,omitempty"`
	ServerPort int                 `json:"server_port,omitempty"`
	Path       string              `json:"path,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	TLS        *dnsTLSConfig       `json:"tls,omitempty"`
	Detour     string              `json:"detour,omitempty"`
	Inet4Range string              `json:"inet4_range,omitempty"`
	Inet6Range string              `json:"inet6_range,omitempty"`
}

type dnsTLSConfig struct {
	ServerName string `json:"server_name"`
}

type dnsRule struct {
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Action       string   `json:"action"`
	Server       string   `json:"server,omitempty"`
}

func RenderClient(input ClientInput) ([]byte, error) {
	nodeAddress, err := validateNode(input.Node)
	if err != nil {
		return nil, err
	}
	tunnel := clientOutbound{Type: "http", Tag: "tunnel", Server: nodeAddress, ServerPort: input.Node.Port}
	if input.Node.Transport == "" {
		method, password, err := validateMethodAndPassword(input.Method, input.Password)
		if err != nil {
			return nil, err
		}
		tunnel.Type = "shadowsocks"
		tunnel.Method = method
		tunnel.Password = password
		tunnel.Network = "tcp"
	}
	corporateCIDRs, err := canonicalCorporateCIDRs(input.CorporateCIDRs)
	if err != nil {
		return nil, err
	}
	corporateDNS, err := canonicalCorporateDNS(input.CorporateDNS)
	if err != nil {
		return nil, err
	}
	internalSuffixes, err := canonicalInternalSuffixes(input.InternalSuffixes)
	if err != nil {
		return nil, err
	}
	if len(internalSuffixes) > 0 && len(corporateDNS) == 0 {
		return nil, fmt.Errorf("corporate DNS is required when internal suffixes are configured")
	}

	corpDirectTargets := append([]string(nil), corporateCIDRs...)
	for _, dnsAddress := range corporateDNS {
		corpDirectTargets = append(corpDirectTargets, dnsAddress+"/32")
	}

	// FakeIP design: tun-side queries are answered instantly from the
	// fake-ip pool and connections are routed by DOMAIN through the proxy,
	// which resolves names on the telecom egress. No DNS traffic crosses
	// the tunnel, so name resolution can never inherit its flakiness.
	// Internal suffixes resolve to real corporate addresses via corp-dns.
	dnsServers := []dnsServer{{
		Type:       "fakeip",
		Tag:        "fakeip",
		Inet4Range: "198.18.0.0/15",
		Inet6Range: "fc00::/18",
	}}
	dnsRules := []dnsRule(nil)
	if len(corporateDNS) > 0 {
		dnsServers = append([]dnsServer{{
			Type:       "udp",
			Tag:        "corp-dns",
			Server:     corporateDNS[0],
			ServerPort: 53,
			Detour:     "direct",
		}}, dnsServers...)
	}
	if len(internalSuffixes) > 0 {
		dnsRules = append(dnsRules, dnsRule{
			DomainSuffix: internalSuffixes,
			Action:       "route",
			Server:       "corp-dns",
		})
	}

	config := clientConfig{
		Inbounds: []clientInbound{{
			Type:          "tun",
			Tag:           "tun-in",
			InterfaceName: tunInterfaceName,
			Address:       []string{tunAddress},
			AutoRoute:     false,
		}},
		Outbounds: []clientOutbound{
			{
				Type:           "direct",
				Tag:            "direct",
				DomainResolver: directDomainResolverTag(corporateDNS),
			},
			tunnel,
		},
		Route: clientRouteConfig{
			Rules: []routeRule{
				{
					// DNS hijack must precede every other rule: the blanket
					// UDP reject below otherwise pre-matches UDP/53 queries
					// and silently kills all tun-side name resolution.
					Port:   []int{53},
					Action: "hijack-dns",
				},
				{
					IPCIDR:   []string{nodeAddress + "/32"},
					Action:   "route",
					Outbound: "direct",
				},
				{
					IPCIDR:   corpDirectTargets,
					Action:   "route",
					Outbound: "direct",
				},
				{
					Network: []string{"udp"},
					Port:    []int{443},
					Action:  "reject",
				},
				{
					Network: []string{"udp"},
					Action:  "reject",
				},
				{
					Network:  []string{"tcp"},
					Action:   "route",
					Outbound: "tunnel",
				},
			},
			Final: "tunnel",
		},
		DNS: clientDNSConfig{
			Servers:          dnsServers,
			Rules:            dnsRules,
			Final:            "fakeip",
			ReverseMapping:   true,
			IndependentCache: true,
			FakeIP: &dnsFakeIP{
				Enabled:    true,
				Inet4Range: "198.18.0.0/15",
				Inet6Range: "fc00::/18",
			},
		},
	}
	if len(internalSuffixes) > 0 {
		// Insert after the node/corporate direct rules but before the
		// blanket UDP reject.
		config.Route.Rules = append(config.Route.Rules[:3], append([]routeRule{{
			DomainSuffix: internalSuffixes,
			Action:       "route",
			Outbound:     "direct",
		}}, config.Route.Rules[3:]...)...)
	}
	return json.Marshal(config)
}

func validateNode(node accessmodel.Node) (string, error) {
	if node.Transport != "" && node.Transport != "http-connect" {
		return "", fmt.Errorf("node transport must be empty or http-connect")
	}
	if strings.TrimSpace(node.ID) == "" {
		return "", fmt.Errorf("node id must not be empty")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(node.Address))
	if err != nil {
		return "", fmt.Errorf("node address must be a valid IP address")
	}
	if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
		return "", fmt.Errorf("node address must not be loopback, multicast, or unspecified")
	}
	if !addr.Is4() {
		return "", fmt.Errorf("node address must be IPv4 for the PoC")
	}
	if node.Port < 1024 {
		return "", fmt.Errorf("node port must be 1024 or higher")
	}
	if node.Transport == "http-connect" && (addr.String() != "172.20.9.15" || node.Port != 8080) {
		return "", fmt.Errorf("node must be the approved telecom endpoint")
	}
	return addr.String(), nil
}

func canonicalCorporateCIDRs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("corporate CIDRs must not be empty")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.String() != strings.TrimSpace(value) {
			return nil, fmt.Errorf("corporate CIDRs must contain canonical prefixes")
		}
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("corporate CIDRs must not contain a default route")
		}
		if _, exists := seen[prefix.String()]; exists {
			return nil, fmt.Errorf("corporate CIDRs must not contain duplicates")
		}
		seen[prefix.String()] = struct{}{}
		result = append(result, prefix.String())
	}
	sort.Strings(result)
	return result, nil
}

func canonicalCorporateDNS(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("corporate DNS must contain valid IP addresses")
		}
		if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
			return nil, fmt.Errorf("corporate DNS must not contain loopback, multicast, or unspecified addresses")
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("corporate DNS must contain IPv4 addresses for the Windows PoC")
		}
		canonical := addr.String()
		if _, exists := seen[canonical]; exists {
			return nil, fmt.Errorf("corporate DNS must not contain duplicates")
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result, nil
}

func canonicalInternalSuffixes(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		suffix := strings.ToLower(strings.TrimSpace(value))
		if suffix == "" {
			return nil, fmt.Errorf("internal suffixes must not contain empty values")
		}
		if _, exists := seen[suffix]; exists {
			return nil, fmt.Errorf("internal suffixes must not contain duplicates")
		}
		seen[suffix] = struct{}{}
		result = append(result, suffix)
	}
	sort.Strings(result)
	return result, nil
}

func directDomainResolverTag(corporateDNS []string) string {
	if len(corporateDNS) == 0 {
		return ""
	}
	return "corp-dns"
}
