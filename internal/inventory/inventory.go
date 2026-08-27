// Package inventory captures and validates the Windows network state required
// before the forwarding proof of concept changes any networking configuration.
package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"time"

	"corp.example/overseas-access-gateway/internal/config"
)

// State is a read-only snapshot of the interfaces and routes reported by
// Windows networking cmdlets.
type State struct {
	Interfaces    []Interface    `json:"interfaces"`
	Routes        []Route        `json:"routes"`
	NAT           []NAT          `json:"nat"`
	FirewallRules []FirewallRule `json:"firewall_rules"`
}

// Artifact binds a network-state capture to one validated PoC run.
type Artifact struct {
	SchemaVersion int       `json:"schema_version"`
	RunID         string    `json:"run_id"`
	ConfigDigest  string    `json:"config_digest"`
	CapturedAt    time.Time `json:"captured_at"`
	State         State     `json:"state"`
}

// Interface describes a Windows IP interface.
type Interface struct {
	Alias         string `json:"alias"`
	Index         int    `json:"index"`
	AddressFamily string `json:"address_family"`
	Status        string `json:"status"`
	Forwarding    string `json:"forwarding"`
	MTU           int    `json:"mtu"`
}

// Route describes a Windows route.
type Route struct {
	Alias             string `json:"alias"`
	Index             int    `json:"index"`
	DestinationPrefix string `json:"destination_prefix"`
	NextHop           string `json:"next_hop"`
	Metric            int    `json:"metric"`
	State             string `json:"state"`
}

// NAT is the stable configuration subset of one WinNAT object.
type NAT struct {
	Name                            string `json:"name"`
	InternalPrefix                  string `json:"internal_prefix"`
	ExternalPrefix                  string `json:"external_prefix"`
	Active                          bool   `json:"active"`
	Store                           string `json:"store"`
	TcpFilteringBehavior            string `json:"tcp_filtering_behavior"`
	UdpFilteringBehavior            string `json:"udp_filtering_behavior"`
	UdpInboundRefresh               bool   `json:"udp_inbound_refresh"`
	IcmpQueryTimeout                int    `json:"icmp_query_timeout"`
	TcpEstablishedConnectionTimeout int    `json:"tcp_established_connection_timeout"`
	TcpTransientConnectionTimeout   int    `json:"tcp_transient_connection_timeout"`
	UdpIdleSessionTimeout           int    `json:"udp_idle_session_timeout"`
}

// FirewallRule captures rule configuration plus the associated filters that
// materially affect packet matching.
type FirewallRule struct {
	Name                          string   `json:"name"`
	DisplayName                   string   `json:"display_name"`
	Description                   string   `json:"description"`
	Group                         string   `json:"group"`
	Enabled                       string   `json:"enabled"`
	Profile                       string   `json:"profile"`
	Direction                     string   `json:"direction"`
	Action                        string   `json:"action"`
	EdgeTraversalPolicy           string   `json:"edge_traversal_policy"`
	LooseSourceMapping            bool     `json:"loose_source_mapping"`
	LocalOnlyMapping              bool     `json:"local_only_mapping"`
	Owner                         string   `json:"owner"`
	PolicyStoreSource             string   `json:"policy_store_source"`
	PolicyStoreSourceType         string   `json:"policy_store_source_type"`
	Platforms                     []string `json:"platforms"`
	InterfaceAliases              []string `json:"interface_aliases"`
	InterfaceTypes                []string `json:"interface_types"`
	LocalAddresses                []string `json:"local_addresses"`
	RemoteAddresses               []string `json:"remote_addresses"`
	RemoteDynamicKeywordAddresses []string `json:"remote_dynamic_keyword_addresses"`
	Protocols                     []string `json:"protocols"`
	LocalPorts                    []string `json:"local_ports"`
	RemotePorts                   []string `json:"remote_ports"`
	IcmpTypes                     []string `json:"icmp_types"`
	DynamicTargets                []string `json:"dynamic_targets"`
	Programs                      []string `json:"programs"`
	Packages                      []string `json:"packages"`
	Services                      []string `json:"services"`
	Authentications               []string `json:"authentications"`
	Encryptions                   []string `json:"encryptions"`
	OverrideBlockRules            []bool   `json:"override_block_rules"`
	LocalUsers                    []string `json:"local_users"`
	RemoteUsers                   []string `json:"remote_users"`
	RemoteMachines                []string `json:"remote_machines"`
}

// UnmarshalJSON makes the collection boundary presence-aware. A missing or
// null collection is not equivalent to a cmdlet reporting an explicit empty
// array, because omission could otherwise erase evidence without invalidating
// a verdict artifact.
func (state *State) UnmarshalJSON(data []byte) error {
	type plain State
	var decoded plain
	if err := decodeRequiredObject(data, &decoded, "interfaces", "routes", "nat", "firewall_rules"); err != nil {
		return fmt.Errorf("decode inventory state: %w", err)
	}
	*state = State(decoded)
	return nil
}

func (item *Interface) UnmarshalJSON(data []byte) error {
	type plain Interface
	var decoded plain
	if err := decodeRequiredObject(data, &decoded, "alias", "index", "address_family", "status", "forwarding", "mtu"); err != nil {
		return fmt.Errorf("decode inventory interface: %w", err)
	}
	*item = Interface(decoded)
	return nil
}

func (item *Route) UnmarshalJSON(data []byte) error {
	type plain Route
	var decoded plain
	if err := decodeRequiredObject(data, &decoded, "alias", "index", "destination_prefix", "next_hop", "metric", "state"); err != nil {
		return fmt.Errorf("decode inventory route: %w", err)
	}
	*item = Route(decoded)
	return nil
}

func (item *NAT) UnmarshalJSON(data []byte) error {
	type plain NAT
	var decoded plain
	if err := decodeRequiredObject(data, &decoded,
		"name", "internal_prefix", "external_prefix", "active", "store",
		"tcp_filtering_behavior", "udp_filtering_behavior", "udp_inbound_refresh",
		"icmp_query_timeout", "tcp_established_connection_timeout", "tcp_transient_connection_timeout", "udp_idle_session_timeout"); err != nil {
		return fmt.Errorf("decode inventory NAT: %w", err)
	}
	*item = NAT(decoded)
	return nil
}

func (item *FirewallRule) UnmarshalJSON(data []byte) error {
	type plain FirewallRule
	var decoded plain
	if err := decodeRequiredObject(data, &decoded,
		"name", "display_name", "description", "group", "enabled", "profile", "direction", "action",
		"edge_traversal_policy", "loose_source_mapping", "local_only_mapping", "owner", "policy_store_source", "policy_store_source_type",
		"platforms", "interface_aliases", "interface_types", "local_addresses", "remote_addresses", "remote_dynamic_keyword_addresses", "protocols", "local_ports", "remote_ports",
		"icmp_types", "dynamic_targets", "programs", "packages", "services", "authentications", "encryptions", "override_block_rules", "local_users", "remote_users", "remote_machines"); err != nil {
		return fmt.Errorf("decode inventory firewall rule: %w", err)
	}
	*item = FirewallRule(decoded)
	return nil
}

func decodeRequiredObject(data []byte, destination any, fields ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	for _, field := range fields {
		value, ok := object[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("required field %q is missing or null", field)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}

func parseJSON(source io.Reader) (State, error) {
	var raw struct {
		Interfaces json.RawMessage `json:"interfaces"`
		Routes     json.RawMessage `json:"routes"`
		NAT        json.RawMessage `json:"nat"`
		Firewall   json.RawMessage `json:"firewall_rules"`
	}
	if err := json.NewDecoder(source).Decode(&raw); err != nil {
		return State{}, fmt.Errorf("decode inventory JSON: %w", err)
	}

	interfaces, err := decodeInterfaces(raw.Interfaces)
	if err != nil {
		return State{}, err
	}
	routes, err := decodeRoutes(raw.Routes)
	if err != nil {
		return State{}, err
	}
	nat, err := decodeNAT(raw.NAT)
	if err != nil {
		return State{}, err
	}
	firewall, err := decodeFirewallRules(raw.Firewall)
	if err != nil {
		return State{}, err
	}
	return State{Interfaces: interfaces, Routes: routes, NAT: nat, FirewallRules: firewall}, nil
}

func decodeInterfaces(raw json.RawMessage) ([]Interface, error) {
	var records []struct {
		Alias         string `json:"InterfaceAlias"`
		Index         int    `json:"InterfaceIndex"`
		AddressFamily string `json:"AddressFamily"`
		Status        string `json:"ConnectionState"`
		Forwarding    string `json:"Forwarding"`
		MTU           int    `json:"NlMtu"`
	}
	if err := decodeArrayOrOne(raw, &records); err != nil {
		return nil, fmt.Errorf("decode inventory interfaces: %w", err)
	}

	interfaces := make([]Interface, len(records))
	for i, record := range records {
		interfaces[i] = Interface{
			Alias:         record.Alias,
			Index:         record.Index,
			AddressFamily: record.AddressFamily,
			Status:        record.Status,
			Forwarding:    record.Forwarding,
			MTU:           record.MTU,
		}
	}
	return interfaces, nil
}

func decodeRoutes(raw json.RawMessage) ([]Route, error) {
	var records []struct {
		Alias             string `json:"InterfaceAlias"`
		Index             int    `json:"InterfaceIndex"`
		DestinationPrefix string `json:"DestinationPrefix"`
		NextHop           string `json:"NextHop"`
		Metric            int    `json:"RouteMetric"`
		State             string `json:"State"`
	}
	if err := decodeArrayOrOne(raw, &records); err != nil {
		return nil, fmt.Errorf("decode inventory routes: %w", err)
	}

	routes := make([]Route, len(records))
	for i, record := range records {
		routes[i] = Route{
			Alias:             record.Alias,
			Index:             record.Index,
			DestinationPrefix: record.DestinationPrefix,
			NextHop:           record.NextHop,
			Metric:            record.Metric,
			State:             record.State,
		}
	}
	return routes, nil
}

func decodeNAT(raw json.RawMessage) ([]NAT, error) {
	var records []struct {
		Name                            string `json:"Name"`
		InternalPrefix                  string `json:"InternalIPInterfaceAddressPrefix"`
		ExternalPrefix                  string `json:"ExternalIPInterfaceAddressPrefix"`
		Active                          bool   `json:"Active"`
		Store                           string `json:"Store"`
		TcpFilteringBehavior            string `json:"TcpFilteringBehavior"`
		UdpFilteringBehavior            string `json:"UdpFilteringBehavior"`
		UdpInboundRefresh               bool   `json:"UdpInboundRefresh"`
		IcmpQueryTimeout                int    `json:"IcmpQueryTimeout"`
		TcpEstablishedConnectionTimeout int    `json:"TcpEstablishedConnectionTimeout"`
		TcpTransientConnectionTimeout   int    `json:"TcpTransientConnectionTimeout"`
		UdpIdleSessionTimeout           int    `json:"UdpIdleSessionTimeout"`
	}
	if err := decodeArrayOrOneAllowEmpty(raw, &records); err != nil {
		return nil, fmt.Errorf("decode inventory NAT: %w", err)
	}
	nat := make([]NAT, len(records))
	for i, record := range records {
		nat[i] = NAT(record)
	}
	return nat, nil
}

func decodeFirewallRules(raw json.RawMessage) ([]FirewallRule, error) {
	var records []struct {
		Name                          string   `json:"Name"`
		DisplayName                   string   `json:"DisplayName"`
		Description                   string   `json:"Description"`
		Group                         string   `json:"Group"`
		Enabled                       string   `json:"Enabled"`
		Profile                       string   `json:"Profile"`
		Direction                     string   `json:"Direction"`
		Action                        string   `json:"Action"`
		EdgeTraversalPolicy           string   `json:"EdgeTraversalPolicy"`
		LooseSourceMapping            bool     `json:"LooseSourceMapping"`
		LocalOnlyMapping              bool     `json:"LocalOnlyMapping"`
		Owner                         string   `json:"Owner"`
		PolicyStoreSource             string   `json:"PolicyStoreSource"`
		PolicyStoreSourceType         string   `json:"PolicyStoreSourceType"`
		Platforms                     []string `json:"Platform"`
		InterfaceAliases              []string `json:"InterfaceAlias"`
		InterfaceTypes                []string `json:"InterfaceType"`
		LocalAddresses                []string `json:"LocalAddress"`
		RemoteAddresses               []string `json:"RemoteAddress"`
		RemoteDynamicKeywordAddresses []string `json:"RemoteDynamicKeywordAddresses"`
		Protocols                     []string `json:"Protocol"`
		LocalPorts                    []string `json:"LocalPort"`
		RemotePorts                   []string `json:"RemotePort"`
		IcmpTypes                     []string `json:"IcmpType"`
		DynamicTargets                []string `json:"DynamicTarget"`
		Programs                      []string `json:"Program"`
		Packages                      []string `json:"Package"`
		Services                      []string `json:"Service"`
		Authentications               []string `json:"Authentication"`
		Encryptions                   []string `json:"Encryption"`
		OverrideBlockRules            []bool   `json:"OverrideBlockRules"`
		LocalUsers                    []string `json:"LocalUser"`
		RemoteUsers                   []string `json:"RemoteUser"`
		RemoteMachines                []string `json:"RemoteMachine"`
	}
	if err := decodeArrayOrOne(raw, &records); err != nil {
		return nil, fmt.Errorf("decode inventory firewall rules: %w", err)
	}
	rules := make([]FirewallRule, len(records))
	for i, record := range records {
		rules[i] = FirewallRule(record)
	}
	return rules, nil
}

func decodeArrayOrOne[T any](raw json.RawMessage, destination *[]T) error {
	if len(raw) == 0 || string(raw) == "null" {
		return fmt.Errorf("field is missing")
	}
	if raw[0] == '[' {
		return json.Unmarshal(raw, destination)
	}

	var one T
	if err := json.Unmarshal(raw, &one); err != nil {
		return err
	}
	*destination = []T{one}
	return nil
}

func decodeArrayOrOneAllowEmpty[T any](raw json.RawMessage, destination *[]T) error {
	if len(raw) == 0 || string(raw) == "null" {
		return fmt.Errorf("field is missing")
	}
	if raw[0] == '[' {
		return json.Unmarshal(raw, destination)
	}
	return decodeArrayOrOne(raw, destination)
}

// Validate verifies that the configured roles have distinct, exact interface
// aliases, that Windows has one active IPv4 default route, and that the
// WireGuard subnet is represented on its configured interface.
func Validate(state State, cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate configuration: %w", err)
	}
	if cfg.TelecomInterface == cfg.EmployeeInterface {
		return fmt.Errorf("telecom_interface and employee_interface must resolve to different interfaces")
	}
	if cfg.WireGuardInterface == cfg.TelecomInterface || cfg.WireGuardInterface == cfg.EmployeeInterface {
		return fmt.Errorf("wireguard_interface must resolve to a distinct interface")
	}

	wireGuard, err := findInterface(state.Interfaces, cfg.WireGuardInterface)
	if err != nil {
		return fmt.Errorf("wireguard_interface: %w", err)
	}
	telecom, err := findInterface(state.Interfaces, cfg.TelecomInterface)
	if err != nil {
		return fmt.Errorf("telecom_interface: %w", err)
	}
	employee, err := findInterface(state.Interfaces, cfg.EmployeeInterface)
	if err != nil {
		return fmt.Errorf("employee_interface: %w", err)
	}
	if wireGuard.Index == telecom.Index || wireGuard.Index == employee.Index || telecom.Index == employee.Index {
		return fmt.Errorf("wireguard_interface, telecom_interface, and employee_interface must resolve to different interface indices")
	}

	if countActiveIPv4DefaultRoutes(state.Routes) != 1 {
		return fmt.Errorf("inventory must contain exactly one active IPv4 default route")
	}
	for _, route := range state.Routes {
		if route.DestinationPrefix == "0.0.0.0/0" && route.State == "Alive" {
			if route.Alias != employee.Alias || route.Index != employee.Index {
				return fmt.Errorf("active IPv4 default route must belong to employee_interface %q", employee.Alias)
			}
			break
		}
	}

	wireGuardPrefix, err := netip.ParsePrefix(cfg.WireGuardSubnet)
	if err != nil {
		return fmt.Errorf("wireguard_subnet: %w", err)
	}
	for _, route := range state.Routes {
		routePrefix, err := netip.ParsePrefix(route.DestinationPrefix)
		if err != nil {
			continue
		}
		if route.Alias == wireGuard.Alias && route.Index == wireGuard.Index && routePrefix.Masked() == wireGuardPrefix.Masked() {
			return nil
		}
	}
	return fmt.Errorf("wireguard_subnet %q is not present on wireguard_interface %q", cfg.WireGuardSubnet, cfg.WireGuardInterface)
}

func findInterface(interfaces []Interface, alias string) (Interface, error) {
	var match *Interface
	for i := range interfaces {
		if interfaces[i].Alias != alias {
			continue
		}
		if match != nil {
			if match.Index != interfaces[i].Index {
				return Interface{}, fmt.Errorf("alias %q has conflicting interface indices %d and %d", alias, match.Index, interfaces[i].Index)
			}
			continue
		}
		match = &interfaces[i]
	}
	if match == nil {
		return Interface{}, fmt.Errorf("alias %q was not found", alias)
	}
	return *match, nil
}

func countActiveIPv4DefaultRoutes(routes []Route) int {
	count := 0
	for _, route := range routes {
		if route.DestinationPrefix == "0.0.0.0/0" && route.State == "Alive" {
			count++
		}
	}
	return count
}
