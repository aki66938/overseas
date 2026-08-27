// Package inventory captures and validates the Windows network state required
// before the forwarding proof of concept changes any networking configuration.
package inventory

import (
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
	Name           string `json:"name"`
	InternalPrefix string `json:"internal_prefix"`
	ExternalPrefix string `json:"external_prefix"`
	Active         bool   `json:"active"`
}

// FirewallRule captures rule configuration plus the associated filters that
// materially affect packet matching.
type FirewallRule struct {
	Name                  string   `json:"name"`
	DisplayName           string   `json:"display_name"`
	Description           string   `json:"description"`
	Group                 string   `json:"group"`
	Enabled               string   `json:"enabled"`
	Profile               string   `json:"profile"`
	Direction             string   `json:"direction"`
	Action                string   `json:"action"`
	PolicyStoreSource     string   `json:"policy_store_source"`
	PolicyStoreSourceType string   `json:"policy_store_source_type"`
	InterfaceAliases      []string `json:"interface_aliases"`
	LocalAddresses        []string `json:"local_addresses"`
	RemoteAddresses       []string `json:"remote_addresses"`
	Protocols             []string `json:"protocols"`
	LocalPorts            []string `json:"local_ports"`
	RemotePorts           []string `json:"remote_ports"`
	Programs              []string `json:"programs"`
	Services              []string `json:"services"`
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
		Name           string `json:"Name"`
		InternalPrefix string `json:"InternalIPInterfaceAddressPrefix"`
		ExternalPrefix string `json:"ExternalIPInterfaceAddressPrefix"`
		Active         bool   `json:"Active"`
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
		Name                  string   `json:"Name"`
		DisplayName           string   `json:"DisplayName"`
		Description           string   `json:"Description"`
		Group                 string   `json:"Group"`
		Enabled               string   `json:"Enabled"`
		Profile               string   `json:"Profile"`
		Direction             string   `json:"Direction"`
		Action                string   `json:"Action"`
		PolicyStoreSource     string   `json:"PolicyStoreSource"`
		PolicyStoreSourceType string   `json:"PolicyStoreSourceType"`
		InterfaceAliases      []string `json:"InterfaceAlias"`
		LocalAddresses        []string `json:"LocalAddress"`
		RemoteAddresses       []string `json:"RemoteAddress"`
		Protocols             []string `json:"Protocol"`
		LocalPorts            []string `json:"LocalPort"`
		RemotePorts           []string `json:"RemotePort"`
		Programs              []string `json:"Program"`
		Services              []string `json:"Service"`
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
