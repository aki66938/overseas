// Package inventory captures and validates the Windows network state required
// before the forwarding proof of concept changes any networking configuration.
package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"

	"corp.example/overseas-access-gateway/internal/config"
)

// State is a read-only snapshot of the interfaces and routes reported by
// Windows networking cmdlets.
type State struct {
	Interfaces []Interface `json:"interfaces"`
	Routes     []Route     `json:"routes"`
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

func parseJSON(source io.Reader) (State, error) {
	var raw struct {
		Interfaces json.RawMessage `json:"interfaces"`
		Routes     json.RawMessage `json:"routes"`
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
	return State{Interfaces: interfaces, Routes: routes}, nil
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
	if _, err := findInterface(state.Interfaces, cfg.TelecomInterface); err != nil {
		return fmt.Errorf("telecom_interface: %w", err)
	}
	if _, err := findInterface(state.Interfaces, cfg.EmployeeInterface); err != nil {
		return fmt.Errorf("employee_interface: %w", err)
	}

	if countActiveIPv4DefaultRoutes(state.Routes) != 1 {
		return fmt.Errorf("inventory must contain exactly one active IPv4 default route")
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
			return Interface{}, fmt.Errorf("alias %q is ambiguous", alias)
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
