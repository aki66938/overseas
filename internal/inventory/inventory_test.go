package inventory

import (
	"strings"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/config"
)

const inventoryFixture = `{
  "interfaces": [
    {"InterfaceAlias":"Ethernet","InterfaceIndex":7,"AddressFamily":"IPv4","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1500},
    {"InterfaceAlias":"Telecom-Client","InterfaceIndex":11,"AddressFamily":"IPv4","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1400},
    {"InterfaceAlias":"wg-overseas-poc","InterfaceIndex":19,"AddressFamily":"IPv4","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1420}
  ],
  "routes": [
    {"InterfaceAlias":"Ethernet","InterfaceIndex":7,"DestinationPrefix":"0.0.0.0/0","NextHop":"172.20.10.1","RouteMetric":25,"State":"Alive"},
    {"InterfaceAlias":"Ethernet","InterfaceIndex":7,"DestinationPrefix":"172.20.10.0/24","NextHop":"0.0.0.0","RouteMetric":25,"State":"Alive"},
    {"InterfaceAlias":"Telecom-Client","InterfaceIndex":11,"DestinationPrefix":"198.51.100.0/24","NextHop":"0.0.0.0","RouteMetric":1,"State":"Alive"},
    {"InterfaceAlias":"wg-overseas-poc","InterfaceIndex":19,"DestinationPrefix":"100.127.77.0/24","NextHop":"0.0.0.0","RouteMetric":0,"State":"Alive"}
  ]
}`

func TestParseJSONDecodesThreeAdaptersAndRoutes(t *testing.T) {
	state, err := parseJSON(strings.NewReader(inventoryFixture))
	if err != nil {
		t.Fatalf("parseJSON() returned an error: %v", err)
	}
	if len(state.Interfaces) != 3 || len(state.Routes) != 4 {
		t.Fatalf("parsed %#v, want three interfaces and four routes", state)
	}
	if got := state.Interfaces[1]; got.Alias != "Telecom-Client" || got.Index != 11 || got.Status != "Connected" {
		t.Fatalf("telecom interface = %#v", got)
	}
}

func TestValidateAcceptsExactAliasesOneDefaultRouteAndWireGuardPrefix(t *testing.T) {
	state, err := parseJSON(strings.NewReader(inventoryFixture))
	if err != nil {
		t.Fatalf("parseJSON() returned an error: %v", err)
	}

	if err := Validate(state, configForAliases("Telecom-Client", "Ethernet")); err != nil {
		t.Fatalf("Validate() returned an error for valid inventory: %v", err)
	}
}

func TestValidateRequiresExactAliasMatching(t *testing.T) {
	state, err := parseJSON(strings.NewReader(inventoryFixture))
	if err != nil {
		t.Fatalf("parseJSON() returned an error: %v", err)
	}
	cfg := configForAliases("Telecom-Client", "ethernet")

	if err := Validate(state, cfg); err == nil {
		t.Fatal("expected case-changed employee alias to be rejected")
	}
}

func TestValidateRejectsSharedEmployeeAndTelecomInterface(t *testing.T) {
	state := State{Interfaces: []Interface{{Alias: "Ethernet", Index: 7, Status: "Up"}}}
	cfg := configForAliases("Ethernet", "Ethernet")
	if err := Validate(state, cfg); err == nil {
		t.Fatal("expected identical interface roles to be rejected")
	}
}

func configForAliases(telecomAlias, employeeAlias string) config.Config {
	return config.Config{
		WireGuardSubnet:    "100.127.77.0/24",
		WireGuardInterface: "wg-overseas-poc",
		TelecomInterface:   telecomAlias,
		EmployeeInterface:  employeeAlias,
		InternalCIDRs:      []string{"10.0.0.0/8"},
		ApprovedTargets:    []config.Target{{Name: "operator-approved-test", URL: "https://approved-test.example.invalid/"}},
		ProbeTimeout:       8 * time.Second,
	}
}
