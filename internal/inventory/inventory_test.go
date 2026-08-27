package inventory

import (
	"encoding/json"
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
  ],
  "nat": [
    {"Name":"ExistingNat","InternalIPInterfaceAddressPrefix":"192.0.2.0/24","ExternalIPInterfaceAddressPrefix":"","Active":true,"Store":"PersistentStore","TcpFilteringBehavior":"AddressDependentFiltering","UdpFilteringBehavior":"AddressAndPortDependentFiltering","UdpInboundRefresh":false,"IcmpQueryTimeout":30,"TcpEstablishedConnectionTimeout":1800,"TcpTransientConnectionTimeout":120,"UdpIdleSessionTimeout":120}
  ],
  "firewall_rules": [
    {"Name":"ExistingRule","DisplayName":"Existing rule","Description":"baseline","Group":"Baseline","Enabled":"True","Profile":"Any","Direction":"Outbound","Action":"Allow","EdgeTraversalPolicy":"Block","LooseSourceMapping":false,"LocalOnlyMapping":false,"Owner":"S-1-5-32-544","PolicyStoreSource":"PersistentStore","PolicyStoreSourceType":"Local","Platform":["10.0+"],"InterfaceAlias":["Ethernet"],"InterfaceType":["Lan"],"LocalAddress":["Any"],"RemoteAddress":["Internet"],"RemoteDynamicKeywordAddresses":["{01234567-89ab-cdef-0123-456789abcdef}"],"Protocol":["TCP"],"LocalPort":["Any"],"RemotePort":["443"],"IcmpType":[],"DynamicTarget":["Any"],"Program":["Any"],"Package":["S-1-15-2-1"],"Service":["Any"],"Authentication":["NotRequired"],"Encryption":["NotRequired"],"OverrideBlockRules":[false],"LocalUser":["Any"],"RemoteUser":["Any"],"RemoteMachine":["Any"]}
  ]
}`

const dualStackInventoryFixture = `{
  "interfaces": [
    {"InterfaceAlias":"Ethernet","InterfaceIndex":7,"AddressFamily":"IPv4","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1500},
    {"InterfaceAlias":"Ethernet","InterfaceIndex":7,"AddressFamily":"IPv6","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1500},
    {"InterfaceAlias":"Telecom-Client","InterfaceIndex":11,"AddressFamily":"IPv4","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1400},
    {"InterfaceAlias":"Telecom-Client","InterfaceIndex":11,"AddressFamily":"IPv6","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1400},
    {"InterfaceAlias":"wg-overseas-poc","InterfaceIndex":19,"AddressFamily":"IPv4","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1420},
    {"InterfaceAlias":"wg-overseas-poc","InterfaceIndex":19,"AddressFamily":"IPv6","ConnectionState":"Connected","Forwarding":"Disabled","NlMtu":1420}
  ],
  "routes": [
    {"InterfaceAlias":"Ethernet","InterfaceIndex":7,"DestinationPrefix":"0.0.0.0/0","NextHop":"172.20.10.1","RouteMetric":25,"State":"Alive"},
    {"InterfaceAlias":"wg-overseas-poc","InterfaceIndex":19,"DestinationPrefix":"100.127.77.0/24","NextHop":"0.0.0.0","RouteMetric":0,"State":"Alive"}
  ],
  "nat": [],
  "firewall_rules": []
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
	if len(state.NAT) != 1 || state.NAT[0].Name != "ExistingNat" || !state.NAT[0].Active {
		t.Fatalf("NAT = %#v, want the exact existing NAT", state.NAT)
	}
	if state.NAT[0].TcpFilteringBehavior != "AddressDependentFiltering" || state.NAT[0].IcmpQueryTimeout != 30 || state.NAT[0].TcpEstablishedConnectionTimeout != 1800 {
		t.Fatalf("NAT behavior/timeouts = %#v, want complete stable WinNAT policy", state.NAT[0])
	}
	if len(state.FirewallRules) != 1 || state.FirewallRules[0].Name != "ExistingRule" || state.FirewallRules[0].RemotePorts[0] != "443" {
		t.Fatalf("firewall rules = %#v, want normalized exact rule metadata", state.FirewallRules)
	}
	rule := state.FirewallRules[0]
	if rule.EdgeTraversalPolicy != "Block" || rule.InterfaceTypes[0] != "Lan" || rule.DynamicTargets[0] != "Any" || rule.Packages[0] != "S-1-15-2-1" || rule.Authentications[0] != "NotRequired" || rule.OverrideBlockRules[0] || len(rule.RemoteDynamicKeywordAddresses) != 1 {
		t.Fatalf("firewall policy/filters = %#v, want all material Windows Firewall dimensions", rule)
	}
}

func TestWindowsInventoryScriptCollectsCompleteNATAndFirewallPolicy(t *testing.T) {
	required := []string{
		"TcpFilteringBehavior", "UdpFilteringBehavior", "UdpInboundRefresh", "IcmpQueryTimeout",
		"TcpEstablishedConnectionTimeout", "TcpTransientConnectionTimeout", "UdpIdleSessionTimeout",
		"EdgeTraversalPolicy", "LooseSourceMapping", "LocalOnlyMapping", "Owner", "Platform",
		"Get-NetFirewallInterfaceTypeFilter", "InterfaceType", "IcmpType", "DynamicTarget", "Package", "RemoteDynamicKeywordAddresses",
		"Get-NetFirewallSecurityFilter", "Authentication", "Encryption", "OverrideBlockRules", "LocalUser", "RemoteUser", "RemoteMachine",
	}
	for _, value := range required {
		if !strings.Contains(windowsInventoryScript, value) {
			t.Errorf("windowsInventoryScript is missing %q", value)
		}
	}
}

func TestEvidenceStateJSONRequiresPresentCollectionsAndFirewallFields(t *testing.T) {
	state := State{
		Interfaces: []Interface{{Alias: "Ethernet", Index: 7, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1500}},
		Routes:     []Route{{Alias: "Ethernet", Index: 7, DestinationPrefix: "0.0.0.0/0", NextHop: "192.0.2.1", Metric: 25, State: "Alive"}},
		NAT:        []NAT{},
		FirewallRules: []FirewallRule{{
			Name: "Baseline", DisplayName: "Baseline", Description: "", Group: "", Enabled: "True", Profile: "Any", Direction: "Outbound", Action: "Allow",
			EdgeTraversalPolicy: "Block", LooseSourceMapping: false, LocalOnlyMapping: false, Owner: "", PolicyStoreSource: "PersistentStore", PolicyStoreSourceType: "Local",
			Platforms: []string{}, InterfaceAliases: []string{}, InterfaceTypes: []string{}, LocalAddresses: []string{"Any"}, RemoteAddresses: []string{"Internet"}, RemoteDynamicKeywordAddresses: []string{},
			Protocols: []string{"TCP"}, LocalPorts: []string{"Any"}, RemotePorts: []string{"443"}, IcmpTypes: []string{}, DynamicTargets: []string{},
			Programs: []string{}, Packages: []string{}, Services: []string{}, Authentications: []string{}, Encryptions: []string{}, OverrideBlockRules: []bool{}, LocalUsers: []string{}, RemoteUsers: []string{}, RemoteMachines: []string{},
		}},
	}
	contents, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(contents, &object); err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"interfaces", "routes", "nat", "firewall_rules"} {
		t.Run("state_"+field, func(t *testing.T) {
			copyObject := cloneJSONMap(t, object)
			delete(copyObject, field)
			if err := unmarshalStateMap(copyObject); err == nil {
				t.Fatalf("omitted state field %q was accepted", field)
			}
		})
	}

	requiredRuleFields := []string{
		"name", "display_name", "description", "group", "enabled", "profile", "direction", "action",
		"edge_traversal_policy", "loose_source_mapping", "local_only_mapping", "owner", "policy_store_source", "policy_store_source_type",
		"platforms", "interface_aliases", "interface_types", "local_addresses", "remote_addresses", "remote_dynamic_keyword_addresses", "protocols", "local_ports", "remote_ports",
		"icmp_types", "dynamic_targets", "programs", "packages", "services", "authentications", "encryptions", "override_block_rules", "local_users", "remote_users", "remote_machines",
	}
	for _, field := range requiredRuleFields {
		t.Run("firewall_"+field, func(t *testing.T) {
			copyObject := cloneJSONMap(t, object)
			rule := copyObject["firewall_rules"].([]any)[0].(map[string]any)
			delete(rule, field)
			if err := unmarshalStateMap(copyObject); err == nil {
				t.Fatalf("omitted firewall field %q was accepted", field)
			}
		})
	}

	if err := unmarshalStateMap(object); err != nil {
		t.Fatalf("complete state with explicit empty arrays was rejected: %v", err)
	}
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	contents, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(contents, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func unmarshalStateMap(value map[string]any) error {
	contents, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var state State
	return json.Unmarshal(contents, &state)
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

func TestValidateRejectsDistinctRoleAliasesWithSharedIndex(t *testing.T) {
	state, err := parseJSON(strings.NewReader(inventoryFixture))
	if err != nil {
		t.Fatalf("parseJSON() returned an error: %v", err)
	}
	state.Interfaces[1] = Interface{Alias: "Telecom-Client", Index: 7, Status: "Connected"}

	if err := Validate(state, configForAliases("Telecom-Client", "Ethernet")); err == nil {
		t.Fatal("expected distinct role aliases with the same interface index to be rejected")
	}
}

func TestValidateAcceptsRepeatedAliasAndIndexAcrossAddressFamilies(t *testing.T) {
	state, err := parseJSON(strings.NewReader(dualStackInventoryFixture))
	if err != nil {
		t.Fatalf("parseJSON() returned an error: %v", err)
	}

	if err := Validate(state, configForAliases("Telecom-Client", "Ethernet")); err != nil {
		t.Fatalf("Validate() returned an error for a dual-stack inventory: %v", err)
	}
}

func TestValidateRejectsAliasWithConflictingIndices(t *testing.T) {
	state, err := parseJSON(strings.NewReader(inventoryFixture))
	if err != nil {
		t.Fatalf("parseJSON() returned an error: %v", err)
	}
	state.Interfaces = append(state.Interfaces, Interface{Alias: "Ethernet", Index: 17, AddressFamily: "IPv6"})

	err = Validate(state, configForAliases("Telecom-Client", "Ethernet"))
	if err == nil || !strings.Contains(err.Error(), "conflicting interface indices") {
		t.Fatalf("Validate() error = %v, want conflicting interface indices", err)
	}
}

func TestValidateRejectsTelecomOnlyIPv4DefaultRoute(t *testing.T) {
	state, err := parseJSON(strings.NewReader(inventoryFixture))
	if err != nil {
		t.Fatalf("parseJSON() returned an error: %v", err)
	}
	state.Routes[0].Alias = "Telecom-Client"
	state.Routes[0].Index = 11

	err = Validate(state, configForAliases("Telecom-Client", "Ethernet"))
	if err == nil || !strings.Contains(err.Error(), "employee_interface") {
		t.Fatalf("Validate() error = %v, want employee_interface default-route rejection", err)
	}
}

func TestValidateRejectsMultipleActiveIPv4DefaultRoutes(t *testing.T) {
	state, err := parseJSON(strings.NewReader(inventoryFixture))
	if err != nil {
		t.Fatalf("parseJSON() returned an error: %v", err)
	}
	state.Routes = append(state.Routes, Route{
		Alias:             "Telecom-Client",
		Index:             11,
		DestinationPrefix: "0.0.0.0/0",
		State:             "Alive",
	})

	err = Validate(state, configForAliases("Telecom-Client", "Ethernet"))
	if err == nil || !strings.Contains(err.Error(), "exactly one active IPv4 default route") {
		t.Fatalf("Validate() error = %v, want multiple IPv4-default-route rejection", err)
	}
}

func configForAliases(telecomAlias, employeeAlias string) config.Config {
	return config.Config{
		WireGuardSubnet:    "100.127.77.0/24",
		WireGuardInterface: "wg-overseas-poc",
		TelecomInterface:   telecomAlias,
		TelecomRoutePrefixes: []string{
			"0.0.0.0/0",
		},
		EmployeeInterface: employeeAlias,
		InternalCIDRs:     []string{"10.0.0.0/8"},
		ApprovedTargets:   []config.Target{{Name: "operator-approved-test", URL: "https://approved-test.example.invalid/"}},
		ProbeTimeout:      8 * time.Second,
	}
}
