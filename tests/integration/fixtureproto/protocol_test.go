package fixtureproto

import (
	"strings"
	"testing"
)

func TestValidateResponseBindsEveryRequestAndFixtureIdentity(t *testing.T) {
	request := validRequest()
	expected := validBinding()
	response := validResponse(request, expected)
	if err := ValidateResponse(request, expected, response); err != nil {
		t.Fatalf("ValidateResponse() = %v", err)
	}

	tests := []struct {
		name string
		edit func(*Response)
		want string
	}{
		{name: "nonce", edit: func(value *Response) { value.RequestNonce = "stale" }, want: "nonce"},
		{name: "run", edit: func(value *Response) { value.RunID = "other-run" }, want: "run"},
		{name: "scenario", edit: func(value *Response) { value.Scenario = "other-case" }, want: "scenario"},
		{name: "action", edit: func(value *Response) { value.Action = "restore" }, want: "action"},
		{name: "payload", edit: func(value *Response) { value.Binding.PayloadSHA256 = strings.Repeat("a", 64) }, want: "payload"},
		{name: "config", edit: func(value *Response) { value.Binding.ConfigSHA256 = strings.Repeat("b", 64) }, want: "config"},
		{name: "upstream", edit: func(value *Response) { value.Binding.FakeUpstreamIdentity = "wrong" }, want: "upstream"},
		{name: "public sentinel", edit: func(value *Response) { value.Binding.PublicSentinelIdentity = "wrong" }, want: "public sentinel"},
		{name: "corporate sentinel", edit: func(value *Response) { value.Binding.CorporateSentinelIdentity = "wrong" }, want: "corporate sentinel"},
		{name: "public endpoint", edit: func(value *Response) { value.Binding.PublicSentinelEndpoint = "wrong" }, want: "public sentinel endpoint"},
		{name: "health endpoint", edit: func(value *Response) { value.Binding.PublicSentinelHealthEndpoint = "wrong" }, want: "public sentinel endpoint"},
		{name: "corporate endpoint", edit: func(value *Response) { value.Binding.CorporateSentinelEndpoint = "wrong" }, want: "corporate sentinel endpoint"},
		{name: "control endpoint", edit: func(value *Response) { value.Binding.FakeUpstreamControlEndpoint = "wrong" }, want: "fake upstream control"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := response
			test.edit(&changed)
			if err := ValidateResponse(request, expected, changed); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("ValidateResponse() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateResponseRejectsStaleOrActionlessEvidence(t *testing.T) {
	request := validRequest()
	expected := validBinding()
	response := validResponse(request, expected)
	response.Evidence.ObservationNonce = "old-observation"
	if err := ValidateResponse(request, expected, response); err == nil || !strings.Contains(err.Error(), "observation") {
		t.Fatalf("ValidateResponse() = %v, want stale observation refusal", err)
	}
	response = validResponse(request, expected)
	response.Evidence.Facts = nil
	if err := ValidateResponse(request, expected, response); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("ValidateResponse() = %v, want missing evidence refusal", err)
	}
}

func TestValidateResponseRequiresActionSpecificPostStateEvidence(t *testing.T) {
	request := validRequest()
	request.Action = "uninstall"
	response := validResponse(request, validBinding())
	response.Evidence.Facts = map[string]string{
		"host_identity":     "host-1",
		"post_state_sha256": strings.Repeat("4", 64),
	}
	if err := ValidateResponse(request, validBinding(), response); err == nil || !strings.Contains(err.Error(), "action evidence lacks") {
		t.Fatalf("ValidateResponse() = %v, want uninstall residue evidence refusal", err)
	}
}

func TestValidateRestoreBindsInputHashToTrustedRequest(t *testing.T) {
	request := validRequest()
	request.Action = "restore"
	response := validResponse(request, validBinding())
	response.Evidence.Facts = map[string]string{
		"host_identity": "host-1", "post_state_sha256": strings.Repeat("4", 64),
		"restore_input_sha256": strings.Repeat("9", 64), "state_restored": "true",
	}
	if err := ValidateResponse(request, validBinding(), response); err == nil || !strings.Contains(err.Error(), "restore input") {
		t.Fatalf("ValidateResponse() = %v, want trusted restore-input binding refusal", err)
	}
}

func TestSnapshotRejectsEmptyOrTrivialSurfaces(t *testing.T) {
	snapshot := validSnapshot("nonce-1")
	if err := snapshot.Validate("nonce-1"); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	tests := []struct {
		name string
		edit func(*Snapshot)
		want string
	}{
		{name: "stale capture", edit: func(value *Snapshot) { value.ObservationNonce = "old" }, want: "observation"},
		{name: "routes", edit: func(value *Snapshot) { value.Routes = nil }, want: "routes"},
		{name: "dns", edit: func(value *Snapshot) { value.DNS = nil }, want: "dns"},
		{name: "adapters", edit: func(value *Snapshot) { value.Adapters = nil }, want: "adapters"},
		{name: "services", edit: func(value *Snapshot) { value.Services = nil }, want: "services"},
		{name: "processes", edit: func(value *Snapshot) { value.Processes = nil }, want: "processes"},
		{name: "firewall", edit: func(value *Snapshot) { value.OwnedFirewallRules = nil }, want: "firewall"},
		{name: "blank adapter", edit: func(value *Snapshot) { value.Adapters[0].InterfaceGUID = "" }, want: "adapter"},
		{name: "blank process role", edit: func(value *Snapshot) { value.Processes[0].Role = "" }, want: "process"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := snapshot.Clone()
			test.edit(&changed)
			if err := changed.Validate("nonce-1"); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("Validate() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCanonicalStateExcludesObservationNonceButIncludesStructuredState(t *testing.T) {
	first := validSnapshot("nonce-1")
	second := validSnapshot("nonce-2")
	left, err := first.CanonicalState()
	if err != nil {
		t.Fatal(err)
	}
	right, err := second.CanonicalState()
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("observation nonce contaminated state comparison:\n%s\n%s", left, right)
	}
	second.Processes[0].PID = 99999
	right, err = second.CanonicalState()
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatal("transient PID contaminated exact restored-state comparison")
	}
	second.Routes[0].RouteMetric++
	right, err = second.CanonicalState()
	if err != nil {
		t.Fatal(err)
	}
	if string(left) == string(right) {
		t.Fatal("structured route change was hidden from canonical state")
	}
}

func validRequest() Request {
	return Request{ProtocolVersion: ProtocolVersion, RequestNonce: "nonce-1", RunID: "run-1", Action: "capture", Scenario: "core-exits", EvidenceDirectory: `C:\evidence\run`, EvidenceDirectoryIdentity: "volume:1/file:2", BaselinePath: `C:\evidence\baseline.json`, BaselineSHA256: strings.Repeat("1", 64)}
}

func validBinding() FixtureBinding {
	return FixtureBinding{PayloadSHA256: strings.Repeat("2", 64), ConfigSHA256: strings.Repeat("3", 64), FakeUpstreamIdentity: "fake-upstream/1", PublicSentinelIdentity: "public/1", CorporateSentinelIdentity: "corporate/1", PublicSentinelEndpoint: "198.18.0.2:18080", PublicSentinelHealthEndpoint: "172.20.9.251:18080", CorporateSentinelEndpoint: "172.20.9.250:18081", FakeUpstreamControlEndpoint: "172.20.9.15:18082"}
}

func validResponse(request Request, binding FixtureBinding) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestNonce:    request.RequestNonce,
		RunID:           request.RunID,
		Scenario:        request.Scenario,
		Action:          request.Action,
		OK:              true,
		Binding:         binding,
		Evidence:        ActionEvidence{Kind: request.Action, ObservationNonce: request.RequestNonce, Facts: map[string]string{"host_identity": "host-1", "snapshot_sha256": strings.Repeat("4", 64), "post_state_sha256": strings.Repeat("4", 64)}},
		Snapshot:        validSnapshot(request.RequestNonce),
	}
}

func validSnapshot(nonce string) Snapshot {
	return Snapshot{
		ObservationNonce:   nonce,
		Adapters:           []AdapterRecord{{InterfaceIndex: 7, InterfaceGUID: "{guid}", InterfaceAlias: "Ethernet", Status: "Up"}},
		Routes:             []RouteRecord{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7, NextHop: "192.0.2.1", RouteMetric: 10}},
		DNS:                []DNSRecord{{InterfaceIndex: 7, InterfaceAlias: "Ethernet", ServerAddresses: []string{"192.0.2.53"}}},
		Services:           []ServiceRecord{{Name: "RegenBioOverseasAccessAgent", Present: false, Status: "Absent", StartMode: "Absent"}},
		Processes:          []ProcessRecord{{Role: "agent", Present: false}, {Role: "core", Present: false}, {Role: "ui", Present: false}, {Role: "fake-upstream", Present: false}},
		OwnedFirewallRules: []FirewallRecord{{Name: "RegenBioOverseasAccess.Managed", Present: false, DefinitionSHA256: strings.Repeat("0", 64)}},
	}
}
