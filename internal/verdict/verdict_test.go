package verdict

import (
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/config"
	"corp.example/overseas-access-gateway/internal/inventory"
)

func TestEvaluatePassesOneFreshBoundChronologicalRun(t *testing.T) {
	report := Evaluate(passingEvidence())
	if report.Status != StatusPass || report.Code != "PASS" || report.RunID != "run-20260827-review-fix" || len(report.ConfigDigest) != 64 {
		t.Fatalf("Evaluate() = %#v", report)
	}
}

func TestEvaluatePreservesValidDownLeakWhenSiblingRecordIsMalformed(t *testing.T) {
	evidence := passingEvidence()
	evidence.TelecomDown.Results[0].Reachable = true
	evidence.TelecomDown.InvalidRecords = 1
	evidence.InventoryAfter = nil

	report := Evaluate(evidence)
	if report.Status != StatusFail || report.Code != "FAIL_LEAK" {
		t.Fatalf("Evaluate() = %#v, want leak precedence", report)
	}
}

func TestEvaluateRejectsMixedStaleAndSyntheticEvidenceAsInconclusive(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{name: "mixed run", mutate: func(e *Evidence) { e.InventoryAfter.RunID = "run-from-somewhere-else" }},
		{name: "mixed config", mutate: func(e *Evidence) {
			e.TelecomUp.ConfigDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "stale", mutate: func(e *Evidence) { e.InventoryBefore.CapturedAt = e.EvaluatedAt.Add(-MaxEvidenceAge - time.Second) }},
		{name: "future", mutate: func(e *Evidence) { e.TelecomUp.FinishedAt = e.EvaluatedAt.Add(MaxClockSkew + time.Second) }},
		{name: "empty inventory", mutate: func(e *Evidence) { e.InventoryBefore.State = inventory.State{} }},
		{name: "empty probe", mutate: func(e *Evidence) { e.TelecomUp.Results = nil }},
		{name: "empty firewall", mutate: func(e *Evidence) { e.InventoryAfter.State.FirewallRules = nil }},
		{name: "omitted NAT collection", mutate: func(e *Evidence) { e.InventoryAfter.State.NAT = nil }},
		{name: "omitted firewall filter collection", mutate: func(e *Evidence) { e.InventoryAfter.State.FirewallRules[0].OverrideBlockRules = nil }},
		{name: "malformed sibling", mutate: func(e *Evidence) { e.TelecomDown.InvalidRecords = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := passingEvidence()
			test.mutate(&evidence)
			report := Evaluate(evidence)
			if report.Status != StatusInconclusive || report.Code != "INCONCLUSIVE_INVALID_EVIDENCE" {
				t.Fatalf("Evaluate() = %#v", report)
			}
		})
	}
}

func TestEvaluateRejectsMissingOrDecodeFailedArtifacts(t *testing.T) {
	evidence := passingEvidence()
	evidence.InventoryBefore = nil
	evidence.ArtifactErrors = []string{"inventory-before.json: unknown field"}

	report := Evaluate(evidence)
	if report.Status != StatusInconclusive {
		t.Fatalf("Evaluate() = %#v", report)
	}
}

func TestEvaluateRequiresExactConfiguredTargetNamesAndURLs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{name: "wrong name", mutate: func(e *Evidence) { e.TelecomDown.Results[0].TargetName = "other-approved" }},
		{name: "wrong URL", mutate: func(e *Evidence) { e.TelecomUp.Results[0].TargetURL = "https://approved.example.invalid/other" }},
		{name: "duplicate", mutate: func(e *Evidence) { e.TelecomUp.Results = append(e.TelecomUp.Results, e.TelecomUp.Results[0]) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := passingEvidence()
			test.mutate(&evidence)
			report := Evaluate(evidence)
			if report.Status != StatusInconclusive || report.Code != "INCONCLUSIVE_INVALID_EVIDENCE" {
				t.Fatalf("Evaluate() = %#v", report)
			}
		})
	}
}

func TestEvaluateRejectsInvalidChronology(t *testing.T) {
	evidence := passingEvidence()
	evidence.TelecomDown.StartedAt = evidence.TelecomUp.FinishedAt.Add(-time.Second)

	report := Evaluate(evidence)
	if report.Status != StatusInconclusive || report.Code != "INCONCLUSIVE_INVALID_EVIDENCE" {
		t.Fatalf("Evaluate() = %#v", report)
	}
}

func TestEvaluateDetectsEveryCapturedStateClassDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*inventory.State)
	}{
		{name: "interface forwarding", mutate: func(s *inventory.State) { s.Interfaces[0].Forwarding = "Enabled" }},
		{name: "route", mutate: func(s *inventory.State) { s.Routes[0].Metric++ }},
		{name: "NAT", mutate: func(s *inventory.State) {
			s.NAT[0].TcpFilteringBehavior = "EndpointIndependentFiltering"
		}},
		{name: "NAT timeout", mutate: func(s *inventory.State) { s.NAT[0].TcpEstablishedConnectionTimeout++ }},
		{name: "firewall rule policy", mutate: func(s *inventory.State) { s.FirewallRules[0].EdgeTraversalPolicy = "Allow" }},
		{name: "firewall interface type", mutate: func(s *inventory.State) { s.FirewallRules[0].InterfaceTypes = []string{"Wireless"} }},
		{name: "firewall ICMP type", mutate: func(s *inventory.State) { s.FirewallRules[0].IcmpTypes = []string{"8:Any"} }},
		{name: "firewall dynamic target", mutate: func(s *inventory.State) { s.FirewallRules[0].DynamicTargets = []string{"ProximityApps"} }},
		{name: "firewall package", mutate: func(s *inventory.State) { s.FirewallRules[0].Packages = []string{"S-1-15-2-99"} }},
		{name: "firewall security", mutate: func(s *inventory.State) { s.FirewallRules[0].Authentications = []string{"Required"} }},
		{name: "firewall authenticated bypass", mutate: func(s *inventory.State) { s.FirewallRules[0].OverrideBlockRules = []bool{true} }},
		{name: "firewall dynamic keyword", mutate: func(s *inventory.State) {
			s.FirewallRules[0].RemoteDynamicKeywordAddresses = []string{"{01234567-89ab-cdef-0123-456789abcdef}"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := passingEvidence()
			test.mutate(&evidence.InventoryAfter.State)
			report := Evaluate(evidence)
			if report.Status != StatusFail || report.Code != "FAIL_STATE_DRIFT" {
				t.Fatalf("Evaluate() = %#v", report)
			}
		})
	}
}

func TestEvaluateIgnoresInventoryOrderingOnly(t *testing.T) {
	evidence := passingEvidence()
	evidence.InventoryAfter.State.Interfaces[0], evidence.InventoryAfter.State.Interfaces[1] = evidence.InventoryAfter.State.Interfaces[1], evidence.InventoryAfter.State.Interfaces[0]
	evidence.InventoryAfter.State.Routes[0], evidence.InventoryAfter.State.Routes[1] = evidence.InventoryAfter.State.Routes[1], evidence.InventoryAfter.State.Routes[0]
	evidence.InventoryAfter.State.FirewallRules[0].RemoteAddresses = []string{"192.0.2.0/24", "Internet"}
	evidence.InventoryBefore.State.FirewallRules[0].RemoteAddresses = []string{"Internet", "192.0.2.0/24"}
	evidence.InventoryAfter.State.FirewallRules[0].Authentications = []string{"Required", "NotRequired"}
	evidence.InventoryBefore.State.FirewallRules[0].Authentications = []string{"NotRequired", "Required"}

	report := Evaluate(evidence)
	if report.Status != StatusPass {
		t.Fatalf("Evaluate() = %#v", report)
	}
}

func TestEvaluateTreatsAutomaticReconnectAsFailure(t *testing.T) {
	evidence := passingEvidence()
	evidence.DownMonitor.ReconnectDetected = true
	evidence.DownMonitor.ReconnectAt = evidence.DownMonitor.StartedAt.Add(time.Second)
	evidence.DownMonitor.ReconnectInterfaceUp = true
	evidence.DownMonitor.ReconnectRoutes = []MonitorRoute{{DestinationPrefix: "0.0.0.0/0", NextHop: "198.51.100.1", State: "Alive"}}

	report := Evaluate(evidence)
	if report.Status != StatusFail || report.Code != "FAIL_TELECOM_RECONNECTED" {
		t.Fatalf("Evaluate() = %#v", report)
	}
}

func TestEvaluateRequiresHealthyUpPathRatherThanReachabilityAlone(t *testing.T) {
	evidence := passingEvidence()
	evidence.TelecomUp.Results[0].Healthy = false
	evidence.TelecomUp.Results[0].Reachable = true

	report := Evaluate(evidence)
	if report.Status != StatusFail || report.Code != "FAIL_NO_FORWARD" {
		t.Fatalf("Evaluate() = %#v", report)
	}
}

func passingEvidence() Evidence {
	now := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	cfg := validVerdictConfig()
	digest, err := config.Digest(cfg)
	if err != nil {
		panic(err)
	}
	newState := func() inventory.State {
		return inventory.State{
			Interfaces: []inventory.Interface{
				{Alias: "Ethernet", Index: 7, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1500},
				{Alias: "Telecom-Client", Index: 11, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1400},
				{Alias: "wg-overseas-poc", Index: 19, AddressFamily: "IPv4", Status: "Connected", Forwarding: "Disabled", MTU: 1420},
			},
			Routes: []inventory.Route{
				{Alias: "Ethernet", Index: 7, DestinationPrefix: "0.0.0.0/0", NextHop: "172.20.10.1", Metric: 25, State: "Alive"},
				{Alias: "wg-overseas-poc", Index: 19, DestinationPrefix: "100.127.77.0/24", NextHop: "0.0.0.0", State: "Alive"},
			},
			NAT: []inventory.NAT{{
				Name: "BaselineNat", InternalPrefix: "100.127.77.0/24", ExternalPrefix: "", Active: true, Store: "PersistentStore",
				TcpFilteringBehavior: "AddressDependentFiltering", UdpFilteringBehavior: "AddressAndPortDependentFiltering", UdpInboundRefresh: false,
				IcmpQueryTimeout: 30, TcpEstablishedConnectionTimeout: 1800, TcpTransientConnectionTimeout: 120, UdpIdleSessionTimeout: 120,
			}},
			FirewallRules: []inventory.FirewallRule{
				{
					Name: "BaselineAllow", DisplayName: "Baseline allow", Description: "", Group: "", Enabled: "True", Profile: "Any", Direction: "Outbound", Action: "Allow",
					EdgeTraversalPolicy: "Block", LooseSourceMapping: false, LocalOnlyMapping: false, Owner: "", PolicyStoreSource: "PersistentStore", PolicyStoreSourceType: "Local",
					Platforms: []string{}, InterfaceAliases: []string{"Ethernet"}, InterfaceTypes: []string{"Lan"}, LocalAddresses: []string{"Any"}, RemoteAddresses: []string{"Internet", "192.0.2.0/24"}, RemoteDynamicKeywordAddresses: []string{},
					Protocols: []string{"TCP"}, LocalPorts: []string{"Any"}, RemotePorts: []string{"443"}, IcmpTypes: []string{}, DynamicTargets: []string{"Any"},
					Programs: []string{"Any"}, Packages: []string{}, Services: []string{"Any"}, Authentications: []string{"NotRequired", "Required"}, Encryptions: []string{"NotRequired"}, OverrideBlockRules: []bool{false}, LocalUsers: []string{"Any"}, RemoteUsers: []string{"Any"}, RemoteMachines: []string{"Any"},
				},
			},
		}
	}
	runID := "run-20260827-review-fix"
	before := &inventory.Artifact{SchemaVersion: EvidenceSchemaVersion, RunID: runID, ConfigDigest: digest, CapturedAt: now.Add(-30 * time.Minute), State: newState()}
	up := &ProbeEvidence{
		SchemaVersion: EvidenceSchemaVersion, RunID: runID, ConfigDigest: digest,
		StartedAt: now.Add(-29 * time.Minute), FinishedAt: now.Add(-28 * time.Minute),
		Results: []ProbeResult{{TargetName: cfg.ApprovedTargets[0].Name, TargetURL: cfg.ApprovedTargets[0].URL, Reachable: true, Healthy: true, StartedAt: now.Add(-29 * time.Minute), FinishedAt: now.Add(-28 * time.Minute)}},
	}
	down := &ProbeEvidence{
		SchemaVersion: EvidenceSchemaVersion, RunID: runID, ConfigDigest: digest,
		StartedAt: now.Add(-26 * time.Minute), FinishedAt: now.Add(-25 * time.Minute),
		Results: []ProbeResult{{TargetName: cfg.ApprovedTargets[0].Name, TargetURL: cfg.ApprovedTargets[0].URL, Reachable: false, Healthy: false, StartedAt: now.Add(-26 * time.Minute), FinishedAt: now.Add(-25 * time.Minute)}},
	}
	monitor := &DownMonitorEvidence{
		SchemaVersion: EvidenceSchemaVersion, RunID: runID, ConfigDigest: digest,
		StartedAt: now.Add(-27 * time.Minute), FinishedAt: now.Add(-24 * time.Minute), SampleCount: 3,
		TelecomRoutePrefixes: append([]string(nil), cfg.TelecomRoutePrefixes...),
	}
	after := &inventory.Artifact{SchemaVersion: EvidenceSchemaVersion, RunID: runID, ConfigDigest: digest, CapturedAt: now.Add(-23 * time.Minute), State: newState()}
	return Evidence{
		RunID: runID, Config: &cfg, EvaluatedAt: now,
		InventoryBefore: before, TelecomUp: up, TelecomDown: down, DownMonitor: monitor, InventoryAfter: after,
	}
}

func validVerdictConfig() config.Config {
	return config.Config{
		WireGuardSubnet: "100.127.77.0/24", WireGuardInterface: "wg-overseas-poc",
		TelecomInterface: "Telecom-Client", TelecomRoutePrefixes: []string{"0.0.0.0/0"}, EmployeeInterface: "Ethernet",
		InternalCIDRs:   []string{"10.0.0.0/8"},
		ApprovedTargets: []config.Target{{Name: "operator-approved-test", URL: "https://approved.example.invalid/health"}},
		ProbeTimeout:    8 * time.Second,
	}
}
