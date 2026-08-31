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
		{name: "server config", edit: func(value *Response) { value.Binding.ServerConfigSHA256 = strings.Repeat("b", 64) }, want: "server config"},
		{name: "action config", edit: func(value *Response) { value.Binding.ActionConfigSHA256 = strings.Repeat("b", 64) }, want: "action config"},
		{name: "upstream", edit: func(value *Response) { value.Binding.FakeUpstreamIdentity = "wrong" }, want: "upstream"},
		{name: "public sentinel", edit: func(value *Response) { value.Binding.PublicSentinelIdentity = "wrong" }, want: "public sentinel"},
		{name: "corporate sentinel", edit: func(value *Response) { value.Binding.CorporateSentinelIdentity = "wrong" }, want: "corporate sentinel"},
		{name: "public endpoint", edit: func(value *Response) { value.Binding.PublicSentinelEndpoint = "wrong" }, want: "public sentinel endpoint"},
		{name: "health endpoint", edit: func(value *Response) { value.Binding.PublicSentinelHealthEndpoint = "wrong" }, want: "public sentinel endpoint"},
		{name: "corporate endpoint", edit: func(value *Response) { value.Binding.CorporateSentinelEndpoint = "wrong" }, want: "corporate sentinel endpoint"},
		{name: "control endpoint", edit: func(value *Response) { value.Binding.FakeUpstreamControlEndpoint = "wrong" }, want: "fake upstream control"},
		{name: "data endpoint", edit: func(value *Response) { value.Binding.FakeUpstreamDataEndpoint = "wrong" }, want: "fake upstream data"},
		{name: "manifest", edit: func(value *Response) { value.Binding.Artifacts.ManifestSHA256 = strings.Repeat("a", 64) }, want: "manifest"},
		{name: "agent artifact", edit: func(value *Response) { value.Binding.Artifacts.AgentSHA256 = strings.Repeat("a", 64) }, want: "agent"},
		{name: "core artifact", edit: func(value *Response) { value.Binding.Artifacts.CoreSHA256 = strings.Repeat("a", 64) }, want: "core"},
		{name: "ui artifact", edit: func(value *Response) { value.Binding.Artifacts.UISHA256 = strings.Repeat("a", 64) }, want: "ui"},
		{name: "server service artifact", edit: func(value *Response) { value.Binding.Artifacts.ServerServiceSHA256 = strings.Repeat("a", 64) }, want: "server-service"},
		{name: "driver artifact", edit: func(value *Response) { value.Binding.Artifacts.DriverSHA256 = strings.Repeat("0", 64) }, want: "driver"},
		{name: "sentinel artifact", edit: func(value *Response) { value.Binding.Artifacts.SentinelSHA256 = strings.Repeat("a", 64) }, want: "sentinel"},
		{name: "action helper artifact", edit: func(value *Response) { value.Binding.Artifacts.ActionHelperSHA256 = strings.Repeat("a", 64) }, want: "action-helper"},
		{name: "powershell artifact", edit: func(value *Response) { value.Binding.Artifacts.PowerShellSHA256 = strings.Repeat("a", 64) }, want: "powershell"},
		{name: "installer artifact", edit: func(value *Response) { value.Binding.Artifacts.InstallerSHA256 = strings.Repeat("a", 64) }, want: "installer"},
		{name: "capture artifact", edit: func(value *Response) { value.Binding.Artifacts.CaptureScriptSHA256 = strings.Repeat("a", 64) }, want: "capture-script"},
		{name: "corporate cidr", edit: func(value *Response) { value.Binding.Network.CorporateCIDRs[0] = "10.0.0.0/8" }, want: "corporate network"},
		{name: "corporate dns", edit: func(value *Response) { value.Binding.Network.CorporateDNS[0] = "10.0.0.53" }, want: "corporate network"},
		{name: "internal suffix", edit: func(value *Response) { value.Binding.Network.InternalSuffixes[0] = "evil.test" }, want: "corporate network"},
		{name: "payload file", edit: func(value *Response) { value.Binding.PayloadFiles[0].SHA256 = strings.Repeat("0", 64) }, want: "payload files"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := validResponse(request, expected)
			test.edit(&changed)
			if err := ValidateResponse(request, expected, changed); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("ValidateResponse() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSnapshotRequiresCompletePayloadHashesNoUnexpectedFilesAndNoLocalServerResidue(t *testing.T) {
	binding := validBinding()
	snapshot := validSnapshot("nonce-1")
	snapshot.InstalledFiles = []FileRecord{{Role: "payload", Name: binding.PayloadFiles[0].Name, Path: binding.PayloadFiles[0].Path, ExpectedSHA256: binding.PayloadFiles[0].SHA256, Present: true, SHA256: binding.PayloadFiles[0].SHA256}}
	snapshot.UnexpectedFiles = []FileRecord{}
	snapshot.OwnedRoots = []RootRecord{{Path: `C:\Program Files\RegenBio\OverseasAccess`, Present: true}, {Path: `C:\ProgramData\RegenBio\OverseasAccess`, Present: true}}
	if err := snapshot.Validate("nonce-1", binding); err != nil {
		t.Fatalf("Validate()=%v", err)
	}

	changed := snapshot.Clone()
	changed.InstalledFiles = nil
	if err := changed.Validate("nonce-1", binding); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("missing payload Validate()=%v", err)
	}
	changed = snapshot.Clone()
	changed.UnexpectedFiles = []FileRecord{{Role: "unexpected", Name: "foreign.dll", Path: `C:\Program Files\RegenBio\OverseasAccess\foreign.dll`, Present: true, SHA256: strings.Repeat("f", 64)}}
	if err := changed.Validate("nonce-1", binding); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("unexpected file Validate()=%v", err)
	}
	changed = snapshot.Clone()
	changed.RuntimeFiles = append(changed.RuntimeFiles, FileRecord{Role: "server-config", Path: `C:\ProgramData\RegenBio\OverseasAccessServer\config.json`, ExpectedSHA256: binding.ServerConfigSHA256, Present: true, SHA256: binding.ServerConfigSHA256})
	if err := changed.Validate("nonce-1", binding); err == nil || !strings.Contains(strings.ToLower(err.Error()), "local server config residue") {
		t.Fatalf("server config residue Validate()=%v", err)
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

func TestValidateResponseRequiresMachineRecoveryResidueBeforeRecovery(t *testing.T) {
	request := validRequest()
	request.Action = "stage-machine-recovery"
	response := validResponse(request, validBinding())
	response.Evidence.Facts = map[string]string{
		"host_identity": "host-1", "post_state_sha256": strings.Repeat("4", 64),
		"agent_absent": "true", "owned_firewall_present": "true",
	}
	if err := ValidateResponse(request, validBinding(), response); err == nil || !strings.Contains(err.Error(), "recovery_staged") {
		t.Fatalf("ValidateResponse() = %v, want recovery staging evidence refusal", err)
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
		{name: "msi", edit: func(value *Snapshot) { value.MSIRegistrations = nil }, want: "msi"},
		{name: "installed files", edit: func(value *Snapshot) { value.InstalledFiles = nil }, want: "installed files"},
		{name: "runtime files", edit: func(value *Snapshot) { value.RuntimeFiles = nil }, want: "runtime files"},
		{name: "registry", edit: func(value *Snapshot) { value.RegistryRecords = nil }, want: "registry"},
		{name: "ownership", edit: func(value *Snapshot) { value.OwnershipArtifacts = nil }, want: "ownership"},
		{name: "recovery", edit: func(value *Snapshot) { value.RecoveryArtifacts = nil }, want: "recovery"},
		{name: "transactions", edit: func(value *Snapshot) { value.TransactionArtifacts = nil }, want: "transaction"},
		{name: "fixture residue", edit: func(value *Snapshot) { value.FixtureResidues = nil }, want: "fixture residue"},
		{name: "listeners", edit: func(value *Snapshot) { value.Listeners = nil }, want: "listener"},
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

func TestSnapshotRejectsWrongHashForPresentBoundArtifacts(t *testing.T) {
	binding := validBinding()
	tests := []struct {
		name string
		edit func(*Snapshot)
	}{
		{name: "process", edit: func(value *Snapshot) {
			value.Processes[0] = ProcessRecord{Role: "agent", Present: true, PID: 44, ImagePath: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, ImageSHA256: strings.Repeat("f", 64)}
		}},
		{name: "service", edit: func(value *Snapshot) {
			value.Services[0] = ServiceRecord{Role: "agent", Name: "RegenBioOverseasAccessAgent", Present: true, Status: "Running", StartMode: "Automatic", Path: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, PathSHA256: strings.Repeat("f", 64)}
		}},
		{name: "file", edit: func(value *Snapshot) {
			value.InstalledFiles[0] = FileRecord{Role: "agent", Path: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, Present: true, SHA256: strings.Repeat("f", 64)}
		}},
		{name: "runtime config", edit: func(value *Snapshot) {
			value.RuntimeFiles[0] = FileRecord{Role: "config", Path: `C:\ProgramData\RegenBio\OverseasAccess\sing-box.json`, Present: true, SHA256: strings.Repeat("f", 64)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validSnapshot("nonce-1")
			test.edit(&value)
			if err := value.Validate("nonce-1", binding); err == nil || !strings.Contains(strings.ToLower(err.Error()), "hash") {
				t.Fatalf("Validate() = %v, want bound hash rejection", err)
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
	return FixtureBinding{PayloadSHA256: strings.Repeat("2", 64), ConfigSHA256: strings.Repeat("3", 64), ServerConfigSHA256: strings.Repeat("4", 64), ActionConfigSHA256: strings.Repeat("5", 64), FakeUpstreamIdentity: "fake-upstream/1", PublicSentinelIdentity: "public/1", CorporateSentinelIdentity: "corporate/1", PublicSentinelEndpoint: "198.18.0.2:18080", PublicSentinelHealthEndpoint: "172.20.9.251:18080", CorporateSentinelEndpoint: "172.20.9.250:18081", FakeUpstreamControlEndpoint: "172.20.9.15:18082", FakeUpstreamDataEndpoint: "172.20.9.15:18083", ServerListenerEndpoint: "172.20.9.15:18443", Network: NetworkBinding{CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"}, InternalSuffixes: []string{"intra.regen-bio.com"}}, PayloadFiles: []PayloadFileBinding{{Name: "overseas-agent.exe", Path: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, SHA256: strings.Repeat("6", 64)}}, Artifacts: ArtifactBinding{ManifestSHA256: strings.Repeat("5", 64), AgentSHA256: strings.Repeat("6", 64), CoreSHA256: strings.Repeat("7", 64), UISHA256: strings.Repeat("8", 64), ServerServiceSHA256: strings.Repeat("9", 64), DriverSHA256: strings.Repeat("a", 64), SentinelSHA256: strings.Repeat("b", 64), ActionHelperSHA256: strings.Repeat("c", 64), PowerShellSHA256: strings.Repeat("d", 64), InstallerSHA256: strings.Repeat("e", 64), CaptureScriptSHA256: strings.Repeat("f", 64)}}
}

func validResponse(request Request, binding FixtureBinding) Response {
	binding.Network.CorporateCIDRs = append([]string(nil), binding.Network.CorporateCIDRs...)
	binding.Network.CorporateDNS = append([]string(nil), binding.Network.CorporateDNS...)
	binding.Network.InternalSuffixes = append([]string(nil), binding.Network.InternalSuffixes...)
	binding.PayloadFiles = append([]PayloadFileBinding(nil), binding.PayloadFiles...)
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
		ObservationNonce:     nonce,
		Adapters:             []AdapterRecord{{InterfaceIndex: 7, InterfaceGUID: "{guid}", InterfaceAlias: "Ethernet", Status: "Up"}},
		Routes:               []RouteRecord{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7, NextHop: "192.0.2.1", RouteMetric: 10}},
		DNS:                  []DNSRecord{{InterfaceIndex: 7, InterfaceAlias: "Ethernet", ServerAddresses: []string{"192.0.2.53"}}},
		Services:             []ServiceRecord{{Name: "RegenBioOverseasAccessAgent", Present: false, Status: "Absent", StartMode: "Absent"}},
		Processes:            []ProcessRecord{{Role: "agent", Present: false}, {Role: "core", Present: false}, {Role: "ui", Present: false}, {Role: "fake-upstream", Present: false}},
		OwnedFirewallRules:   []FirewallRecord{{Name: "RegenBioOverseasAccess.Managed", Present: false, DefinitionSHA256: strings.Repeat("0", 64)}},
		MSIRegistrations:     []MSIRecord{{ProductCode: "{D1234567-89AB-4CDE-8012-3456789ABCDE}", Present: false}},
		InstalledFiles:       []FileRecord{{Role: "payload", Name: "overseas-agent.exe", Path: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, ExpectedSHA256: strings.Repeat("6", 64), Present: false}},
		UnexpectedFiles:      []FileRecord{},
		OwnedRoots:           []RootRecord{{Path: `C:\Program Files\RegenBio\OverseasAccess`, Present: false}, {Path: `C:\ProgramData\RegenBio\OverseasAccess`, Present: false}},
		RuntimeFiles:         []FileRecord{{Role: "credential", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`, Present: false}},
		RegistryRecords:      []StateRecord{{Kind: "registry", Name: `HKLM\Software\RegenBio\OverseasAccess`, Present: false}},
		OwnershipArtifacts:   []StateRecord{{Kind: "ownership", Name: "runtime-owned.json", Present: false}},
		RecoveryArtifacts:    []StateRecord{{Kind: "recovery", Name: "machine-recovery", Present: false}},
		TransactionArtifacts: []StateRecord{{Kind: "transaction", Name: "installer-journal", Present: false}},
		FixtureResidues:      []StateRecord{{Kind: "fixture-residue", Name: "fixture-service", Present: false}},
		Listeners:            []ListenerRecord{{Role: "fake-upstream", Endpoint: "172.20.9.15:18083", Present: false}},
	}
}
