package fixtureproto

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const ProtocolVersion = 4

type Request struct {
	ProtocolVersion           int    `json:"protocol_version"`
	RequestNonce              string `json:"request_nonce"`
	RunID                     string `json:"run_id"`
	Action                    string `json:"action"`
	Scenario                  string `json:"scenario,omitempty"`
	EvidenceDirectory         string `json:"evidence_directory"`
	EvidenceDirectoryIdentity string `json:"evidence_directory_identity"`
	BaselinePath              string `json:"baseline_path,omitempty"`
	BaselineSHA256            string `json:"baseline_sha256,omitempty"`
}

type FixtureBinding struct {
	PayloadSHA256                string               `json:"payload_sha256"`
	ConfigSHA256                 string               `json:"config_sha256"`
	ServerConfigSHA256           string               `json:"server_config_sha256"`
	ActionConfigSHA256           string               `json:"action_config_sha256"`
	FakeUpstreamIdentity         string               `json:"fake_upstream_identity"`
	PublicSentinelIdentity       string               `json:"public_sentinel_identity"`
	CorporateSentinelIdentity    string               `json:"corporate_sentinel_identity"`
	PublicSentinelEndpoint       string               `json:"public_sentinel_endpoint"`
	PublicSentinelHealthEndpoint string               `json:"public_sentinel_health_endpoint"`
	CorporateSentinelEndpoint    string               `json:"corporate_sentinel_endpoint"`
	FakeUpstreamControlEndpoint  string               `json:"fake_upstream_control_endpoint"`
	FakeUpstreamDataEndpoint     string               `json:"fake_upstream_data_endpoint"`
	ServerListenerEndpoint       string               `json:"server_listener_endpoint"`
	Network                      NetworkBinding       `json:"network"`
	PayloadFiles                 []PayloadFileBinding `json:"payload_files"`
	Artifacts                    ArtifactBinding      `json:"artifacts"`
}

type NetworkBinding struct {
	CorporateCIDRs   []string `json:"corporate_cidrs"`
	CorporateDNS     []string `json:"corporate_dns"`
	InternalSuffixes []string `json:"internal_suffixes"`
}

type PayloadFileBinding struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ArtifactBinding struct {
	ManifestSHA256      string `json:"manifest_sha256"`
	AgentSHA256         string `json:"agent_sha256"`
	CoreSHA256          string `json:"core_sha256"`
	UISHA256            string `json:"ui_sha256"`
	ServerServiceSHA256 string `json:"server_service_sha256"`
	DriverSHA256        string `json:"driver_sha256"`
	SentinelSHA256      string `json:"sentinel_sha256"`
	ActionHelperSHA256  string `json:"action_helper_sha256"`
	PowerShellSHA256    string `json:"powershell_sha256"`
	InstallerSHA256     string `json:"installer_sha256"`
	CaptureScriptSHA256 string `json:"capture_script_sha256"`
}

type ActionEvidence struct {
	Kind             string            `json:"kind"`
	ObservationNonce string            `json:"observation_nonce"`
	Facts            map[string]string `json:"facts"`
}

type Response struct {
	ProtocolVersion int            `json:"protocol_version"`
	RequestNonce    string         `json:"request_nonce"`
	RunID           string         `json:"run_id"`
	Scenario        string         `json:"scenario,omitempty"`
	Action          string         `json:"action"`
	OK              bool           `json:"ok"`
	Binding         FixtureBinding `json:"binding"`
	Evidence        ActionEvidence `json:"evidence"`
	Snapshot        Snapshot       `json:"snapshot,omitempty"`
	ErrorCode       string         `json:"error_code,omitempty"`
}

type Snapshot struct {
	ObservationNonce     string           `json:"observation_nonce"`
	Adapters             []AdapterRecord  `json:"adapters"`
	Routes               []RouteRecord    `json:"routes"`
	DNS                  []DNSRecord      `json:"dns"`
	Services             []ServiceRecord  `json:"services"`
	Processes            []ProcessRecord  `json:"processes"`
	OwnedFirewallRules   []FirewallRecord `json:"owned_firewall_rules"`
	MSIRegistrations     []MSIRecord      `json:"msi_registrations"`
	InstalledFiles       []FileRecord     `json:"installed_files"`
	UnexpectedFiles      []FileRecord     `json:"unexpected_files"`
	OwnedRoots           []RootRecord     `json:"owned_roots"`
	RuntimeFiles         []FileRecord     `json:"runtime_files"`
	RegistryRecords      []StateRecord    `json:"registry_records"`
	OwnershipArtifacts   []StateRecord    `json:"ownership_artifacts"`
	RecoveryArtifacts    []StateRecord    `json:"recovery_artifacts"`
	TransactionArtifacts []StateRecord    `json:"transaction_artifacts"`
	FixtureResidues      []StateRecord    `json:"fixture_residues"`
	Listeners            []ListenerRecord `json:"listeners"`
}

type AdapterRecord struct {
	InterfaceIndex int    `json:"interface_index"`
	InterfaceGUID  string `json:"interface_guid"`
	InterfaceAlias string `json:"interface_alias"`
	Status         string `json:"status"`
}

type RouteRecord struct {
	DestinationPrefix string `json:"destination_prefix"`
	InterfaceIndex    int    `json:"interface_index"`
	NextHop           string `json:"next_hop"`
	RouteMetric       int    `json:"route_metric"`
}

type DNSRecord struct {
	InterfaceIndex  int      `json:"interface_index"`
	InterfaceAlias  string   `json:"interface_alias"`
	ServerAddresses []string `json:"server_addresses"`
}

type ServiceRecord struct {
	Role       string `json:"role,omitempty"`
	Name       string `json:"name"`
	Present    bool   `json:"present"`
	Status     string `json:"status"`
	StartMode  string `json:"start_mode"`
	Path       string `json:"path,omitempty"`
	PathSHA256 string `json:"path_sha256,omitempty"`
	PID        int    `json:"pid,omitempty"`
}

type MSIRecord struct {
	ProductCode   string `json:"product_code"`
	Present       bool   `json:"present"`
	Version       string `json:"version,omitempty"`
	PackageSHA256 string `json:"package_sha256,omitempty"`
}

type FileRecord struct {
	Role           string `json:"role"`
	Name           string `json:"name,omitempty"`
	Path           string `json:"path"`
	Present        bool   `json:"present"`
	SHA256         string `json:"sha256,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

type RootRecord struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
}

type StateRecord struct {
	Kind             string `json:"kind"`
	Name             string `json:"name"`
	Present          bool   `json:"present"`
	DefinitionSHA256 string `json:"definition_sha256,omitempty"`
}

type ListenerRecord struct {
	Role        string `json:"role"`
	Endpoint    string `json:"endpoint"`
	Present     bool   `json:"present"`
	PID         int    `json:"pid,omitempty"`
	ImagePath   string `json:"image_path,omitempty"`
	ImageSHA256 string `json:"image_sha256,omitempty"`
}

type ProcessRecord struct {
	Role        string `json:"role"`
	Present     bool   `json:"present"`
	PID         int    `json:"pid,omitempty"`
	ParentPID   int    `json:"parent_pid,omitempty"`
	ImagePath   string `json:"image_path,omitempty"`
	ImageSHA256 string `json:"image_sha256,omitempty"`
}

type FirewallRecord struct {
	Name             string `json:"name"`
	Present          bool   `json:"present"`
	DefinitionSHA256 string `json:"definition_sha256"`
}

func ValidateResponse(request Request, expected FixtureBinding, response Response) error {
	if response.ProtocolVersion != ProtocolVersion || request.ProtocolVersion != ProtocolVersion {
		return errors.New("protocol version mismatch")
	}
	if response.RequestNonce != request.RequestNonce || strings.TrimSpace(request.RequestNonce) == "" {
		return errors.New("request nonce mismatch")
	}
	if response.RunID != request.RunID || strings.TrimSpace(request.RunID) == "" {
		return errors.New("run binding mismatch")
	}
	if response.Scenario != request.Scenario {
		return errors.New("scenario binding mismatch")
	}
	if response.Action != request.Action {
		return errors.New("action binding mismatch")
	}
	if !response.OK {
		return fmt.Errorf("driver refused action with code %q", response.ErrorCode)
	}
	if response.Binding.PayloadSHA256 != expected.PayloadSHA256 || !validSHA256(response.Binding.PayloadSHA256) {
		return errors.New("payload hash binding mismatch")
	}
	if response.Binding.ConfigSHA256 != expected.ConfigSHA256 || !validSHA256(response.Binding.ConfigSHA256) {
		return errors.New("config hash binding mismatch")
	}
	if response.Binding.ServerConfigSHA256 != expected.ServerConfigSHA256 || !validSHA256(response.Binding.ServerConfigSHA256) {
		return errors.New("server config hash binding mismatch")
	}
	if response.Binding.ActionConfigSHA256 != expected.ActionConfigSHA256 || !validSHA256(response.Binding.ActionConfigSHA256) {
		return errors.New("action config hash binding mismatch")
	}
	if response.Binding.FakeUpstreamIdentity != expected.FakeUpstreamIdentity || response.Binding.FakeUpstreamIdentity == "" {
		return errors.New("fake upstream identity mismatch")
	}
	if response.Binding.PublicSentinelIdentity != expected.PublicSentinelIdentity || response.Binding.PublicSentinelIdentity == "" {
		return errors.New("public sentinel identity mismatch")
	}
	if response.Binding.CorporateSentinelIdentity != expected.CorporateSentinelIdentity || response.Binding.CorporateSentinelIdentity == "" {
		return errors.New("corporate sentinel identity mismatch")
	}
	if response.Binding.PublicSentinelEndpoint != expected.PublicSentinelEndpoint || response.Binding.PublicSentinelEndpoint == "" || response.Binding.PublicSentinelHealthEndpoint != expected.PublicSentinelHealthEndpoint || response.Binding.PublicSentinelHealthEndpoint == "" {
		return errors.New("public sentinel endpoint binding mismatch")
	}
	if response.Binding.CorporateSentinelEndpoint != expected.CorporateSentinelEndpoint || response.Binding.CorporateSentinelEndpoint == "" {
		return errors.New("corporate sentinel endpoint binding mismatch")
	}
	if response.Binding.FakeUpstreamControlEndpoint != expected.FakeUpstreamControlEndpoint || response.Binding.FakeUpstreamControlEndpoint == "" {
		return errors.New("fake upstream control endpoint binding mismatch")
	}
	if response.Binding.FakeUpstreamDataEndpoint != expected.FakeUpstreamDataEndpoint || response.Binding.FakeUpstreamDataEndpoint == "" {
		return errors.New("fake upstream data endpoint binding mismatch")
	}
	if response.Binding.ServerListenerEndpoint != expected.ServerListenerEndpoint || response.Binding.ServerListenerEndpoint == "" {
		return errors.New("server listener endpoint binding mismatch")
	}
	if !equalNetworkBinding(response.Binding.Network, expected.Network) {
		return errors.New("corporate network binding mismatch")
	}
	if !equalPayloadBindings(response.Binding.PayloadFiles, expected.PayloadFiles) {
		return errors.New("payload files binding mismatch")
	}
	if err := response.Binding.Artifacts.validateEqual(expected.Artifacts); err != nil {
		return err
	}
	if response.Evidence.Kind != request.Action {
		return errors.New("action evidence kind mismatch")
	}
	if response.Evidence.ObservationNonce != request.RequestNonce {
		return errors.New("action evidence observation nonce mismatch")
	}
	if len(response.Evidence.Facts) == 0 {
		return errors.New("action evidence facts are absent")
	}
	if strings.TrimSpace(response.Evidence.Facts["host_identity"]) == "" {
		return errors.New("action evidence lacks host identity")
	}
	if err := response.Snapshot.Validate(request.RequestNonce, expected); err != nil {
		return err
	}
	if !validSHA256(response.Evidence.Facts["post_state_sha256"]) {
		return errors.New("action evidence lacks post-state hash")
	}
	for name, expectedValue := range requiredFacts(request.Action) {
		value, exists := response.Evidence.Facts[name]
		if !exists || (expectedValue != "" && value != expectedValue) {
			return fmt.Errorf("action evidence lacks %s=%s", name, expectedValue)
		}
	}
	if request.Action == "restore" && response.Evidence.Facts["restore_input_sha256"] != request.BaselineSHA256 {
		return errors.New("restore input hash does not match trusted request")
	}
	return nil
}

func (a ArtifactBinding) validateEqual(expected ArtifactBinding) error {
	values := []struct{ name, got, want string }{
		{"manifest", a.ManifestSHA256, expected.ManifestSHA256}, {"agent", a.AgentSHA256, expected.AgentSHA256},
		{"core", a.CoreSHA256, expected.CoreSHA256}, {"ui", a.UISHA256, expected.UISHA256},
		{"server-service", a.ServerServiceSHA256, expected.ServerServiceSHA256}, {"driver", a.DriverSHA256, expected.DriverSHA256},
		{"sentinel", a.SentinelSHA256, expected.SentinelSHA256}, {"action-helper", a.ActionHelperSHA256, expected.ActionHelperSHA256},
		{"powershell", a.PowerShellSHA256, expected.PowerShellSHA256}, {"installer", a.InstallerSHA256, expected.InstallerSHA256},
		{"capture-script", a.CaptureScriptSHA256, expected.CaptureScriptSHA256},
	}
	for _, value := range values {
		if value.got != value.want || !validSHA256(value.got) {
			return fmt.Errorf("%s artifact hash binding mismatch", value.name)
		}
	}
	return nil
}

func requiredFacts(action string) map[string]string {
	switch action {
	case "preflight":
		return map[string]string{"payload_sha256": "", "config_sha256": "", "sentinel_identities_verified": "true"}
	case "capture":
		return map[string]string{"snapshot_sha256": ""}
	case "case-setup":
		return map[string]string{"service_present": "true", "agent_hash_verified": "true", "installed_hashes_verified": "true", "credential_provisioned": "true", "server_identity_verified": "true", "unexpected_files_absent": "true"}
	case "fake-upstream-start":
		return map[string]string{"fake_upstream_present": "true", "fake_listener_hash_verified": "true"}
	case "fake-upstream-stop":
		return map[string]string{"fake_upstream_absent": "true"}
	case "core-crash":
		return map[string]string{"core_absent": "true", "owned_firewall_present": "true"}
	case "ui-start":
		return map[string]string{"ui_present": "true", "ui_hash_verified": "true"}
	case "ui-exit":
		return map[string]string{"ui_absent": "true"}
	case "agent-crash":
		return map[string]string{"agent_absent": "true", "owned_firewall_present": "true"}
	case "stage-machine-recovery":
		return map[string]string{"agent_absent": "true", "owned_firewall_present": "true", "recovery_staged": "true"}
	case "agent-start":
		return map[string]string{"service_present": "true", "agent_hash_verified": "true", "core_absent": "true", "tun_absent": "true", "owned_firewall_absent": "true"}
	case "machine-recover":
		return map[string]string{"service_present": "true", "agent_hash_verified": "true", "core_absent": "true", "tun_absent": "true", "owned_firewall_absent": "true", "fixture_recovery_absent": "true"}
	case "uninstall":
		return map[string]string{"service_absent": "true", "agent_absent": "true", "core_absent": "true", "ui_absent": "true", "server_service_absent": "true", "server_identity_absent": "true", "tun_absent": "true", "owned_firewall_absent": "true", "msi_absent": "true", "installed_files_absent": "true", "unexpected_files_absent": "true", "owned_roots_absent": "true", "runtime_files_absent": "true", "registry_absent": "true", "ownership_absent": "true", "recovery_absent": "true", "transactions_absent": "true", "fixture_product_residue_absent": "true"}
	case "case-cleanup":
		return map[string]string{"core_absent": "true", "ui_absent": "true", "fake_upstream_absent": "true"}
	case "restore":
		return map[string]string{"restore_input_sha256": "", "state_restored": "true"}
	default:
		return map[string]string{"unsupported_action": "never"}
	}
}

func (s Snapshot) Validate(expectedNonce string, bindings ...FixtureBinding) error {
	if s.ObservationNonce != expectedNonce || expectedNonce == "" {
		return errors.New("snapshot observation nonce mismatch")
	}
	if len(s.Adapters) == 0 {
		return errors.New("snapshot adapters are empty")
	}
	if len(s.Routes) == 0 {
		return errors.New("snapshot routes are empty")
	}
	if len(s.DNS) == 0 {
		return errors.New("snapshot dns is empty")
	}
	if len(s.Services) == 0 {
		return errors.New("snapshot services are empty")
	}
	if len(s.Processes) == 0 {
		return errors.New("snapshot processes are empty")
	}
	if len(s.OwnedFirewallRules) == 0 {
		return errors.New("snapshot firewall records are empty")
	}
	for _, surface := range []struct {
		name   string
		length int
	}{
		{"msi", len(s.MSIRegistrations)}, {"payload installed files", len(s.InstalledFiles)}, {"runtime files", len(s.RuntimeFiles)},
		{"registry", len(s.RegistryRecords)}, {"ownership", len(s.OwnershipArtifacts)}, {"recovery", len(s.RecoveryArtifacts)},
		{"transaction", len(s.TransactionArtifacts)}, {"fixture residue", len(s.FixtureResidues)}, {"listener", len(s.Listeners)},
	} {
		if surface.length == 0 {
			return fmt.Errorf("snapshot %s records are empty", surface.name)
		}
	}
	if s.UnexpectedFiles == nil {
		return errors.New("snapshot unexpected-file records are absent")
	}
	if len(s.UnexpectedFiles) != 0 {
		return errors.New("snapshot contains unexpected files in owned roots")
	}
	if s.OwnedRoots == nil || len(s.OwnedRoots) != 2 {
		return errors.New("snapshot owned-root records are incomplete")
	}
	wantedRoots := map[string]bool{strings.ToLower(`C:\Program Files\RegenBio\OverseasAccess`): false, strings.ToLower(`C:\ProgramData\RegenBio\OverseasAccess`): false}
	for _, root := range s.OwnedRoots {
		key := strings.ToLower(root.Path)
		if _, ok := wantedRoots[key]; !ok || wantedRoots[key] {
			return errors.New("snapshot owned-root record is invalid")
		}
		wantedRoots[key] = true
	}
	for _, value := range s.Adapters {
		if value.InterfaceIndex <= 0 || value.InterfaceGUID == "" || value.InterfaceAlias == "" || value.Status == "" {
			return errors.New("snapshot adapter record is incomplete")
		}
	}
	for _, value := range s.Routes {
		if value.DestinationPrefix == "" || value.InterfaceIndex <= 0 || value.NextHop == "" || value.RouteMetric < 0 {
			return errors.New("snapshot routes contain an incomplete record")
		}
	}
	for _, value := range s.DNS {
		if value.InterfaceIndex <= 0 || value.InterfaceAlias == "" || len(value.ServerAddresses) == 0 {
			return errors.New("snapshot dns contains an incomplete record")
		}
	}
	for _, value := range s.Services {
		if value.Name == "" || value.Status == "" || value.StartMode == "" || (value.Present && (value.Path == "" || !validSHA256(value.PathSHA256))) {
			return errors.New("snapshot services contain an incomplete record")
		}
		if value.Present && value.Role == "action-helper" && value.PID <= 0 {
			return errors.New("snapshot action-helper service lacks a running PID")
		}
		if len(bindings) > 0 && value.Present && value.Role != "" {
			if expected := bindings[0].Artifacts.hashForRole(value.Role); expected != "" && value.PathSHA256 != expected {
				return fmt.Errorf("service %s image hash mismatch", value.Role)
			}
		}
	}
	roles := make(map[string]struct{}, len(s.Processes))
	for _, value := range s.Processes {
		if value.Role == "" || (value.Present && (value.PID <= 0 || value.ImagePath == "" || !validSHA256(value.ImageSHA256))) {
			return errors.New("snapshot process record is incomplete")
		}
		if _, exists := roles[value.Role]; exists {
			return errors.New("snapshot process role is duplicated")
		}
		roles[value.Role] = struct{}{}
		if len(bindings) > 0 && value.Present {
			if expected := bindings[0].Artifacts.hashForRole(value.Role); expected != "" && value.ImageSHA256 != expected {
				return fmt.Errorf("process %s image hash mismatch", value.Role)
			}
		}
	}
	for _, role := range []string{"agent", "core", "ui", "fake-upstream"} {
		if _, exists := roles[role]; !exists {
			return fmt.Errorf("snapshot process role %s is missing", role)
		}
	}
	for _, value := range s.OwnedFirewallRules {
		if value.Name == "" || !validSHA256(value.DefinitionSHA256) {
			return errors.New("snapshot firewall record is incomplete")
		}
	}
	for _, value := range s.MSIRegistrations {
		if value.ProductCode == "" || (value.Present && (value.Version == "" || !validSHA256(value.PackageSHA256))) {
			return errors.New("snapshot msi record is incomplete")
		}
	}
	for _, records := range [][]FileRecord{s.InstalledFiles, s.RuntimeFiles} {
		for _, value := range records {
			if value.Role == "" || value.Path == "" || (value.Present && !validSHA256(value.SHA256)) {
				return errors.New("snapshot file record is incomplete")
			}
			if len(bindings) > 0 && value.Present {
				expected := bindings[0].Artifacts.hashForRole(value.Role)
				if value.Role == "config" {
					expected = bindings[0].ConfigSHA256
				}
				if expected != "" && value.SHA256 != expected {
					return fmt.Errorf("installed file %s hash mismatch", value.Role)
				}
			}
		}
	}
	if len(bindings) > 0 && len(bindings[0].PayloadFiles) > 0 {
		if err := validateInstalledPayloadFiles(s.InstalledFiles, bindings[0].PayloadFiles); err != nil {
			return err
		}
	}
	for _, records := range [][]StateRecord{s.RegistryRecords, s.OwnershipArtifacts, s.RecoveryArtifacts, s.TransactionArtifacts, s.FixtureResidues} {
		for _, value := range records {
			if value.Kind == "" || value.Name == "" || (value.Present && !validSHA256(value.DefinitionSHA256)) {
				return errors.New("snapshot state record is incomplete")
			}
		}
	}
	for _, value := range s.Listeners {
		if value.Role == "" || value.Endpoint == "" || (value.Present && (value.PID <= 0 || value.ImagePath == "" || !validSHA256(value.ImageSHA256))) {
			return errors.New("snapshot listener record is incomplete")
		}
		if len(bindings) > 0 && value.Present {
			if expected := bindings[0].Artifacts.hashForRole(value.Role); expected != "" && value.ImageSHA256 != expected {
				return fmt.Errorf("listener %s image hash mismatch", value.Role)
			}
		}
	}
	if len(bindings) > 0 {
		if err := validateLocalServerAbsence(s, bindings[0]); err != nil {
			return err
		}
	}
	return nil
}

func equalNetworkBinding(left, right NetworkBinding) bool {
	return equalStrings(left.CorporateCIDRs, right.CorporateCIDRs) && equalStrings(left.CorporateDNS, right.CorporateDNS) && equalStrings(left.InternalSuffixes, right.InternalSuffixes)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalPayloadBindings(left, right []PayloadFileBinding) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	for index := range left {
		if left[index] != right[index] || !validSHA256(left[index].SHA256) || left[index].Name == "" || left[index].Path == "" {
			return false
		}
	}
	return true
}

func validateInstalledPayloadFiles(records []FileRecord, expected []PayloadFileBinding) error {
	if len(records) != len(expected) {
		return errors.New("snapshot does not cover the complete payload file set")
	}
	byPath := make(map[string]FileRecord, len(records))
	for _, record := range records {
		key := strings.ToLower(record.Path)
		if _, ok := byPath[key]; ok {
			return errors.New("snapshot payload file path is duplicated")
		}
		byPath[key] = record
	}
	for _, want := range expected {
		record, ok := byPath[strings.ToLower(want.Path)]
		if !ok || record.Name != want.Name || record.ExpectedSHA256 != want.SHA256 {
			return errors.New("snapshot payload file binding mismatch")
		}
		if record.Present && record.SHA256 != want.SHA256 {
			return errors.New("snapshot payload file hash mismatch")
		}
	}
	return nil
}

func validateLocalServerAbsence(s Snapshot, binding FixtureBinding) error {
	for _, service := range s.Services {
		if service.Role == "server-service" && service.Present {
			return errors.New("local server service residue is present on the client host")
		}
	}
	for _, process := range s.Processes {
		if (process.Role == "server-service" || process.Role == "server-core") && process.Present {
			return errors.New("local server process residue is present on the client host")
		}
	}
	for _, listener := range s.Listeners {
		if listener.Endpoint == binding.ServerListenerEndpoint && listener.Present {
			return errors.New("local server listener residue is present on the client host")
		}
	}
	for _, file := range s.RuntimeFiles {
		if file.Role == "server-config" && file.Present {
			return errors.New("local server config residue is present on the client host")
		}
	}
	return nil
}

func (a ArtifactBinding) hashForRole(role string) string {
	switch role {
	case "agent":
		return a.AgentSHA256
	case "core":
		return a.CoreSHA256
	case "ui":
		return a.UISHA256
	case "server-service":
		return a.ServerServiceSHA256
	case "driver":
		return a.DriverSHA256
	case "sentinel", "fake-upstream":
		return a.SentinelSHA256
	case "action-helper":
		return a.ActionHelperSHA256
	default:
		return ""
	}
}

func (s Snapshot) CanonicalState() ([]byte, error) {
	state := s.Clone()
	state.ObservationNonce = ""
	for index := range state.Processes {
		state.Processes[index].PID = 0
		state.Processes[index].ParentPID = 0
	}
	for index := range state.Services {
		state.Services[index].PID = 0
	}
	sort.Slice(state.Adapters, func(i, j int) bool { return state.Adapters[i].InterfaceGUID < state.Adapters[j].InterfaceGUID })
	sort.Slice(state.Routes, func(i, j int) bool {
		left, right := state.Routes[i], state.Routes[j]
		return fmt.Sprintf("%s/%010d/%s/%010d", left.DestinationPrefix, left.InterfaceIndex, left.NextHop, left.RouteMetric) < fmt.Sprintf("%s/%010d/%s/%010d", right.DestinationPrefix, right.InterfaceIndex, right.NextHop, right.RouteMetric)
	})
	sort.Slice(state.DNS, func(i, j int) bool { return state.DNS[i].InterfaceIndex < state.DNS[j].InterfaceIndex })
	sort.Slice(state.Services, func(i, j int) bool { return state.Services[i].Name < state.Services[j].Name })
	sort.Slice(state.Processes, func(i, j int) bool { return state.Processes[i].Role < state.Processes[j].Role })
	sort.Slice(state.OwnedFirewallRules, func(i, j int) bool { return state.OwnedFirewallRules[i].Name < state.OwnedFirewallRules[j].Name })
	sort.Slice(state.MSIRegistrations, func(i, j int) bool {
		return state.MSIRegistrations[i].ProductCode < state.MSIRegistrations[j].ProductCode
	})
	sort.Slice(state.InstalledFiles, func(i, j int) bool { return state.InstalledFiles[i].Path < state.InstalledFiles[j].Path })
	sort.Slice(state.RuntimeFiles, func(i, j int) bool { return state.RuntimeFiles[i].Path < state.RuntimeFiles[j].Path })
	sortStateRecords(state.RegistryRecords)
	sortStateRecords(state.OwnershipArtifacts)
	sortStateRecords(state.RecoveryArtifacts)
	sortStateRecords(state.TransactionArtifacts)
	sortStateRecords(state.FixtureResidues)
	for index := range state.Listeners {
		state.Listeners[index].PID = 0
	}
	sort.Slice(state.Listeners, func(i, j int) bool { return state.Listeners[i].Endpoint < state.Listeners[j].Endpoint })
	return json.Marshal(state)
}

func sortStateRecords(values []StateRecord) {
	sort.Slice(values, func(i, j int) bool { return values[i].Kind+"/"+values[i].Name < values[j].Kind+"/"+values[j].Name })
}

func (s Snapshot) Clone() Snapshot {
	result := s
	result.Adapters = append([]AdapterRecord(nil), s.Adapters...)
	result.Routes = append([]RouteRecord(nil), s.Routes...)
	result.DNS = append([]DNSRecord(nil), s.DNS...)
	for index := range result.DNS {
		result.DNS[index].ServerAddresses = append([]string(nil), s.DNS[index].ServerAddresses...)
	}
	result.Services = append([]ServiceRecord(nil), s.Services...)
	result.Processes = append([]ProcessRecord(nil), s.Processes...)
	result.OwnedFirewallRules = append([]FirewallRecord(nil), s.OwnedFirewallRules...)
	result.MSIRegistrations = append([]MSIRecord(nil), s.MSIRegistrations...)
	result.InstalledFiles = append([]FileRecord(nil), s.InstalledFiles...)
	if s.UnexpectedFiles != nil {
		result.UnexpectedFiles = append([]FileRecord{}, s.UnexpectedFiles...)
	}
	result.OwnedRoots = append([]RootRecord(nil), s.OwnedRoots...)
	result.RuntimeFiles = append([]FileRecord(nil), s.RuntimeFiles...)
	result.RegistryRecords = append([]StateRecord(nil), s.RegistryRecords...)
	result.OwnershipArtifacts = append([]StateRecord(nil), s.OwnershipArtifacts...)
	result.RecoveryArtifacts = append([]StateRecord(nil), s.RecoveryArtifacts...)
	result.TransactionArtifacts = append([]StateRecord(nil), s.TransactionArtifacts...)
	result.FixtureResidues = append([]StateRecord(nil), s.FixtureResidues...)
	result.Listeners = append([]ListenerRecord(nil), s.Listeners...)
	return result
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
