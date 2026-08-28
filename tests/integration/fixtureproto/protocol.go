package fixtureproto

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const ProtocolVersion = 2

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
	PayloadSHA256                string `json:"payload_sha256"`
	ConfigSHA256                 string `json:"config_sha256"`
	FakeUpstreamIdentity         string `json:"fake_upstream_identity"`
	PublicSentinelIdentity       string `json:"public_sentinel_identity"`
	CorporateSentinelIdentity    string `json:"corporate_sentinel_identity"`
	PublicSentinelEndpoint       string `json:"public_sentinel_endpoint"`
	PublicSentinelHealthEndpoint string `json:"public_sentinel_health_endpoint"`
	CorporateSentinelEndpoint    string `json:"corporate_sentinel_endpoint"`
	FakeUpstreamControlEndpoint  string `json:"fake_upstream_control_endpoint"`
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
	ObservationNonce   string           `json:"observation_nonce"`
	Adapters           []AdapterRecord  `json:"adapters"`
	Routes             []RouteRecord    `json:"routes"`
	DNS                []DNSRecord      `json:"dns"`
	Services           []ServiceRecord  `json:"services"`
	Processes          []ProcessRecord  `json:"processes"`
	OwnedFirewallRules []FirewallRecord `json:"owned_firewall_rules"`
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
	Name       string `json:"name"`
	Present    bool   `json:"present"`
	Status     string `json:"status"`
	StartMode  string `json:"start_mode"`
	PathSHA256 string `json:"path_sha256,omitempty"`
}

type ProcessRecord struct {
	Role        string `json:"role"`
	Present     bool   `json:"present"`
	PID         int    `json:"pid,omitempty"`
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
	if err := response.Snapshot.Validate(request.RequestNonce); err != nil {
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

func requiredFacts(action string) map[string]string {
	switch action {
	case "preflight":
		return map[string]string{"payload_sha256": "", "config_sha256": "", "sentinel_identities_verified": "true"}
	case "capture":
		return map[string]string{"snapshot_sha256": ""}
	case "case-setup":
		return map[string]string{"service_present": "true"}
	case "fake-upstream-start":
		return map[string]string{"fake_upstream_present": "true"}
	case "fake-upstream-stop":
		return map[string]string{"fake_upstream_absent": "true"}
	case "core-crash":
		return map[string]string{"core_absent": "true", "owned_firewall_present": "true"}
	case "ui-start":
		return map[string]string{"ui_present": "true"}
	case "ui-exit":
		return map[string]string{"ui_absent": "true"}
	case "agent-crash", "stage-machine-recovery":
		return map[string]string{"agent_absent": "true", "owned_firewall_present": "true"}
	case "agent-start", "machine-recover":
		return map[string]string{"service_present": "true", "core_absent": "true", "tun_absent": "true", "owned_firewall_absent": "true"}
	case "uninstall":
		return map[string]string{"service_absent": "true", "core_absent": "true", "ui_absent": "true", "tun_absent": "true", "owned_firewall_absent": "true"}
	case "case-cleanup":
		return map[string]string{"core_absent": "true", "ui_absent": "true", "fake_upstream_absent": "true"}
	case "restore":
		return map[string]string{"restore_input_sha256": "", "state_restored": "true"}
	default:
		return map[string]string{"unsupported_action": "never"}
	}
}

func (s Snapshot) Validate(expectedNonce string) error {
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
		if value.Name == "" || value.Status == "" || value.StartMode == "" || (value.Present && !validSHA256(value.PathSHA256)) {
			return errors.New("snapshot services contain an incomplete record")
		}
	}
	roles := make(map[string]struct{}, len(s.Processes))
	for _, value := range s.Processes {
		if value.Role == "" || (value.Present && (value.PID <= 0 || !validSHA256(value.ImageSHA256))) {
			return errors.New("snapshot process record is incomplete")
		}
		if _, exists := roles[value.Role]; exists {
			return errors.New("snapshot process role is duplicated")
		}
		roles[value.Role] = struct{}{}
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
	return nil
}

func (s Snapshot) CanonicalState() ([]byte, error) {
	state := s.Clone()
	state.ObservationNonce = ""
	for index := range state.Processes {
		state.Processes[index].PID = 0
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
	return json.Marshal(state)
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
	return result
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
