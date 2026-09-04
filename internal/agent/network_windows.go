//go:build windows

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/traceevent"
)

const (
	networkOperationCapture         = "capture"
	networkOperationScan            = "scan"
	networkOperationBlock           = "block"
	networkOperationVerify          = "verify"
	networkOperationEmergency       = "emergency"
	networkOperationReady           = "ready"
	networkOperationActivate        = "activate"
	networkOperationRestore         = "restore"
	networkOperationPreparedRestore = "prepared_restore"
	networkOperationDNSMetric       = "dns_metric"
	networkOperationResidue         = "residue"
	networkOperationFirewallPrepare = "firewall_prepare"
	networkOperationFirewallEnable  = "firewall_enable"
	networkOperationFirewallVerify  = "firewall_verify"
	networkOperationFirewallDisable = "firewall_disable"
	networkOperationFirewallArm     = "firewall_arm"
	networkOperationFirewallAudit   = "firewall_audit"
	networkOperationTUNRecover      = "tun_recover"

	windowsTUNInterface = "RegenBioOverseasAccess"
	// windowsFakeIPRoutePrefix must mirror the fakeip inet4_range rendered by
	// internal/singconfig: tun-side fake-ip destinations only reach the core
	// when this route exists.
	windowsFakeIPRoutePrefix      = "198.18.0.0/15"
	windowsTUNAddress             = "172.19.0.1/30"
	windowsTUNDNS                 = "172.19.0.2"
	windowsTCPBlockRule           = "RegenBioOverseasAccess.BlockPublicTCP"
	windowsQUICBlockRule          = "RegenBioOverseasAccess.BlockQUIC"
	windowsUDPBlockRule           = "RegenBioOverseasAccess.BlockPublicUDP"
	windowsDNSUDPBlockRule        = "RegenBioOverseasAccess.BlockUnapprovedDNSUDP"
	windowsDNSTCPBlockRule        = "RegenBioOverseasAccess.BlockUnapprovedDNSTCP"
	windowsEmergencyBlockRule     = "RegenBioOverseasAccess.BlockPublicEmergency"
	windowsFirewallGroup          = "RegenBioOverseasAccess.Managed"
	windowsCoreExecutable         = `C:\Program Files\RegenBio\OverseasAccess\sing-box.exe`
	windowsOwnedRouteMetric       = 4096
	windowsSnapshotPhaseCaptured  = "captured"
	windowsSnapshotPhaseProtected = "protected"
	windowsSnapshotPhaseTUNOwned  = "tun-owned"
	maxNetworkDiagnosticBytes     = traceevent.MaxDetailBytes
	windowsEmergencyTimeout       = 30 * time.Second
	windowsPreparationTimeout     = 60 * time.Second
)

var powerShellEscapePattern = regexp.MustCompile(`(?i)_x[0-9a-f]{4}_`)

type fixedNetworkOperationError struct {
	operation string
	stage     string
	detail    string
	err       error
}

func newFixedNetworkOperationError(operation string, err error, stderr []byte) *fixedNetworkOperationError {
	return newFixedNetworkOperationErrorWithContext(context.Background(), operation, err, stderr)
}

func newFixedNetworkOperationErrorWithContext(ctx context.Context, operation string, err error, stderr []byte) *fixedNetworkOperationError {
	detail := extractPowerShellErrorDetail(stderr)
	if detail == "" && ctx != nil && ctx.Err() != nil {
		detail = ctx.Err().Error()
	}
	if detail == "" && err != nil {
		detail = err.Error()
	}
	if detail == "" {
		detail = fmt.Sprintf("operation %s failed without stderr", operation)
	}
	detail, _ = traceevent.SanitizeDetail(detail)
	stage := networkStage(operation)
	return &fixedNetworkOperationError{operation: operation, stage: stage, detail: detail, err: err}
}

func (e *fixedNetworkOperationError) Error() string {
	if e.detail == "" {
		return fmt.Sprintf("fixed network operation %s failed: %v", e.operation, e.err)
	}
	return fmt.Sprintf("fixed network operation %s failed: %v: %s", e.operation, e.err, e.detail)
}

func (e *fixedNetworkOperationError) Unwrap() error           { return e.err }
func (e *fixedNetworkOperationError) DiagnosticStage() string { return e.stage }
func (e *fixedNetworkOperationError) DiagnosticDetail() string {
	return e.detail
}

func sanitizePowerShellDetail(raw []byte) string {
	normalized := strings.Join(strings.Fields(strings.Map(func(value rune) rune {
		if unicode.IsControl(value) || unicode.IsSpace(value) {
			return ' '
		}
		return value
	}, string(raw))), " ")
	if len(normalized) <= maxNetworkDiagnosticBytes {
		return normalized
	}
	limit := 0
	for _, value := range normalized {
		size := utf8.RuneLen(value)
		if limit+size > maxNetworkDiagnosticBytes {
			break
		}
		limit += size
	}
	return normalized[:limit]
}

func extractPowerShellErrorDetail(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	text := string(trimmed)
	if strings.HasPrefix(text, "#< CLIXML") {
		if start := strings.Index(text, "<Objs"); start >= 0 {
			decoder := xml.NewDecoder(strings.NewReader(text[start:]))
			progressDepth := 0
			captureError := false
			var extracted strings.Builder
			for {
				token, err := decoder.Token()
				if err != nil {
					break
				}
				switch value := token.(type) {
				case xml.StartElement:
					if value.Name.Local == "Obj" && xmlAttribute(value.Attr, "S") == "progress" {
						progressDepth++
					}
					if progressDepth == 0 && value.Name.Local == "S" && strings.EqualFold(xmlAttribute(value.Attr, "S"), "Error") {
						captureError = true
					}
				case xml.CharData:
					if captureError && progressDepth == 0 {
						extracted.Write([]byte(value))
						extracted.WriteByte(' ')
					}
				case xml.EndElement:
					if value.Name.Local == "S" && captureError {
						captureError = false
					}
					if value.Name.Local == "Obj" && progressDepth > 0 {
						progressDepth--
					}
				}
			}
			decoded := decodePowerShellEscapes(extracted.String())
			return sanitizePowerShellDetail([]byte(decoded))
		}
		return ""
	}
	return sanitizePowerShellDetail(trimmed)
}

func xmlAttribute(attributes []xml.Attr, name string) string {
	for _, attribute := range attributes {
		if attribute.Name.Local == name {
			return attribute.Value
		}
	}
	return ""
}

func decodePowerShellEscapes(value string) string {
	return powerShellEscapePattern.ReplaceAllStringFunc(value, func(match string) string {
		code, err := strconv.ParseUint(match[2:6], 16, 16)
		if err != nil {
			return " "
		}
		return string(rune(code))
	})
}

// User-facing business messages for each fixed network operation. The raw
// operation code never appears as the primary line of a trace event.
func networkOperationStartMessage(operation string) string {
	start, _ := networkOperationMessages(operation)
	return start
}

func networkOperationSuccessMessage(operation string) string {
	_, success := networkOperationMessages(operation)
	return success
}

func networkOperationFailureMessage(operation string) string {
	if start, _ := networkOperationMessages(operation); start != "" {
		return start + "失败"
	}
	return "网络操作失败"
}

func networkOperationMessages(operation string) (string, string) {
	switch operation {
	case networkOperationFirewallPrepare:
		return "正在创建预置防泄漏规则", "预置规则已准备并保持禁用"
	case networkOperationFirewallEnable:
		return "正在启用防泄漏保护", "防泄漏保护已启用"
	case networkOperationFirewallArm, networkOperationFirewallVerify:
		return "正在启用防泄漏保护", "防泄漏保护已启用"
	case networkOperationFirewallDisable:
		return "正在禁用预置防泄漏规则", "预置规则已禁用"
	case networkOperationFirewallAudit:
		return "正在审计预置防火墙定义", "预置防火墙定义审计通过"
	case networkOperationTUNRecover:
		return "正在检查残留虚拟网卡", "残留虚拟网卡已处理"
	case networkOperationReady:
		return "正在等待 sing-box TUN 网卡", "TUN 网卡已就绪"
	case networkOperationActivate, networkOperationDNSMetric:
		return "正在切换 DNS 与安全路由", "安全路由已启用"
	case networkOperationRestore, networkOperationPreparedRestore:
		return "正在恢复普通网络", "普通网络已恢复"
	case networkOperationResidue:
		return "正在检查连接残留", "活动残留已清零"
	case networkOperationEmergency:
		return "正在启用应急防护", "应急防护已启用"
	case networkOperationCapture:
		return "正在读取当前网络配置", "当前网络配置已确认"
	case networkOperationScan:
		return "正在枚举需要保护的网卡", "已识别需保护接口"
	case networkOperationBlock:
		return "正在启用防泄漏保护", "防泄漏保护已启用"
	case networkOperationVerify:
		return "正在核对 Windows 防火墙活动状态", "活动规则核对通过"
	default:
		return "", ""
	}
}

func networkStage(operation string) string {
	switch operation {
	case networkOperationCapture:
		return traceevent.StageNetworkCapture
	case networkOperationScan:
		return traceevent.StageAdapterScan
	case networkOperationBlock:
		return traceevent.StageFirewallPublish
	case networkOperationVerify:
		return traceevent.StageActiveStoreVerify
	case networkOperationEmergency:
		return traceevent.StageEmergencyProtection
	case networkOperationReady:
		return traceevent.StageTUNReady
	case networkOperationTUNRecover:
		return traceevent.StageTUNReady
	case networkOperationActivate:
		return traceevent.StageRouteActivation
	case networkOperationRestore, networkOperationPreparedRestore, networkOperationDNSMetric:
		return traceevent.StageNetworkRestore
	case networkOperationResidue:
		return traceevent.StageResidueVerify
	case networkOperationFirewallPrepare:
		return traceevent.StageFirewallPrepare
	case networkOperationFirewallArm, networkOperationFirewallEnable:
		return traceevent.StageFirewallEnable
	case networkOperationFirewallVerify, networkOperationFirewallAudit:
		return traceevent.StageFirewallVerify
	case networkOperationFirewallDisable:
		return traceevent.StageNetworkRestore
	default:
		return traceevent.StageLoggingDegraded
	}
}

var errSnapshotNotFound = errors.New("network snapshot not found")

// tunReadyReader is the native fast path for fixed-TUN detection; the
// PowerShell ready operation remains as the fallback for readers that do
// not implement it.
type tunReadyReader interface {
	TUNReady(ctx context.Context, alias, address string, baseline []string) (WindowsTUNIdentity, bool, error)
}

// routeApplier applies/revokes owned TUN routes and the TUN interface
// metric through native IP Helper calls instead of per-route WMI writes.
type routeApplier interface {
	ApplyOwnedRoutes(snapshot WindowsNetworkSnapshot) error
	RevokeOwnedRoutes(snapshot WindowsNetworkSnapshot) error
}

type WindowsInterfaceSnapshot struct {
	Index           int      `json:"Index"`
	InterfaceGuid   string   `json:"InterfaceGuid"`
	Alias           string   `json:"Alias"`
	InterfaceMetric int      `json:"InterfaceMetric"`
	AutomaticMetric bool     `json:"AutomaticMetric"`
	DNSAutomatic    bool     `json:"DNSAutomatic"`
	DNSServers      []string `json:"DNSServers"`
}

type WindowsNodeRouteSnapshot struct {
	NodeAddress       string `json:"NodeAddress"`
	DestinationPrefix string `json:"DestinationPrefix"`
	InterfaceIndex    int    `json:"InterfaceIndex"`
	NextHop           string `json:"NextHop"`
	RouteMetric       int    `json:"RouteMetric"`
	InterfaceMetric   int    `json:"InterfaceMetric"`
	EffectiveMetric   int    `json:"EffectiveMetric"`
	BypassRequired    bool   `json:"BypassRequired"`
}

type WindowsOwnedRoute struct {
	AddressFamily     string `json:"AddressFamily"`
	DestinationPrefix string `json:"DestinationPrefix"`
	InterfaceIndex    int    `json:"InterfaceIndex"`
	NextHop           string `json:"NextHop"`
	RouteMetric       int    `json:"RouteMetric"`
}

type WindowsTUNIdentity struct {
	InterfaceIndex       int      `json:"InterfaceIndex"`
	InterfaceGuid        string   `json:"InterfaceGuid"`
	InterfaceAlias       string   `json:"InterfaceAlias"`
	InterfaceDescription string   `json:"InterfaceDescription"`
	HardwareInterface    bool     `json:"HardwareInterface"`
	Virtual              bool     `json:"Virtual"`
	Addresses            []string `json:"Addresses"`
}

type WindowsAdapterIdentity struct {
	InterfaceIndex int    `json:"InterfaceIndex"`
	InterfaceGuid  string `json:"InterfaceGuid"`
	InterfaceAlias string `json:"InterfaceAlias"`
	Status         string `json:"Status"`
}

type WindowsNetworkSnapshot struct {
	Version                   int                        `json:"Version"`
	Interfaces                []WindowsInterfaceSnapshot `json:"Interfaces"`
	OwnedFirewallRulesPresent []string                   `json:"OwnedFirewallRulesPresent"`
	ConflictingTUNRoutes      []string                   `json:"ConflictingTUNRoutes"`
	BaselineAdapterGuids      []string                   `json:"BaselineAdapterGuids"`
	TUNAliasPresent           bool                       `json:"TUNAliasPresent"`
	TUNAddressPresent         bool                       `json:"TUNAddressPresent"`
	NodeRoutes                []WindowsNodeRouteSnapshot `json:"NodeRoutes"`
	OwnedTUN                  *WindowsTUNIdentity        `json:"OwnedTUN,omitempty"`
	OwnedRoutes               []WindowsOwnedRoute        `json:"OwnedRoutes"`
	GuardRoutes               []WindowsOwnedRoute        `json:"GuardRoutes"`
	GuardInterfaceIndex       int                        `json:"GuardInterfaceIndex"`
	BlockedRemoteAddresses    []string                   `json:"BlockedRemoteAddresses"`
	DNSBlockedRemoteAddresses []string                   `json:"DNSBlockedRemoteAddresses"`
	RouteMetric               int                        `json:"RouteMetric"`
	OwnershipPhase            string                     `json:"OwnershipPhase"`
	PreparedGeneration        uint64                     `json:"PreparedGeneration,omitempty"`
	IntegritySHA256           string                     `json:"IntegritySHA256"`
}

type windowsNetworkInput struct {
	Interfaces                        []WindowsInterfaceSnapshot `json:"Interfaces,omitempty"`
	RestoreInterfaces                 bool                       `json:"RestoreInterfaces,omitempty"`
	FirewallRuleNames                 []string                   `json:"FirewallRuleNames,omitempty"`
	FirewallGroup                     string                     `json:"FirewallGroup,omitempty"`
	BlockedRemoteAddresses            []string                   `json:"BlockedRemoteAddresses,omitempty"`
	DNSBlockedRemoteAddresses         []string                   `json:"DNSBlockedRemoteAddresses,omitempty"`
	ProtectedAdapters                 []WindowsAdapterIdentity   `json:"ProtectedAdapters,omitempty"`
	PreparedRules                     []WindowsPreparedRule      `json:"PreparedRules,omitempty"`
	PreparedGeneration                uint64                     `json:"PreparedGeneration,omitempty"`
	RuleDefinitionVersion             int                        `json:"RuleDefinitionVersion,omitempty"`
	PreviousPreparedRules             []WindowsPreparedRule      `json:"PreviousPreparedRules,omitempty"`
	PreviousPreparedGeneration        uint64                     `json:"PreviousPreparedGeneration,omitempty"`
	PreviousRuleDefinitionVersion     int                        `json:"PreviousRuleDefinitionVersion,omitempty"`
	PreviousBlockedRemoteAddresses    []string                   `json:"PreviousBlockedRemoteAddresses,omitempty"`
	PreviousDNSBlockedRemoteAddresses []string                   `json:"PreviousDNSBlockedRemoteAddresses,omitempty"`
	DNSConnected                      bool                       `json:"DNSConnected,omitempty"`
	TUNInterface                      string                     `json:"TUNInterface,omitempty"`
	TUNAddress                        string                     `json:"TUNAddress,omitempty"`
	TUNDNS                            string                     `json:"TUNDNS,omitempty"`
	TUNRoutePrefixes                  []string                   `json:"TUNRoutePrefixes,omitempty"`
	RouteMetric                       int                        `json:"RouteMetric,omitempty"`
	NodeAddresses                     []string                   `json:"NodeAddresses,omitempty"`
	BaselineAdapterGuids              []string                   `json:"BaselineAdapterGuids,omitempty"`
	OwnedTUN                          *WindowsTUNIdentity        `json:"OwnedTUN,omitempty"`
	OwnedRoutes                       []WindowsOwnedRoute        `json:"OwnedRoutes,omitempty"`
	GuardRoutes                       []WindowsOwnedRoute        `json:"GuardRoutes,omitempty"`
	CoreExecutable                    string                     `json:"CoreExecutable,omitempty"`
}

type windowsResidueCounts struct {
	ManagedRules          int `json:"ManagedRules"`
	DisabledPreparedRules int `json:"DisabledPreparedRules"`
	ProductRoutes         int `json:"ProductRoutes"`
	ProductTUNs           int `json:"ProductTUNs"`
	CoreProcesses         int `json:"CoreProcesses"`
}

type networkRunner interface {
	Run(context.Context, string, []byte) ([]byte, error)
}

type snapshotStore interface {
	Save(string, WindowsNetworkSnapshot) error
	Load(string) (WindowsNetworkSnapshot, error)
	Delete(string) error
}

type WindowsNetworkManager struct {
	mu                 sync.Mutex
	prepareMu          sync.Mutex
	prepareFlight      *prepareFlight
	policy             accessmodel.Policy
	statePath          string
	runner             networkRunner
	native             nativeNetworkReader
	store              snapshotStore
	preparedStore      preparedStateStore
	preparedPath       string
	prepared           *WindowsPreparedState
	nodeAddresses      []string
	blockedPrefixes    []string
	dnsBlockedPrefixes []string
	current            *WindowsNetworkSnapshot
	trace              traceevent.Sink
	lastOwnedTUN       *WindowsTUNIdentity
	lastOwnedRoutes    []WindowsOwnedRoute
	monitorClock       monitorClock
	monitorConfig      networkMonitorConfig
	monitorFlights     int
	routes             routeApplier
}

type WindowsNetworkOption func(*WindowsNetworkManager)

func WithWindowsTraceSink(sink traceevent.Sink) WindowsNetworkOption {
	return func(manager *WindowsNetworkManager) { manager.trace = sink }
}

func withWindowsRouteApplier(applier routeApplier) WindowsNetworkOption {
	return func(manager *WindowsNetworkManager) { manager.routes = applier }
}

func withWindowsNativeNetworkReader(reader nativeNetworkReader) WindowsNetworkOption {
	return func(manager *WindowsNetworkManager) { manager.native = reader }
}

func NewWindowsNetworkManager(policy accessmodel.Policy, statePath string, options ...WindowsNetworkOption) (*WindowsNetworkManager, error) {
	return newWindowsNetworkManager(policy, statePath, powerShellNetworkRunner{}, fileSnapshotStore{}, options...)
}

func newWindowsNetworkManager(policy accessmodel.Policy, statePath string, runner networkRunner, store snapshotStore, options ...WindowsNetworkOption) (*WindowsNetworkManager, error) {
	if err := accessmodel.Validate(policy); err != nil {
		return nil, err
	}
	if statePath == "" || !filepath.IsAbs(statePath) || filepath.Clean(statePath) != statePath {
		return nil, errors.New("network state path must be absolute and clean")
	}
	if runner == nil || store == nil {
		return nil, errors.New("network runner and snapshot store are required")
	}
	nodes := append([]accessmodel.Node(nil), policy.Nodes...)
	sort.Slice(nodes, func(left, right int) bool {
		if nodes[left].Priority == nodes[right].Priority {
			return nodes[left].ID < nodes[right].ID
		}
		return nodes[left].Priority < nodes[right].Priority
	})
	nodeAddresses := make([]string, 0, len(nodes))
	excluded4 := canonicalNonGlobalIPv4Prefixes()
	excluded6 := standardNonPublicIPv6Prefixes()
	for _, node := range nodes {
		nodeAddress, err := netip.ParseAddr(node.Address)
		if err != nil || !nodeAddress.Is4() {
			return nil, errors.New("Windows network manager requires IPv4 nodes")
		}
		nodeAddresses = append(nodeAddresses, nodeAddress.String())
		excluded4 = append(excluded4, netip.PrefixFrom(nodeAddress, 32))
	}
	for _, value := range policy.CorporateCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, errors.New("Windows network manager requires valid corporate CIDRs")
		}
		if prefix.Addr().Is4() {
			excluded4 = append(excluded4, prefix.Masked())
		} else {
			excluded6 = append(excluded6, prefix.Masked())
		}
	}
	for _, value := range policy.CorporateDNS {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return nil, errors.New("Windows network manager requires IPv4 corporate DNS addresses")
		}
		excluded4 = append(excluded4, netip.PrefixFrom(address, 32))
	}
	blocked := append(complementIPv4Prefixes(excluded4), complementIPv6Prefixes(excluded6)...)
	dnsExcluded4 := []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(windowsTUNDNS), 32)}
	for _, value := range policy.CorporateDNS {
		dnsExcluded4 = append(dnsExcluded4, netip.PrefixFrom(netip.MustParseAddr(value), 32))
	}
	dnsBlocked := normalizeWindowsFirewallPrefixes(append(
		complementIPv4Prefixes(dnsExcluded4),
		complementIPv6From(netip.MustParsePrefix("::/0"), nil)...,
	))
	manager := &WindowsNetworkManager{
		policy:             clonePolicy(policy),
		statePath:          statePath,
		runner:             runner,
		native:             newWindowsNativeNetworkReader(),
		store:              store,
		preparedStore:      filePreparedStateStore{},
		preparedPath:       filepath.Join(filepath.Dir(statePath), windowsPreparedStateFile),
		nodeAddresses:      nodeAddresses,
		blockedPrefixes:    blocked,
		dnsBlockedPrefixes: dnsBlocked,
		routes:             windowsRouteApplier{},
	}
	for _, option := range options {
		if option != nil {
			option(manager)
		}
	}
	return manager, nil
}

// Capture validates the prepared generation, re-reads the lightweight native
// fingerprint, and atomically persists the active snapshot without touching
// the firewall.
func (m *WindowsNetworkManager) Capture(ctx context.Context, prepared PreparedNetwork) (any, error) {
	return m.capturePoc(ctx, prepared)
}

func (m *WindowsNetworkManager) installEmergencyProtection(ctx context.Context) error {
	input := windowsNetworkInput{
		FirewallRuleNames:         windowsFirewallRuleNames(),
		FirewallGroup:             windowsFirewallGroup,
		BlockedRemoteAddresses:    append([]string(nil), m.blockedPrefixes...),
		DNSBlockedRemoteAddresses: append([]string(nil), m.dnsBlockedPrefixes...),
	}
	_, err := m.run(ctx, networkOperationEmergency, input)
	return err
}

// armEmergencyProtection installs the legacy fail-closed emergency block once.
// The prepared pool arms its own emergency rule through the prepared path;
// this remains for legacy snapshots without a prepared generation.
func (m *WindowsNetworkManager) armEmergencyProtection(ctx context.Context) error {
	emergencyContext, cancelEmergency := context.WithTimeout(context.WithoutCancel(ctx), windowsEmergencyTimeout)
	defer cancelEmergency()
	return m.installEmergencyProtection(emergencyContext)
}

func windowsFirewallRuleNames() []string {
	return []string{windowsTCPBlockRule, windowsQUICBlockRule, windowsUDPBlockRule, windowsDNSUDPBlockRule, windowsDNSTCPBlockRule, windowsEmergencyBlockRule}
}

func (m *WindowsNetworkManager) WaitTUNReady(ctx context.Context) error {
	m.mu.Lock()
	if m.current == nil {
		m.mu.Unlock()
		return errors.New("network state was not captured")
	}
	reader, ok := m.native.(tunReadyReader)
	if !ok {
		m.mu.Unlock()
		return errors.New("native tun detection is unavailable")
	}
	deadline := time.Now().Add(8 * time.Second)
	var identity WindowsTUNIdentity
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			m.mu.Unlock()
			return ctxErr
		}
		candidate, found, pollErr := reader.TUNReady(ctx, windowsTUNInterface, windowsTUNAddress, m.current.BaselineAdapterGuids)
		if pollErr == nil && found {
			if err := validateTUNIdentity(candidate, m.current.BaselineAdapterGuids); err != nil {
				m.mu.Unlock()
				return fmt.Errorf("%w: %w", errTUNIdentityMismatch, err)
			}
			identity = candidate
			break
		}
		if time.Now().After(deadline) {
			m.mu.Unlock()
			return fmt.Errorf("%w: deadline reached", errTUNNotFound)
		}
		time.Sleep(150 * time.Millisecond)
	}
	m.current.OwnedTUN = &identity
	m.current.OwnershipPhase = windowsSnapshotPhaseTUNOwned
	m.mu.Unlock()
	return nil
}

// ActivateTUNRoutes: sing-box auto_route owns the routes; the product
// points every live interface's resolver at the tun so Windows' parallel
// DNS racing can never answer with a polluted upstream result.
func (m *WindowsNetworkManager) ActivateTUNRoutes(ctx context.Context) error {
	m.mu.Lock()
	if m.current == nil {
		m.mu.Unlock()
		return errors.New("network state was not captured")
	}
	m.mu.Unlock()
	return m.pointAllResolversAtTun(ctx)
}

// Restore: sing-box routes die with the core; the product restores each
// captured interface's resolver exactly and resets any straggler still
// pointing at the tun resolver.
func (m *WindowsNetworkManager) Restore(ctx context.Context, value any) error {
	m.mu.Lock()
	snapshot := WindowsNetworkSnapshot{}
	if m.current != nil {
		snapshot = *m.current
		m.rememberOwnershipLocked(*m.current)
	} else if value != nil {
		if captured, ok := value.(WindowsNetworkSnapshot); ok {
			snapshot = captured
		}
	}
	m.current = nil
	m.mu.Unlock()
	if snapshot.OwnedTUN == nil {
		return (minimalRouting{}).flushResolverCache()
	}
	_ = snapshot
	return m.restoreSnapshotResolvers(ctx)
}

// Reconcile: startup hygiene only — routes died with the service's core;
// resolvers cannot be restored without a snapshot, so stray tun DNS is
// reset via the dns_metric script with an empty snapshot.
func (m *WindowsNetworkManager) Reconcile(ctx context.Context) error {
	return (minimalRouting{}).flushResolverCache()
}

// Residue: the tun adapter is the only product footprint that can outlive
// a transaction; routes die with the core process.
func (m *WindowsNetworkManager) Residue(ctx context.Context) (traceevent.Residue, error) {
	reader, ok := m.native.(tunReadyReader)
	tunCount := 0
	if ok {
		if _, found, err := reader.TUNReady(ctx, windowsTUNInterface, windowsTUNAddress, nil); err == nil && found {
			tunCount = 1
		}
	}
	residue := traceevent.Residue{ProductTUNs: tunCount}
	if residue.IsZero() {
		m.mu.Lock()
		m.lastOwnedRoutes = nil
		m.lastOwnedTUN = nil
		m.mu.Unlock()
	}
	return residue, nil
}

func dnsMetricInput(snapshot WindowsNetworkSnapshot, connected bool) windowsNetworkInput {
	input := windowsNetworkInput{
		Interfaces:        append([]WindowsInterfaceSnapshot(nil), snapshot.Interfaces...),
		TUNInterface:      windowsTUNInterface,
		TUNDNS:            windowsTUNDNS,
		OwnedTUN:          snapshot.OwnedTUN,
		DNSConnected:      connected,
		RestoreInterfaces: !connected,
	}
	return input
}

// preparedStateForSnapshot resolves the sealed prepared state matching the
// snapshot generation from memory or the durable store.
func (m *WindowsNetworkManager) preparedStateForSnapshot(snapshot WindowsNetworkSnapshot) (WindowsPreparedState, bool) {
	m.mu.Lock()
	cached := m.prepared
	m.mu.Unlock()
	if cached != nil && cached.Generation == snapshot.PreparedGeneration {
		return *cached, true
	}
	return m.loadSealedPreparedState(func(state WindowsPreparedState) bool {
		return state.Generation == snapshot.PreparedGeneration
	})
}

// loadSealedPreparedState loads and validates the durable prepared state and
// accepts it when the predicate matches.
func (m *WindowsNetworkManager) loadSealedPreparedState(accept func(WindowsPreparedState) bool) (WindowsPreparedState, bool) {
	state, err := m.preparedStore.Load(m.preparedPath)
	if err != nil {
		return WindowsPreparedState{}, false
	}
	if err := validateWindowsPreparedState(state); err != nil {
		return WindowsPreparedState{}, false
	}
	if !accept(state) {
		return WindowsPreparedState{}, false
	}
	return state, true
}

func (m *WindowsNetworkManager) rememberOwnershipLocked(snapshot WindowsNetworkSnapshot) {
	m.lastOwnedRoutes = append([]WindowsOwnedRoute(nil), snapshot.OwnedRoutes...)
	m.lastOwnedTUN = cloneTUNIdentity(snapshot.OwnedTUN)
}

func cloneTUNIdentity(identity *WindowsTUNIdentity) *WindowsTUNIdentity {
	if identity == nil {
		return nil
	}
	clone := *identity
	clone.Addresses = append([]string(nil), identity.Addresses...)
	return &clone
}

func (m *WindowsNetworkManager) run(ctx context.Context, operation string, input windowsNetworkInput) ([]byte, error) {
	startedAt := time.Now()
	stage := networkStage(operation)
	generation := traceevent.GenerationFromContext(ctx)
	summary := networkInputSummary(operation, input)
	m.emitNetworkTrace(traceevent.Event{
		Generation: generation, Level: traceevent.LevelInfo, Component: traceevent.ComponentPowerShell,
		Stage: stage, Event: traceevent.EventStarted, Message: networkOperationStartMessage(operation), Detail: summary,
	})
	payload, err := json.Marshal(input)
	if err != nil {
		wrapped := newFixedNetworkOperationErrorWithContext(ctx, operation, err, nil)
		m.emitNetworkTerminal(generation, stage, startedAt, traceevent.EventFailed, networkOperationFailureMessage(operation), wrapped.DiagnosticDetail(), traceevent.LevelError)
		return nil, wrapped
	}
	output, err := m.runner.Run(ctx, operation, payload)
	if err != nil {
		var diagnostic stagedDiagnosticError
		if !errors.As(err, &diagnostic) || diagnostic.DiagnosticDetail() == "" || diagnostic.DiagnosticStage() == "" {
			err = newFixedNetworkOperationErrorWithContext(ctx, operation, err, nil)
		}
		detail := err.Error()
		if errors.As(err, &diagnostic) && diagnostic.DiagnosticDetail() != "" {
			detail = diagnostic.DiagnosticDetail()
		}
		detail, _ = traceevent.SanitizeDetail(detail)
		m.emitNetworkTerminal(generation, stage, startedAt, traceevent.EventFailed, networkOperationFailureMessage(operation), detail, traceevent.LevelError)
		return nil, err
	}
	m.emitNetworkTerminal(generation, stage, startedAt, traceevent.EventSucceeded, networkOperationSuccessMessage(operation), summary, traceevent.LevelInfo)
	return output, nil
}

func (m *WindowsNetworkManager) emitNetworkTerminal(generation uint64, stage string, startedAt time.Time, event, message, detail, level string) {
	elapsed := time.Since(startedAt).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	m.emitNetworkTrace(traceevent.Event{
		Generation: generation, Level: level, Component: traceevent.ComponentPowerShell,
		Stage: stage, Event: event, ElapsedMS: &elapsed, Message: message, Detail: detail,
	})
}

func (m *WindowsNetworkManager) emitNetworkTrace(event traceevent.Event) {
	if m.trace == nil {
		return
	}
	event.Message, _ = traceevent.SanitizeDetail(event.Message)
	event.Detail, event.DetailTruncated = traceevent.SanitizeDetail(event.Detail)
	m.trace.Record(event)
}

func networkInputSummary(operation string, input windowsNetworkInput) string {
	return fmt.Sprintf(
		"operation=%s interfaces=%d protected_adapters=%d firewall_rules=%d blocked_prefixes=%d dns_prefixes=%d owned_routes=%d node_addresses=%d",
		operation,
		len(input.Interfaces),
		len(input.ProtectedAdapters),
		len(input.FirewallRuleNames),
		len(input.BlockedRemoteAddresses),
		len(input.DNSBlockedRemoteAddresses),
		len(input.OwnedRoutes),
		len(input.NodeAddresses),
	)
}

func activationInput(snapshot WindowsNetworkSnapshot) windowsNetworkInput {
	return windowsNetworkInput{
		Interfaces:                append([]WindowsInterfaceSnapshot(nil), snapshot.Interfaces...),
		FirewallRuleNames:         windowsFirewallRuleNames(),
		FirewallGroup:             windowsFirewallGroup,
		BlockedRemoteAddresses:    append([]string(nil), snapshot.BlockedRemoteAddresses...),
		DNSBlockedRemoteAddresses: append([]string(nil), snapshot.DNSBlockedRemoteAddresses...),
		TUNInterface:              windowsTUNInterface,
		TUNAddress:                windowsTUNAddress,
		TUNDNS:                    windowsTUNDNS,
		TUNRoutePrefixes:          []string{"0.0.0.0/1", "128.0.0.0/1"},
		RouteMetric:               snapshot.RouteMetric,
		OwnedTUN:                  snapshot.OwnedTUN,
		OwnedRoutes:               append([]WindowsOwnedRoute(nil), snapshot.OwnedRoutes...),
	}
}

func (m *WindowsNetworkManager) restorationInput(snapshot WindowsNetworkSnapshot) windowsNetworkInput {
	input := activationInput(snapshot)
	input.RestoreInterfaces = snapshot.OwnershipPhase == windowsSnapshotPhaseTUNOwned
	// Version-1 snapshots written before the route-guard remediation did not
	// persist these derived sets. Re-derive them from the validated immutable
	// policy so the in-script catch path remains fail-closed during upgrade.
	if len(input.BlockedRemoteAddresses) == 0 {
		input.BlockedRemoteAddresses = append([]string(nil), m.blockedPrefixes...)
	}
	if len(input.DNSBlockedRemoteAddresses) == 0 {
		input.DNSBlockedRemoteAddresses = append([]string(nil), m.dnsBlockedPrefixes...)
	}
	for index := range input.OwnedRoutes {
		if input.OwnedRoutes[index].AddressFamily == "" {
			input.OwnedRoutes[index].AddressFamily = addressFamilyForPrefix(input.OwnedRoutes[index].DestinationPrefix)
		}
	}
	return input
}

func addressFamilyForPrefix(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is6() {
		return "IPv6"
	}
	return "IPv4"
}

func asWindowsSnapshot(value any) (WindowsNetworkSnapshot, error) {
	switch snapshot := value.(type) {
	case WindowsNetworkSnapshot:
		return snapshot, validateWindowsSnapshot(snapshot)
	case *WindowsNetworkSnapshot:
		if snapshot == nil {
			return WindowsNetworkSnapshot{}, errors.New("network snapshot is nil")
		}
		return *snapshot, validateWindowsSnapshot(*snapshot)
	default:
		return WindowsNetworkSnapshot{}, errors.New("network snapshot has an unexpected type")
	}
}

func validateWindowsSnapshot(snapshot WindowsNetworkSnapshot) error {
	if err := validateWindowsSnapshotIntegrity(snapshot); err != nil {
		return err
	}
	if snapshot.Version != 1 || len(snapshot.Interfaces) == 0 {
		return errors.New("captured network state is incomplete")
	}
	if snapshot.RouteMetric != windowsOwnedRouteMetric {
		return errors.New("captured route ownership marker is invalid")
	}
	if len(snapshot.NodeRoutes) == 0 {
		return errors.New("captured node route state is missing")
	}
	for _, route := range snapshot.NodeRoutes {
		node, err := netip.ParseAddr(route.NodeAddress)
		if err != nil || !node.Is4() || route.InterfaceIndex <= 0 || route.DestinationPrefix == "" {
			return errors.New("captured node route state is invalid")
		}
		prefix, err := netip.ParsePrefix(route.DestinationPrefix)
		if err != nil || !prefix.Addr().Is4() || !prefix.Contains(node) {
			return errors.New("captured node route prefix is invalid")
		}
		if route.NextHop == "" {
			return errors.New("captured node next hop is missing")
		}
		if route.RouteMetric < 0 || route.InterfaceMetric < 0 || route.EffectiveMetric != route.RouteMetric+route.InterfaceMetric {
			return errors.New("captured node route metric is invalid")
		}
		if route.BypassRequired != (prefix.Bits() == 0) {
			return errors.New("captured node bypass decision is invalid")
		}
	}
	seenInterfaceGUIDs := make(map[string]struct{}, len(snapshot.Interfaces))
	for _, networkInterface := range snapshot.Interfaces {
		guid := strings.ToLower(strings.TrimSpace(networkInterface.InterfaceGuid))
		if networkInterface.Index <= 0 || strings.TrimSpace(networkInterface.Alias) == "" || guid == "" {
			return errors.New("captured interface state is invalid")
		}
		if _, duplicate := seenInterfaceGUIDs[guid]; duplicate {
			return errors.New("captured interface GUID is duplicated")
		}
		seenInterfaceGUIDs[guid] = struct{}{}
		for _, server := range networkInterface.DNSServers {
			if _, err := netip.ParseAddr(server); err != nil {
				return errors.New("captured DNS state is invalid")
			}
		}
	}
	return nil
}

func (m *WindowsNetworkManager) validateWindowsSnapshot(snapshot WindowsNetworkSnapshot) error {
	if err := validateWindowsSnapshot(snapshot); err != nil {
		return err
	}
	if err := validateCapturedNodeRoutes(snapshot.NodeRoutes, m.nodeAddresses); err != nil {
		return err
	}
	if !equalStringSlices(snapshot.BlockedRemoteAddresses, m.blockedPrefixes) || !equalStringSlices(snapshot.DNSBlockedRemoteAddresses, m.dnsBlockedPrefixes) {
		return errors.New("captured firewall prefix ownership is invalid")
	}
	if len(snapshot.GuardRoutes) != 0 || snapshot.GuardInterfaceIndex != 0 {
		return errors.New("captured snapshot contains unsupported guard route ownership")
	}

	switch snapshot.OwnershipPhase {
	case windowsSnapshotPhaseCaptured, windowsSnapshotPhaseProtected:
		if snapshot.OwnedTUN != nil || len(snapshot.OwnedRoutes) != 0 {
			return errors.New("captured snapshot contains unexpected TUN ownership")
		}
		return nil
	case windowsSnapshotPhaseTUNOwned:
		if snapshot.OwnedTUN == nil {
			return errors.New("TUN-owned snapshot is missing its adapter identity")
		}
	default:
		return errors.New("captured network ownership phase is invalid")
	}
	if err := validateTUNIdentity(*snapshot.OwnedTUN, snapshot.BaselineAdapterGuids); err != nil {
		return err
	}
	for _, networkInterface := range snapshot.Interfaces {
		if strings.EqualFold(strings.TrimSpace(networkInterface.InterfaceGuid), strings.TrimSpace(snapshot.OwnedTUN.InterfaceGuid)) {
			return errors.New("captured physical interface identity collides with the owned TUN")
		}
	}
	expectedOwned := make([]WindowsOwnedRoute, 0, len(m.blockedPrefixes)+len(snapshot.NodeRoutes)+1)
	expectedOwned = append(expectedOwned, WindowsOwnedRoute{
		AddressFamily:     "IPv4",
		DestinationPrefix: windowsFakeIPRoutePrefix,
		InterfaceIndex:    snapshot.OwnedTUN.InterfaceIndex,
		NextHop:           "0.0.0.0",
		RouteMetric:       windowsOwnedRouteMetric,
	})
	for _, value := range m.blockedPrefixes {
		if addressFamilyForPrefix(value) != "IPv4" {
			continue
		}
		expectedOwned = append(expectedOwned, WindowsOwnedRoute{
			AddressFamily:     "IPv4",
			DestinationPrefix: value,
			InterfaceIndex:    snapshot.OwnedTUN.InterfaceIndex,
			NextHop:           "0.0.0.0",
			RouteMetric:       windowsOwnedRouteMetric,
		})
	}
	for _, route := range snapshot.NodeRoutes {
		if route.BypassRequired {
			expectedOwned = append(expectedOwned, WindowsOwnedRoute{
				AddressFamily:     "IPv4",
				DestinationPrefix: route.NodeAddress + "/32",
				InterfaceIndex:    route.InterfaceIndex,
				NextHop:           route.NextHop,
				RouteMetric:       route.RouteMetric,
			})
		}
	}
	return validateExactOwnedRouteSet(snapshot.OwnedRoutes, expectedOwned, "TUN")
}

func sealWindowsSnapshot(snapshot *WindowsNetworkSnapshot) error {
	snapshot.IntegritySHA256 = ""
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode network snapshot integrity payload: %w", err)
	}
	snapshot.IntegritySHA256 = fmt.Sprintf("%x", sha256.Sum256(payload))
	return nil
}

func validateWindowsSnapshotIntegrity(snapshot WindowsNetworkSnapshot) error {
	want := snapshot.IntegritySHA256
	if len(want) != sha256.Size*2 {
		return errors.New("captured network snapshot integrity marker is missing")
	}
	if err := sealWindowsSnapshot(&snapshot); err != nil {
		return err
	}
	if snapshot.IntegritySHA256 != want {
		return errors.New("captured network snapshot integrity check failed")
	}
	return nil
}

func validateExactOwnedRouteSet(actual, expected []WindowsOwnedRoute, label string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("captured %s route ownership count is invalid", label)
	}
	want := make(map[WindowsOwnedRoute]struct{}, len(expected))
	for _, route := range expected {
		want[route] = struct{}{}
	}
	seen := make(map[WindowsOwnedRoute]struct{}, len(actual))
	for _, route := range actual {
		if _, duplicate := seen[route]; duplicate {
			return fmt.Errorf("captured %s route ownership contains a duplicate", label)
		}
		seen[route] = struct{}{}
		if _, ok := want[route]; !ok {
			return fmt.Errorf("captured %s route ownership tuple is invalid", label)
		}
	}
	return nil
}

func equalStringSlices(left, right []string) bool {
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

func validateCapturedNodeRoutes(routes []WindowsNodeRouteSnapshot, expected []string) error {
	if len(routes) != len(expected) {
		return errors.New("captured node route set does not match the configured nodes")
	}
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if _, duplicate := seen[route.NodeAddress]; duplicate {
			return errors.New("captured node route set contains a duplicate")
		}
		seen[route.NodeAddress] = struct{}{}
	}
	for _, node := range expected {
		if _, ok := seen[node]; !ok {
			return errors.New("captured node route set does not match the configured nodes")
		}
	}
	return nil
}

func validateTUNIdentity(identity WindowsTUNIdentity, baseline []string) error {
	if identity.InterfaceIndex <= 0 || identity.InterfaceAlias != windowsTUNInterface || strings.TrimSpace(identity.InterfaceGuid) == "" {
		return errors.New("TUN identity is incomplete")
	}
	for _, guid := range baseline {
		if strings.EqualFold(guid, identity.InterfaceGuid) {
			return errors.New("TUN adapter was present before core launch")
		}
	}
	if len(identity.Addresses) != 1 || identity.Addresses[0] != windowsTUNAddress {
		return errors.New("TUN adapter address does not match the rendered configuration")
	}
	return nil
}

type fileSnapshotStore struct{}

func (fileSnapshotStore) Save(path string, snapshot WindowsNetworkSnapshot) error {
	contents, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".network-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func (fileSnapshotStore) Load(path string) (WindowsNetworkSnapshot, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return WindowsNetworkSnapshot{}, errSnapshotNotFound
	}
	if err != nil {
		return WindowsNetworkSnapshot{}, err
	}
	var snapshot WindowsNetworkSnapshot
	if err := json.Unmarshal(contents, &snapshot); err != nil {
		return WindowsNetworkSnapshot{}, err
	}
	return snapshot, nil
}

func (fileSnapshotStore) Delete(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type powerShellNetworkRunner struct{}

func powerShellInputEnvelope(input []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(input))
}

const networkPowerShellTransportPrologue = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$envelope = [Console]::In.ReadToEnd().Trim()
if ([string]::IsNullOrWhiteSpace($envelope)) { throw 'PowerShell input envelope is empty.' }
$jsonBytes = [Convert]::FromBase64String($envelope)
$json = $utf8.GetString($jsonBytes)
$i = ($json | ConvertFrom-Json)`

func (powerShellNetworkRunner) Run(ctx context.Context, operation string, input []byte) ([]byte, error) {
	script, exists := networkPowerShellScripts[operation]
	if !exists {
		return nil, errors.New("unknown network operation")
	}
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(networkPowerShellTransportPrologue+"\n"+script))
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	command.Stdin = bytes.NewReader(powerShellInputEnvelope(input))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, newFixedNetworkOperationErrorWithContext(ctx, operation, err, nil)
	}
	if err := command.Wait(); err != nil {
		return nil, newFixedNetworkOperationErrorWithContext(ctx, operation, err, stderr.Bytes())
	}
	if !utf8.Valid(stdout.Bytes()) {
		const detail = "invalid PowerShell UTF-8 output"
		return nil, newFixedNetworkOperationErrorWithContext(ctx, operation, errors.New(detail), []byte(detail))
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}

func encodePowerShell(script string) string {
	encoded := utf16.Encode([]rune(script))
	bytes := make([]byte, len(encoded)*2)
	for index, value := range encoded {
		binary.LittleEndian.PutUint16(bytes[index*2:], value)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func normalizeWindowsFirewallPrefixes(values []string) []string {
	result := make([]string, 0, len(values)+1)
	seen := make(map[string]struct{}, len(values)+1)
	appendUnique := func(value string) {
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	for _, value := range values {
		if value == "::/0" {
			appendUnique("::/1")
			appendUnique("8000::/1")
			continue
		}
		appendUnique(value)
	}
	return result
}

func complementIPv4Prefixes(excluded []netip.Prefix) []string {
	remaining := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	for _, exclusion := range excluded {
		if !exclusion.Addr().Is4() {
			continue
		}
		next := make([]netip.Prefix, 0, len(remaining))
		for _, candidate := range remaining {
			next = append(next, subtractIPv4Prefix(candidate, exclusion.Masked())...)
		}
		remaining = next
	}
	sort.Slice(remaining, func(left, right int) bool {
		leftAddress := binary.BigEndian.Uint32(remaining[left].Addr().AsSlice())
		rightAddress := binary.BigEndian.Uint32(remaining[right].Addr().AsSlice())
		if leftAddress == rightAddress {
			return remaining[left].Bits() < remaining[right].Bits()
		}
		return leftAddress < rightAddress
	})
	result := make([]string, len(remaining))
	for index, prefix := range remaining {
		result[index] = prefix.String()
	}
	return result
}

func subtractIPv4Prefix(candidate, exclusion netip.Prefix) []netip.Prefix {
	if !candidate.Overlaps(exclusion) {
		return []netip.Prefix{candidate}
	}
	if exclusion.Bits() <= candidate.Bits() && exclusion.Contains(candidate.Addr()) {
		return nil
	}
	if candidate.Bits() >= 32 {
		return nil
	}
	address := binary.BigEndian.Uint32(candidate.Addr().AsSlice())
	childBits := candidate.Bits() + 1
	secondAddress := address | uint32(1<<(32-childBits))
	var firstBytes, secondBytes [4]byte
	binary.BigEndian.PutUint32(firstBytes[:], address)
	binary.BigEndian.PutUint32(secondBytes[:], secondAddress)
	first := netip.PrefixFrom(netip.AddrFrom4(firstBytes), childBits)
	second := netip.PrefixFrom(netip.AddrFrom4(secondBytes), childBits)
	result := subtractIPv4Prefix(first, exclusion)
	return append(result, subtractIPv4Prefix(second, exclusion)...)
}

// canonicalNonGlobalIPv4Prefixes mirrors the IANA IPv4 Special-Purpose
// Address Registry's Globally Reachable column. The 192.0.0.0/24 parent is
// non-global except for its two globally reachable anycast /32 assignments.
func canonicalNonGlobalIPv4Prefixes() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.2.0/24", "192.88.99.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	ietfProtocolAssignments := []netip.Prefix{netip.MustParsePrefix("192.0.0.0/24")}
	for _, globallyReachable := range []string{"192.0.0.9/32", "192.0.0.10/32"} {
		next := make([]netip.Prefix, 0, len(ietfProtocolAssignments)+8)
		for _, candidate := range ietfProtocolAssignments {
			next = append(next, subtractIPv4Prefix(candidate, netip.MustParsePrefix(globallyReachable))...)
		}
		ietfProtocolAssignments = next
	}
	prefixes = append(prefixes, ietfProtocolAssignments...)
	return prefixes
}

func complementIPv6Prefixes(excluded []netip.Prefix) []string {
	// 2000::/3 is the IANA global-unicast space. The IPv4-only PoC keeps this
	// public IPv6 space on the sink guard while leaving loopback, link-local,
	// ULA, multicast, and other non-Internet protocol ranges untouched.
	return complementIPv6From(netip.MustParsePrefix("2000::/3"), excluded)
}

func complementIPv6From(base netip.Prefix, excluded []netip.Prefix) []string {
	remaining := []netip.Prefix{base}
	for _, exclusion := range excluded {
		if !exclusion.Addr().Is6() || exclusion.Addr().Is4In6() {
			continue
		}
		next := make([]netip.Prefix, 0, len(remaining))
		for _, candidate := range remaining {
			next = append(next, subtractIPv6Prefix(candidate, exclusion.Masked())...)
		}
		remaining = next
	}
	result := make([]string, len(remaining))
	for index, prefix := range remaining {
		result[index] = prefix.String()
	}
	sort.Strings(result)
	return result
}

func subtractIPv6Prefix(candidate, exclusion netip.Prefix) []netip.Prefix {
	if !candidate.Overlaps(exclusion) {
		return []netip.Prefix{candidate}
	}
	if exclusion.Bits() <= candidate.Bits() && exclusion.Contains(candidate.Addr()) {
		return nil
	}
	if candidate.Bits() >= 128 {
		return nil
	}
	firstAddress := candidate.Addr().As16()
	secondAddress := firstAddress
	newBit := candidate.Bits()
	secondAddress[newBit/8] |= byte(1 << (7 - (newBit % 8)))
	childBits := candidate.Bits() + 1
	first := netip.PrefixFrom(netip.AddrFrom16(firstAddress), childBits)
	second := netip.PrefixFrom(netip.AddrFrom16(secondAddress), childBits)
	result := subtractIPv6Prefix(first, exclusion)
	return append(result, subtractIPv6Prefix(second, exclusion)...)
}

func standardNonPublicIPv6Prefixes() []netip.Prefix {
	values := []string{
		"::/128", "::1/128", "100::/64", "2001:2::/48", "2001:db8::/32",
		"fc00::/7", "fe80::/10", "ff00::/8",
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

// dnsMetricPowerShell switches DNS and the TUN metric for one direction of
// the connection lifecycle. Routes are handled natively; this covers the
// per-interface resolver and metric writes only.
const dnsMetricPowerShell = `if ([bool]$i.DNSConnected) {
  Clear-DnsClientCache -ErrorAction SilentlyContinue
  $tunIndex = [int]$i.OwnedTUN.InterfaceIndex
  $all = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -ne $tunIndex -and $_.InterfaceIndex -gt 1 } | Select-Object -ExpandProperty InterfaceIndex -Unique)
  if ($all.Count -ne 0) { Set-DnsClientServerAddress -InterfaceIndex $all -ServerAddresses @([string]$i.TUNDNS) -ErrorAction Stop }
  Set-DnsClientServerAddress -InterfaceIndex $tunIndex -ServerAddresses @([string]$i.TUNDNS) -ErrorAction Stop
  [pscustomobject]@{Connected=$true}|ConvertTo-Json -Compress
} else {
  Clear-DnsClientCache -ErrorAction SilentlyContinue
  $tunIndex = [int]$i.OwnedTUN.InterfaceIndex
  foreach ($physical in @($i.Interfaces | Where-Object { $null -ne $_ })) {
    if ([bool]$physical.DNSAutomatic) {
      Set-DnsClientServerAddress -InterfaceIndex ([int]$physical.Index) -ResetServerAddresses -ErrorAction Stop
    } else {
      Set-DnsClientServerAddress -InterfaceIndex ([int]$physical.Index) -ServerAddresses @($physical.DNSServers) -ErrorAction Stop
    }
  }
  $strays = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -ne $tunIndex -and ($_.ServerAddresses -contains [string]$i.TUNDNS) })
  foreach ($stray in $strays) { Set-DnsClientServerAddress -InterfaceIndex $stray.InterfaceIndex -ResetServerAddresses -ErrorAction Stop }
  [pscustomobject]@{Connected=$false}|ConvertTo-Json -Compress
}`

var networkPowerShellScripts = map[string]string{
	networkOperationTUNRecover:      recoverTUNPowerShell,
	networkOperationCapture:         captureNetworkPowerShell,
	networkOperationScan:            scanNetworkPowerShell,
	networkOperationBlock:           blockNetworkPowerShell,
	networkOperationVerify:          verifyNetworkPowerShell,
	networkOperationEmergency:       emergencyNetworkPowerShell,
	networkOperationReady:           readyNetworkPowerShell,
	networkOperationActivate:        activateNetworkPowerShell,
	networkOperationRestore:         restoreNetworkPowerShell,
	networkOperationPreparedRestore: preparedRestoreNetworkPowerShell,
	networkOperationDNSMetric:       dnsMetricPowerShell,
	networkOperationResidue:         residueNetworkPowerShell,
	networkOperationFirewallPrepare: preparedFirewallPreparePowerShell,
	networkOperationFirewallArm:     preparedFirewallArmPowerShell,
	networkOperationFirewallDisable: preparedFirewallDisablePowerShell,
	networkOperationFirewallAudit:   preparedFirewallAuditPowerShell,
}

const recoverTUNPowerShell = `$managed = @(Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" -ErrorAction Stop | Where-Object {
  [string]::Equals([string]$_.ExecutablePath, [string]$i.CoreExecutable, [StringComparison]::OrdinalIgnoreCase)
})
if ($managed.Count -ne 0) { throw 'tun_recover: managed core is active.' }
$networkClass = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'
$matches = @()
$candidates = @(Get-PnpDevice -PresentOnly:$false -ErrorAction Stop | Where-Object {
  [string]$_.InstanceId -like 'SWD\WINTUN\*' -and
  [string]$_.FriendlyName -eq 'sing-tun Tunnel' -and
  [string]$_.Problem -eq 'CM_PROB_PHANTOM'
})
foreach ($candidate in $candidates) {
  $instanceId = [string]$candidate.InstanceId
  $guid = $instanceId.Substring($instanceId.LastIndexOf('\') + 1)
  if ($guid -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }
  $connection = Get-ItemProperty -LiteralPath (Join-Path (Join-Path $networkClass $guid) 'Connection') -ErrorAction SilentlyContinue
  if ($null -ne $connection -and [string]::Equals([string]$connection.Name, [string]$i.TUNInterface, [StringComparison]::OrdinalIgnoreCase)) {
    $matches += $candidate
  }
}
if ($matches.Count -gt 1) { throw 'tun_recover: ownership is ambiguous.' }
if ($matches.Count -eq 1) {
  $instanceId = [string]$matches[0].InstanceId
  & "$env:SystemRoot\System32\pnputil.exe" /remove-device $instanceId | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'tun_recover: removal failed.' }
  $remaining = @(Get-PnpDevice -PresentOnly:$false -ErrorAction Stop | Where-Object {
    [string]::Equals([string]$_.InstanceId, $instanceId, [StringComparison]::OrdinalIgnoreCase)
  })
  if ($remaining.Count -ne 0) { throw 'tun_recover: removal was not proven.' }
}
[pscustomobject]@{Removed=($matches.Count -eq 1)} | ConvertTo-Json -Compress`

const residueNetworkPowerShell = `$allRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group ([string]$i.FirewallGroup) -ErrorAction SilentlyContinue)
$enabledRules = @($allRules | Where-Object { [string]$_.Enabled -eq 'True' })
$managedRules = $enabledRules.Count
$disabledPreparedRules = $allRules.Count - $enabledRules.Count
$routeKeys = @{}
foreach ($owned in @($i.OwnedRoutes | Where-Object { $null -ne $_ })) {
  $family = [string]$owned.AddressFamily
  if ([string]::IsNullOrWhiteSpace($family)) { $family = 'IPv4' }
  $matches = @(Get-NetRoute -AddressFamily $family -DestinationPrefix ([string]$owned.DestinationPrefix) -ErrorAction SilentlyContinue | Where-Object {
    [int]$_.InterfaceIndex -eq [int]$owned.InterfaceIndex -and
    [string]$_.NextHop -eq [string]$owned.NextHop -and
    [int]$_.RouteMetric -eq [int]$owned.RouteMetric
  })
  foreach ($match in $matches) {
    $key = $family + '|' + [string]$match.DestinationPrefix + '|' + [string]$match.InterfaceIndex + '|' + [string]$match.NextHop + '|' + [string]$match.RouteMetric
    $routeKeys[$key] = $true
  }
}
$tunKeys = @{}
$fixedAliases = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { [string]$_.InterfaceAlias -eq [string]$i.TUNInterface })
foreach ($adapter in $fixedAliases) { $tunKeys[[string]$adapter.InterfaceGuid] = $true }
if ($null -ne $i.OwnedTUN) {
  $ownedAdapters = @(Get-NetAdapter -IncludeHidden -InterfaceIndex ([int]$i.OwnedTUN.InterfaceIndex) -ErrorAction SilentlyContinue | Where-Object {
    [string]$_.InterfaceGuid -eq [string]$i.OwnedTUN.InterfaceGuid -and [string]$_.InterfaceAlias -eq [string]$i.OwnedTUN.InterfaceAlias
  })
  foreach ($adapter in $ownedAdapters) { $tunKeys[[string]$adapter.InterfaceGuid] = $true }
}
$coreProcesses = @(Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" -ErrorAction SilentlyContinue | Where-Object {
  [string]$_.ExecutablePath -eq [string]$i.CoreExecutable
}).Count
[pscustomobject]@{
  ManagedRules = [int]$managedRules
  DisabledPreparedRules = [int]$disabledPreparedRules
  ProductRoutes = [int]$routeKeys.Count
  ProductTUNs = [int]$tunKeys.Count
  CoreProcesses = [int]$coreProcesses
} | ConvertTo-Json -Compress`

const captureNetworkPowerShell = `$defaults = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric)
if ($defaults.Count -eq 0) { throw 'No IPv4 default route exists.' }
$interfaces = @()
foreach ($index in @($defaults.InterfaceIndex | Sort-Object -Unique)) {
  $ip = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $index
  $adapter = Get-NetAdapter -InterfaceIndex $index
  $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $index).ServerAddresses
  $registry = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $adapter.InterfaceGuid) -ErrorAction SilentlyContinue
  $interfaces += [pscustomobject]@{
    Index = [int]$index
    InterfaceGuid = [string]$adapter.InterfaceGuid
    Alias = [string]$adapter.InterfaceAlias
    InterfaceMetric = [int]$ip.InterfaceMetric
    AutomaticMetric = ([string]$ip.AutomaticMetric -eq 'Enabled')
    DNSAutomatic = [string]::IsNullOrWhiteSpace([string]$registry.NameServer)
    DNSServers = @($dns)
  }
}
$collisions = @()
foreach ($name in @($i.FirewallRuleNames)) {
  if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { $collisions += [string]$name }
}
if (Get-NetFirewallRule -Group $i.FirewallGroup -ErrorAction SilentlyContinue) { $collisions += [string]$i.FirewallGroup }
$allAdapters = @(Get-NetAdapter -IncludeHidden)
$baselineGuids = @($allAdapters | ForEach-Object { [string]$_.InterfaceGuid })
$tunAliasPresent = [bool]($allAdapters | Where-Object { $_.InterfaceAlias -eq [string]$i.TUNInterface })
$tunAddressIP = ([string]$i.TUNAddress).Split('/')[0]
$tunAddressPresent = [bool](Get-NetIPAddress -AddressFamily IPv4 -IPAddress $tunAddressIP -ErrorAction SilentlyContinue)
$nodeRoutes = @()
foreach ($node in @($i.NodeAddresses | Where-Object { $null -ne $_ })) {
  $selection = @(Find-NetRoute -RemoteIPAddress ([string]$node))
  $route = @($selection | Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } | Select-Object -First 1)
  if ($route.Count -ne 1) { throw 'Could not resolve one best route for a configured node.' }
  $prefixLength = [int](([string]$route[0].DestinationPrefix).Split('/')[1])
  $nodeRoutes += [pscustomobject]@{
    NodeAddress = [string]$node
    DestinationPrefix = [string]$route[0].DestinationPrefix
    InterfaceIndex = [int]$route[0].InterfaceIndex
    NextHop = [string]$route[0].NextHop
    RouteMetric = [int]$route[0].RouteMetric
    InterfaceMetric = [int]$route[0].InterfaceMetric
    EffectiveMetric = [int]$route[0].RouteMetric + [int]$route[0].InterfaceMetric
    BypassRequired = ($prefixLength -eq 0)
  }
}
[pscustomobject]@{
  Version = 1
  Interfaces = @($interfaces)
  OwnedFirewallRulesPresent = @($collisions)
  ConflictingTUNRoutes = @()
  BaselineAdapterGuids = @($baselineGuids)
  TUNAliasPresent = $tunAliasPresent
  TUNAddressPresent = $tunAddressPresent
  NodeRoutes = @($nodeRoutes)
} | ConvertTo-Json -Compress -Depth 8`

const scanNetworkPowerShell = `$indices = @(Get-NetIPInterface | Where-Object { [int]$_.InterfaceIndex -gt 0 } | Select-Object -ExpandProperty InterfaceIndex | Sort-Object -Unique)
$adapters = @()
foreach ($index in $indices) {
  $matches = @(Get-NetAdapter -IncludeHidden -InterfaceIndex ([int]$index) -ErrorAction SilentlyContinue)
  if ($matches.Count -eq 0) { continue }
  if ($matches.Count -ne 1) { throw 'adapter_identity_join: IP interface did not resolve to exactly one adapter.' }
  $adapter = $matches[0]
  if ([int]$adapter.InterfaceIndex -le 0 -or [string]::IsNullOrWhiteSpace([string]$adapter.InterfaceGuid) -or [string]::IsNullOrWhiteSpace([string]$adapter.InterfaceAlias)) {
    throw 'adapter_identity_join: adapter identity is incomplete.'
  }
  $adapters += [pscustomobject]@{
    InterfaceIndex = [int]$adapter.InterfaceIndex
    InterfaceGuid = [string]$adapter.InterfaceGuid
    InterfaceAlias = [string]$adapter.InterfaceAlias
    Status = [string]$adapter.Status
  }
}
$adapters = @($adapters)
ConvertTo-Json -InputObject $adapters -Compress -Depth 4`

const blockNetworkPowerShell = `$remote = @($i.BlockedRemoteAddresses)
$dnsRemote = @($i.DNSBlockedRemoteAddresses)
$desired = @([string]$i.FirewallRuleNames[3], [string]$i.FirewallRuleNames[4], [string]$i.FirewallRuleNames[5])
function Test-ManagedAdapterRule([string]$name, [string]$alias) {
  $existing = @(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)
  if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and [string]$existing[0].Group -ne [string]$i.FirewallGroup)) { throw 'Firewall rule name collision.' }
  if ($existing.Count -eq 0) { return $false }
  $aliases = @($existing[0] | Get-NetFirewallInterfaceFilter).InterfaceAlias
  if ($aliases.Count -eq 1 -and [string]$aliases[0] -eq $alias) { return $true }
  $existing[0] | Remove-NetFirewallRule -ErrorAction Stop
  return $false
}
function Test-ManagedRule([string]$name) {
  $existing = @(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)
  if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and [string]$existing[0].Group -ne [string]$i.FirewallGroup)) { throw 'Firewall rule name collision.' }
  return ($existing.Count -eq 1)
}
foreach ($adapter in @($i.ProtectedAdapters)) {
  $suffix = ([string]$adapter.InterfaceGuid).Trim('{}').Replace('-', '')
  $tcpName = ([string]$i.FirewallRuleNames[0]) + '.' + $suffix
  $quicName = ([string]$i.FirewallRuleNames[1]) + '.' + $suffix
  $udpName = ([string]$i.FirewallRuleNames[2]) + '.' + $suffix
  $desired += @($tcpName, $quicName, $udpName)
  if (-not (Test-ManagedAdapterRule $tcpName ([string]$adapter.InterfaceAlias))) { New-NetFirewallRule -Name $tcpName -DisplayName $tcpName -Group $i.FirewallGroup -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $remote -InterfaceAlias ([string]$adapter.InterfaceAlias) -Profile Any | Out-Null }
  if (-not (Test-ManagedAdapterRule $quicName ([string]$adapter.InterfaceAlias))) { New-NetFirewallRule -Name $quicName -DisplayName $quicName -Group $i.FirewallGroup -Direction Outbound -Action Block -Protocol UDP -RemotePort 443 -RemoteAddress $remote -InterfaceAlias ([string]$adapter.InterfaceAlias) -Profile Any | Out-Null }
  if (-not (Test-ManagedAdapterRule $udpName ([string]$adapter.InterfaceAlias))) { New-NetFirewallRule -Name $udpName -DisplayName $udpName -Group $i.FirewallGroup -Direction Outbound -Action Block -Protocol UDP -RemoteAddress $remote -InterfaceAlias ([string]$adapter.InterfaceAlias) -Profile Any | Out-Null }
}
if (-not (Test-ManagedRule ([string]$i.FirewallRuleNames[3]))) { New-NetFirewallRule -Name $i.FirewallRuleNames[3] -DisplayName $i.FirewallRuleNames[3] -Group $i.FirewallGroup -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -RemoteAddress $dnsRemote -Profile Any | Out-Null }
if (-not (Test-ManagedRule ([string]$i.FirewallRuleNames[4]))) { New-NetFirewallRule -Name $i.FirewallRuleNames[4] -DisplayName $i.FirewallRuleNames[4] -Group $i.FirewallGroup -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 -RemoteAddress $dnsRemote -Profile Any | Out-Null }
Get-NetFirewallRule -Group $i.FirewallGroup -ErrorAction SilentlyContinue | Where-Object { $desired -notcontains $_.Name } | Remove-NetFirewallRule -ErrorAction Stop`

const verifyNetworkPowerShell = `function Assert-EqualSet([string]$label, $actual, $expected) {
  $left = @($actual | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
  $right = @($expected | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
  if ($left.Count -ne $right.Count -or [string]::Join('|', $left) -ne [string]::Join('|', $right)) { throw ('active_store_verify: ' + $label + ' does not match.') }
}
function Normalize-AddressToken($value) {
  $text = ([string]$value).Trim().ToLowerInvariant()
  if ($text -match '^(?<address>\d{1,3}(?:\.\d{1,3}){3})/(?<mask>\d{1,3}(?:\.\d{1,3}){3})$') {
    $address = [string]$Matches.address
    $addressOctets = @($address.Split('.') | ForEach-Object { [int]$_ })
    $maskOctets = @(([string]$Matches.mask).Split('.') | ForEach-Object { [int]$_ })
    if (@($addressOctets | Where-Object { $_ -lt 0 -or $_ -gt 255 }).Count -ne 0 -or @($maskOctets | Where-Object { $_ -lt 0 -or $_ -gt 255 }).Count -ne 0) { return $text }
    $prefixLength = 0
    $seenZero = $false
    foreach ($octet in $maskOctets) {
      for ($bit = 7; $bit -ge 0; $bit--) {
        if (($octet -band (1 -shl $bit)) -ne 0) {
          if ($seenZero) { return $text }
          $prefixLength++
        } else {
          $seenZero = $true
        }
      }
    }
    if ($prefixLength -eq 32) { return $address }
    return ($address + '/' + [string]$prefixLength)
  }
  if ($text -match '^(?<address>\d{1,3}(?:\.\d{1,3}){3})/32$') { return [string]$Matches.address }
  if ($text -match '^(?<address>[^/]*:[^/]*)/128$') { return [string]$Matches.address }
  return $text
}
function Assert-EqualAddressSet([string]$label, $actual, $expected) {
  $left = @($actual | ForEach-Object { Normalize-AddressToken $_ } | Sort-Object -Unique)
  $right = @($expected | ForEach-Object { Normalize-AddressToken $_ } | Sort-Object -Unique)
  if ($left.Count -ne $right.Count -or [string]::Join('|', $left) -ne [string]::Join('|', $right)) { throw ('active_store_verify: ' + $label + ' does not match.') }
}
function Assert-Rule([string]$name, [string]$protocol, $remotePort, $remoteAddress, [string]$interfaceAlias) {
  $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction SilentlyContinue)
  if ($rules.Count -ne 1) { throw ('active_store_verify: expected exactly one rule named ' + $name + '.') }
  $rule = $rules[0]
  if ([string]$rule.Group -ne [string]$i.FirewallGroup -or [string]$rule.Enabled -ne 'True' -or [string]$rule.Direction -ne 'Outbound' -or [string]$rule.Action -ne 'Block') { throw ('active_store_verify: rule metadata does not match for ' + $name + '.') }
  $port = @($rule | Get-NetFirewallPortFilter)
  if ($port.Count -ne 1 -or [string]$port[0].Protocol -ne $protocol) { throw ('active_store_verify: protocol does not match for ' + $name + '.') }
  Assert-EqualSet ($name + ' remote port') @($port[0].RemotePort) @($remotePort)
  $address = @($rule | Get-NetFirewallAddressFilter)
  if ($address.Count -ne 1) { throw ('active_store_verify: address filter is ambiguous for ' + $name + '.') }
  Assert-EqualAddressSet ($name + ' remote address') @($address[0].RemoteAddress) @($remoteAddress)
  if (-not [string]::IsNullOrWhiteSpace($interfaceAlias)) {
    $interface = @($rule | Get-NetFirewallInterfaceFilter)
    if ($interface.Count -ne 1) { throw ('active_store_verify: interface filter is ambiguous for ' + $name + '.') }
    Assert-EqualSet ($name + ' interface alias') @($interface[0].InterfaceAlias) @($interfaceAlias)
  }
}
$remote = @($i.BlockedRemoteAddresses)
foreach ($adapter in @($i.ProtectedAdapters)) {
  $suffix = ([string]$adapter.InterfaceGuid).Trim('{}').Replace('-', '')
  Assert-Rule (([string]$i.FirewallRuleNames[0]) + '.' + $suffix) 'TCP' @('Any') $remote ([string]$adapter.InterfaceAlias)
  Assert-Rule (([string]$i.FirewallRuleNames[1]) + '.' + $suffix) 'UDP' @('443') $remote ([string]$adapter.InterfaceAlias)
  Assert-Rule (([string]$i.FirewallRuleNames[2]) + '.' + $suffix) 'UDP' @('Any') $remote ([string]$adapter.InterfaceAlias)
}
Assert-Rule ([string]$i.FirewallRuleNames[3]) 'UDP' @('53') @($i.DNSBlockedRemoteAddresses) ''
Assert-Rule ([string]$i.FirewallRuleNames[4]) 'TCP' @('53') @($i.DNSBlockedRemoteAddresses) ''`

const emergencyNetworkPowerShell = preparedFirewallPowerShellHelpers + `$remote = @($i.BlockedRemoteAddresses)
$prepared = @($i.PreparedRules | Where-Object { $null -ne $_ })
if ($prepared.Count -ne 0) {
  if ([int]$i.RuleDefinitionVersion -ne 2 -or [uint64]$i.PreparedGeneration -eq 0) { throw 'prepared_firewall: invalid emergency generation.' }
  $candidates = @($prepared | Where-Object { [bool]$_.Emergency })
  if ($candidates.Count -ne 1) { throw 'prepared_firewall: emergency rule is ambiguous.' }
  $expected = $candidates[0]
  $name = [string]$expected.Name
  $existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
  if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and [string]$existing[0].Group -ne [string]$i.FirewallGroup)) { throw 'Firewall rule name collision.' }
  if ($existing.Count -eq 0) {
    New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group $i.FirewallGroup -Description (Get-PreparedDescription $expected) -Direction Outbound -Action Block -Protocol Any -RemoteAddress @(Get-PreparedRemote $expected) -InterfaceAlias @(Get-PreparedAliases $expected) -Profile Any -Enabled True | Out-Null
  } else {
    $currentEnabled = [string]$existing[0].Enabled
    if ($currentEnabled -ne 'True' -and $currentEnabled -ne 'False') { throw 'prepared_firewall: invalid emergency enabled state.' }
    Assert-PreparedRule $expected 'PersistentStore' $currentEnabled
    if ($currentEnabled -eq 'False') { Enable-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop }
  }
  Assert-PreparedRule $expected 'ActiveStore' 'True'
  [pscustomobject]@{EmergencyEnabled=$true;PreparedGeneration=[uint64]$i.PreparedGeneration}|ConvertTo-Json -Compress
  return
}
$name = [string]$i.FirewallRuleNames[5]
$existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and [string]$existing[0].Group -ne [string]$i.FirewallGroup)) { throw 'Firewall rule name collision.' }
if ($existing.Count -eq 0) {
  New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group $i.FirewallGroup -Direction Outbound -Action Block -Protocol Any -RemoteAddress $remote -Profile Any -Enabled True | Out-Null
} else {
  Enable-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
}
$active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction SilentlyContinue)
if ($active.Count -ne 1 -or [string]$active[0].Enabled -ne 'True' -or [string]$active[0].Group -ne [string]$i.FirewallGroup) { throw 'Emergency firewall rule did not become active.' }
[pscustomobject]@{EmergencyEnabled=$true}|ConvertTo-Json -Compress`

const readyNetworkPowerShell = `$deadline = [DateTime]::UtcNow.AddSeconds(2)
do {
  $adapters = @(Get-NetAdapter -InterfaceAlias $i.TUNInterface -IncludeHidden -ErrorAction SilentlyContinue)
  if ($adapters.Count -gt 1) { throw 'More than one fixed TUN adapter exists.' }
  if ($adapters.Count -eq 1) {
    $tun = $adapters[0]
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $tun.InterfaceIndex -ErrorAction SilentlyContinue | ForEach-Object { ([string]$_.IPAddress) + '/' + ([string]$_.PrefixLength) })
    if ($addresses -contains [string]$i.TUNAddress) { break }
  }
  Start-Sleep -Milliseconds 100
} while ([DateTime]::UtcNow -lt $deadline)
if ($adapters.Count -ne 1 -or -not ($addresses -contains [string]$i.TUNAddress)) { throw 'Expected fixed TUN adapter and address were not ready.' }
[pscustomobject]@{
  InterfaceIndex = [int]$tun.InterfaceIndex
  InterfaceGuid = [string]$tun.InterfaceGuid
  InterfaceAlias = [string]$tun.InterfaceAlias
  InterfaceDescription = [string]$tun.InterfaceDescription
  HardwareInterface = [bool]$tun.HardwareInterface
  Virtual = [bool]$tun.Virtual
  Addresses = @($addresses)
} | ConvertTo-Json -Compress -Depth 5`

const activateNetworkPowerShell = `$tun = Get-NetAdapter -InterfaceIndex $i.OwnedTUN.InterfaceIndex -IncludeHidden -ErrorAction Stop
if ([string]$tun.InterfaceGuid -ne [string]$i.OwnedTUN.InterfaceGuid -or [string]$tun.InterfaceAlias -ne [string]$i.OwnedTUN.InterfaceAlias) { throw 'Owned TUN identity changed before activation.' }
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $tun.InterfaceIndex -ErrorAction Stop | ForEach-Object { ([string]$_.IPAddress) + '/' + ([string]$_.PrefixLength) })
if ($addresses.Count -ne 1 -or $addresses[0] -ne [string]$i.TUNAddress) { throw 'Owned TUN address changed before activation.' }
Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $i.OwnedTUN.InterfaceIndex -AutomaticMetric Disabled -InterfaceMetric 1
Set-DnsClientServerAddress -InterfaceIndex $i.OwnedTUN.InterfaceIndex -ServerAddresses @([string]$i.TUNDNS)
foreach ($physical in @($i.Interfaces | Where-Object { $null -ne $_ })) {
  Set-DnsClientServerAddress -InterfaceIndex $physical.Index -ServerAddresses @([string]$i.TUNDNS)
}
foreach ($route in @($i.OwnedRoutes | Where-Object { $null -ne $_ })) {
  Get-NetRoute -AddressFamily $route.AddressFamily -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -eq [int]$route.InterfaceIndex -and $_.NextHop -eq [string]$route.NextHop -and $_.RouteMetric -eq [int]$route.RouteMetric } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
  New-NetRoute -AddressFamily $route.AddressFamily -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop -RouteMetric $route.RouteMetric -PolicyStore ActiveStore | Out-Null
}`

const restoreNetworkPowerShell = `function Install-Emergency {
  $name = [string]$i.FirewallRuleNames[5]
  $existing = @(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)
  if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and [string]$existing[0].Group -ne [string]$i.FirewallGroup)) { throw 'Emergency firewall rule name collision.' }
  if ($existing.Count -eq 0) { New-NetFirewallRule -Name $name -DisplayName $name -Group $i.FirewallGroup -Direction Outbound -Action Block -Protocol Any -RemoteAddress @($i.BlockedRemoteAddresses) -Profile Any | Out-Null }
  foreach ($entry in @(@{Name=[string]$i.FirewallRuleNames[3]; Protocol='UDP'}, @{Name=[string]$i.FirewallRuleNames[4]; Protocol='TCP'})) {
    $rule = @(Get-NetFirewallRule -Name $entry.Name -ErrorAction SilentlyContinue)
    if ($rule.Count -gt 1 -or ($rule.Count -eq 1 -and [string]$rule[0].Group -ne [string]$i.FirewallGroup)) { throw 'Emergency DNS firewall rule name collision.' }
    if ($rule.Count -eq 0) { New-NetFirewallRule -Name $entry.Name -DisplayName $entry.Name -Group $i.FirewallGroup -Direction Outbound -Action Block -Protocol $entry.Protocol -RemotePort 53 -RemoteAddress @($i.DNSBlockedRemoteAddresses) -Profile Any | Out-Null }
  }
}
try {
if ([bool]$i.RestoreInterfaces) {
$allAdapters = @(Get-NetAdapter -IncludeHidden)
foreach ($physical in @($i.Interfaces | Where-Object { $null -ne $_ })) {
  $matches = @($allAdapters | Where-Object { [string]::Equals([string]$_.InterfaceGuid, [string]$physical.InterfaceGuid, [StringComparison]::OrdinalIgnoreCase) })
  if ($matches.Count -eq 0) { continue }
  if ($matches.Count -ne 1) { throw 'Could not resolve one physical adapter by stable GUID.' }
  if ($null -ne $i.OwnedTUN -and [string]::Equals([string]$matches[0].InterfaceGuid, [string]$i.OwnedTUN.InterfaceGuid, [StringComparison]::OrdinalIgnoreCase)) { throw 'Physical adapter identity resolves to the owned TUN.' }
  $currentIndex = [int]$matches[0].InterfaceIndex
  if ([bool]$physical.DNSAutomatic) {
    Set-DnsClientServerAddress -InterfaceIndex $currentIndex -ResetServerAddresses
  } else {
    Set-DnsClientServerAddress -InterfaceIndex $currentIndex -ServerAddresses @($physical.DNSServers)
  }
  Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $currentIndex -AutomaticMetric $(if ([bool]$physical.AutomaticMetric) { 'Enabled' } else { 'Disabled' }) -InterfaceMetric $physical.InterfaceMetric
}
}
foreach ($route in @($i.OwnedRoutes | Where-Object { $null -ne $_ })) {
  Get-NetRoute -AddressFamily $route.AddressFamily -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -eq [int]$route.InterfaceIndex -and $_.NextHop -eq [string]$route.NextHop -and $_.RouteMetric -eq [int]$route.RouteMetric } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
Get-NetFirewallRule -Group $i.FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
} catch {
  Install-Emergency
  throw
}`

// preparedRestoreNetworkPowerShell reverses one prepared connection in a
// single transaction: baseline DNS/metrics/routes return first, then the
// exact-name prepared pool is disabled (never deleted). Any failure enables
// the pool's own emergency rule before rethrowing, so the machine stays
// fail-closed.
const preparedRestoreNetworkPowerShell = `function Enable-PreparedEmergency {
  $emergency = @($i.PreparedRules | Where-Object { [bool]$_.Emergency })
  if ($emergency.Count -ne 1) { throw 'prepared_restore: emergency rule is ambiguous.' }
  $name = [string]$emergency[0].Name
  $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
  if ($rule.Count -eq 1 -and [string]$rule[0].Group -eq [string]$i.FirewallGroup) { Enable-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop }
}
try {
if ([bool]$i.RestoreInterfaces) {
$allAdapters = @(Get-NetAdapter -IncludeHidden)
foreach ($physical in @($i.Interfaces | Where-Object { $null -ne $_ })) {
  $matches = @($allAdapters | Where-Object { [string]::Equals([string]$_.InterfaceGuid, [string]$physical.InterfaceGuid, [StringComparison]::OrdinalIgnoreCase) })
  if ($matches.Count -eq 0) { continue }
  if ($matches.Count -ne 1) { throw 'Could not resolve one physical adapter by stable GUID.' }
  if ($null -ne $i.OwnedTUN -and [string]::Equals([string]$matches[0].InterfaceGuid, [string]$i.OwnedTUN.InterfaceGuid, [StringComparison]::OrdinalIgnoreCase)) { throw 'Physical adapter identity resolves to the owned TUN.' }
  $currentIndex = [int]$matches[0].InterfaceIndex
  if ([bool]$physical.DNSAutomatic) {
    Set-DnsClientServerAddress -InterfaceIndex $currentIndex -ResetServerAddresses
  } else {
    Set-DnsClientServerAddress -InterfaceIndex $currentIndex -ServerAddresses @($physical.DNSServers)
  }
  Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $currentIndex -AutomaticMetric $(if ([bool]$physical.AutomaticMetric) { 'Enabled' } else { 'Disabled' }) -InterfaceMetric $physical.InterfaceMetric
}
}
foreach ($route in @($i.OwnedRoutes | Where-Object { $null -ne $_ })) {
  Get-NetRoute -AddressFamily $route.AddressFamily -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -eq [int]$route.InterfaceIndex -and $_.NextHop -eq [string]$route.NextHop -and $_.RouteMetric -eq [int]$route.RouteMetric } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$i.FirewallGroup) -ErrorAction SilentlyContinue)
$ownedNames = @($i.PreparedRules | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
$unknown = @($rules | Where-Object { $ownedNames -notcontains [string]$_.Name })
if ($unknown.Count -ne 0) { throw 'prepared_restore: refusing to disable unknown product-group rule.' }
foreach ($name in @($ownedNames)) {
  $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction SilentlyContinue)
  if ($rule.Count -eq 0) { continue }
  if ($rule.Count -ne 1 -or [string]$rule[0].Group -ne [string]$i.FirewallGroup) { throw ('prepared_restore: cannot disable unowned rule ' + [string]$name + '.') }
  Disable-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction Stop
}
$enabled = @($ownedNames | ForEach-Object { @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $_ -ErrorAction SilentlyContinue) } | Where-Object { [string]$_.Enabled -eq 'True' })
if ($enabled.Count -ne 0) { throw 'prepared_restore: an owned rule remains enabled.' }
[pscustomobject]@{DisabledCount=[int]$ownedNames.Count}|ConvertTo-Json -Compress
} catch {
  Enable-PreparedEmergency
  throw
}`
