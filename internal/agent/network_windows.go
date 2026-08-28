//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"

	"corp.example/overseas-access-gateway/internal/accessmodel"
)

const (
	networkOperationCapture  = "capture"
	networkOperationBlock    = "block"
	networkOperationActivate = "activate"
	networkOperationRestore  = "restore"

	windowsTUNInterface     = "RegenBioOverseasAccess"
	windowsTUNDNS           = "172.19.0.2"
	windowsTCPBlockRule     = "RegenBioOverseasAccess.BlockPublicTCP"
	windowsQUICBlockRule    = "RegenBioOverseasAccess.BlockQUIC"
	windowsUDPBlockRule     = "RegenBioOverseasAccess.BlockPublicUDP"
	windowsOwnedRouteMetric = 4096
)

var errSnapshotNotFound = errors.New("network snapshot not found")

type WindowsInterfaceSnapshot struct {
	Index           int      `json:"Index"`
	Alias           string   `json:"Alias"`
	InterfaceMetric int      `json:"InterfaceMetric"`
	AutomaticMetric bool     `json:"AutomaticMetric"`
	DNSAutomatic    bool     `json:"DNSAutomatic"`
	DNSServers      []string `json:"DNSServers"`
}

type WindowsNetworkSnapshot struct {
	Version                   int                        `json:"Version"`
	Interfaces                []WindowsInterfaceSnapshot `json:"Interfaces"`
	DefaultInterfaceIndex     int                        `json:"DefaultInterfaceIndex"`
	DefaultGateway            string                     `json:"DefaultGateway"`
	NodeRoutePresent          bool                       `json:"NodeRoutePresent"`
	OwnedFirewallRulesPresent []string                   `json:"OwnedFirewallRulesPresent"`
	ConflictingTUNRoutes      []string                   `json:"ConflictingTUNRoutes"`
	NodeAddress               string                     `json:"NodeAddress"`
	RouteMetric               int                        `json:"RouteMetric"`
}

type windowsNetworkInput struct {
	Interfaces             []WindowsInterfaceSnapshot `json:"Interfaces,omitempty"`
	FirewallRuleNames      []string                   `json:"FirewallRuleNames,omitempty"`
	BlockedRemoteAddresses []string                   `json:"BlockedRemoteAddresses,omitempty"`
	TUNInterface           string                     `json:"TUNInterface,omitempty"`
	TUNDNS                 string                     `json:"TUNDNS,omitempty"`
	TUNRoutePrefixes       []string                   `json:"TUNRoutePrefixes,omitempty"`
	NodeAddress            string                     `json:"NodeAddress,omitempty"`
	DefaultGateway         string                     `json:"DefaultGateway,omitempty"`
	DefaultInterfaceIndex  int                        `json:"DefaultInterfaceIndex,omitempty"`
	NodeRoutePresent       bool                       `json:"NodeRoutePresent,omitempty"`
	RouteMetric            int                        `json:"RouteMetric,omitempty"`
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
	mu              sync.Mutex
	policy          accessmodel.Policy
	statePath       string
	runner          networkRunner
	store           snapshotStore
	nodeAddress     string
	blockedPrefixes []string
	current         *WindowsNetworkSnapshot
}

func NewWindowsNetworkManager(policy accessmodel.Policy, statePath string) (*WindowsNetworkManager, error) {
	return newWindowsNetworkManager(policy, statePath, powerShellNetworkRunner{}, fileSnapshotStore{})
}

func newWindowsNetworkManager(policy accessmodel.Policy, statePath string, runner networkRunner, store snapshotStore) (*WindowsNetworkManager, error) {
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
	nodeAddress, err := netip.ParseAddr(nodes[0].Address)
	if err != nil || !nodeAddress.Is4() {
		return nil, errors.New("Windows network manager requires an IPv4 node")
	}
	excluded := standardNonPublicIPv4Prefixes()
	excluded = append(excluded, netip.PrefixFrom(nodeAddress, 32))
	for _, value := range policy.CorporateCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return nil, errors.New("Windows network manager requires IPv4 corporate CIDRs")
		}
		excluded = append(excluded, prefix.Masked())
	}
	for _, value := range policy.CorporateDNS {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return nil, errors.New("Windows network manager requires IPv4 corporate DNS addresses")
		}
		excluded = append(excluded, netip.PrefixFrom(address, 32))
	}
	blocked := complementIPv4Prefixes(excluded)
	return &WindowsNetworkManager{
		policy:          clonePolicy(policy),
		statePath:       statePath,
		runner:          runner,
		store:           store,
		nodeAddress:     nodeAddress.String(),
		blockedPrefixes: blocked,
	}, nil
}

func (m *WindowsNetworkManager) Capture(ctx context.Context) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		return nil, errors.New("network state is already captured")
	}
	if _, err := m.store.Load(m.statePath); err == nil {
		return nil, errors.New("unreconciled network snapshot exists")
	} else if !errors.Is(err, errSnapshotNotFound) {
		return nil, err
	}
	input := windowsNetworkInput{
		FirewallRuleNames: []string{windowsTCPBlockRule, windowsQUICBlockRule, windowsUDPBlockRule},
		TUNRoutePrefixes:  []string{"0.0.0.0/1", "128.0.0.0/1"},
		NodeAddress:       m.nodeAddress,
	}
	output, err := m.run(ctx, networkOperationCapture, input)
	if err != nil {
		return nil, err
	}
	var snapshot WindowsNetworkSnapshot
	if err := json.Unmarshal(output, &snapshot); err != nil {
		return nil, fmt.Errorf("decode captured network state: %w", err)
	}
	snapshot.Version = 1
	snapshot.NodeAddress = m.nodeAddress
	snapshot.RouteMetric = windowsOwnedRouteMetric
	if err := validateWindowsSnapshot(snapshot); err != nil {
		return nil, err
	}
	if len(snapshot.OwnedFirewallRulesPresent) != 0 {
		return nil, errors.New("owned firewall rule names already exist")
	}
	if len(snapshot.ConflictingTUNRoutes) != 0 {
		return nil, errors.New("managed TUN route prefixes already exist")
	}
	if err := m.store.Save(m.statePath, snapshot); err != nil {
		return nil, err
	}
	m.current = &snapshot
	return snapshot, nil
}

func (m *WindowsNetworkManager) InstallPublicTCPBlock(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return errors.New("network state was not captured")
	}
	input := windowsNetworkInput{
		Interfaces:             append([]WindowsInterfaceSnapshot(nil), m.current.Interfaces...),
		FirewallRuleNames:      []string{windowsTCPBlockRule, windowsQUICBlockRule, windowsUDPBlockRule},
		BlockedRemoteAddresses: append([]string(nil), m.blockedPrefixes...),
	}
	_, err := m.run(ctx, networkOperationBlock, input)
	return err
}

func (m *WindowsNetworkManager) ActivateTUNRoutes(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return errors.New("network state was not captured")
	}
	input := activationInput(*m.current)
	_, err := m.run(ctx, networkOperationActivate, input)
	return err
}

func (m *WindowsNetworkManager) Restore(ctx context.Context, value any) error {
	snapshot, err := asWindowsSnapshot(value)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.run(ctx, networkOperationRestore, activationInput(snapshot)); err != nil {
		return err
	}
	if err := m.store.Delete(m.statePath); err != nil {
		return err
	}
	m.current = nil
	return nil
}

func (m *WindowsNetworkManager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot, err := m.store.Load(m.statePath)
	if errors.Is(err, errSnapshotNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateWindowsSnapshot(snapshot); err != nil {
		return err
	}
	if _, err := m.run(ctx, networkOperationRestore, activationInput(snapshot)); err != nil {
		return err
	}
	if err := m.store.Delete(m.statePath); err != nil {
		return err
	}
	m.current = nil
	return nil
}

func (m *WindowsNetworkManager) run(ctx context.Context, operation string, input windowsNetworkInput) ([]byte, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return m.runner.Run(ctx, operation, payload)
}

func activationInput(snapshot WindowsNetworkSnapshot) windowsNetworkInput {
	return windowsNetworkInput{
		Interfaces:            append([]WindowsInterfaceSnapshot(nil), snapshot.Interfaces...),
		FirewallRuleNames:     []string{windowsTCPBlockRule, windowsQUICBlockRule, windowsUDPBlockRule},
		TUNInterface:          windowsTUNInterface,
		TUNDNS:                windowsTUNDNS,
		TUNRoutePrefixes:      []string{"0.0.0.0/1", "128.0.0.0/1"},
		NodeAddress:           snapshot.NodeAddress,
		DefaultGateway:        snapshot.DefaultGateway,
		DefaultInterfaceIndex: snapshot.DefaultInterfaceIndex,
		NodeRoutePresent:      snapshot.NodeRoutePresent,
		RouteMetric:           snapshot.RouteMetric,
	}
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
	if snapshot.Version != 1 || len(snapshot.Interfaces) == 0 || snapshot.DefaultInterfaceIndex <= 0 {
		return errors.New("captured network state is incomplete")
	}
	gateway, err := netip.ParseAddr(snapshot.DefaultGateway)
	if err != nil || !gateway.Is4() || gateway.IsUnspecified() {
		return errors.New("captured default gateway is invalid")
	}
	node, err := netip.ParseAddr(snapshot.NodeAddress)
	if err != nil || !node.Is4() {
		return errors.New("captured node address is invalid")
	}
	if snapshot.RouteMetric != windowsOwnedRouteMetric {
		return errors.New("captured route ownership marker is invalid")
	}
	for _, networkInterface := range snapshot.Interfaces {
		if networkInterface.Index <= 0 || strings.TrimSpace(networkInterface.Alias) == "" {
			return errors.New("captured interface state is invalid")
		}
		for _, server := range networkInterface.DNSServers {
			if _, err := netip.ParseAddr(server); err != nil {
				return errors.New("captured DNS state is invalid")
			}
		}
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

func (powerShellNetworkRunner) Run(ctx context.Context, operation string, input []byte) ([]byte, error) {
	script, exists := networkPowerShellScripts[operation]
	if !exists {
		return nil, errors.New("unknown network operation")
	}
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(script))
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	command.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start fixed network operation %s: %w", operation, err)
	}
	if err := command.Wait(); err != nil {
		return nil, fmt.Errorf("fixed network operation %s failed: %w", operation, err)
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

func standardNonPublicIPv4Prefixes() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

var networkPowerShellScripts = map[string]string{
	networkOperationCapture:  captureNetworkPowerShell,
	networkOperationBlock:    blockNetworkPowerShell,
	networkOperationActivate: activateNetworkPowerShell,
	networkOperationRestore:  restoreNetworkPowerShell,
}

const captureNetworkPowerShell = `$ErrorActionPreference = 'Stop'
$i = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
$defaults = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric)
if ($defaults.Count -eq 0) { throw 'No IPv4 default route exists.' }
$primary = $defaults[0]
$interfaces = @()
foreach ($index in @($defaults.InterfaceIndex | Sort-Object -Unique)) {
  $ip = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $index
  $adapter = Get-NetAdapter -InterfaceIndex $index
  $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $index).ServerAddresses
  $registry = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $adapter.InterfaceGuid) -ErrorAction SilentlyContinue
  $interfaces += [pscustomobject]@{
    Index = [int]$index
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
$conflicting = @()
foreach ($prefix in @($i.TUNRoutePrefixes)) {
  if (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue) { $conflicting += [string]$prefix }
}
$nodePrefix = ([string]$i.NodeAddress) + '/32'
$nodePresent = [bool](Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $nodePrefix -ErrorAction SilentlyContinue)
[pscustomobject]@{
  Version = 1
  Interfaces = @($interfaces)
  DefaultInterfaceIndex = [int]$primary.InterfaceIndex
  DefaultGateway = [string]$primary.NextHop
  NodeRoutePresent = $nodePresent
  OwnedFirewallRulesPresent = @($collisions)
  ConflictingTUNRoutes = @($conflicting)
} | ConvertTo-Json -Compress -Depth 8`

const blockNetworkPowerShell = `$ErrorActionPreference = 'Stop'
$i = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
$aliases = @($i.Interfaces | ForEach-Object { [string]$_.Alias })
$remote = @($i.BlockedRemoteAddresses)
if (-not (Get-NetFirewallRule -Name $i.FirewallRuleNames[0] -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $i.FirewallRuleNames[0] -DisplayName $i.FirewallRuleNames[0] -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $remote -InterfaceAlias $aliases -Profile Any | Out-Null }
if (-not (Get-NetFirewallRule -Name $i.FirewallRuleNames[1] -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $i.FirewallRuleNames[1] -DisplayName $i.FirewallRuleNames[1] -Direction Outbound -Action Block -Protocol UDP -RemotePort 443 -RemoteAddress $remote -InterfaceAlias $aliases -Profile Any | Out-Null }
if (-not (Get-NetFirewallRule -Name $i.FirewallRuleNames[2] -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $i.FirewallRuleNames[2] -DisplayName $i.FirewallRuleNames[2] -Direction Outbound -Action Block -Protocol UDP -RemoteAddress $remote -InterfaceAlias $aliases -Profile Any | Out-Null }`

const activateNetworkPowerShell = `$ErrorActionPreference = 'Stop'
$i = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
$tun = Get-NetAdapter -InterfaceAlias $i.TUNInterface -ErrorAction Stop
Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $tun.InterfaceIndex -AutomaticMetric Disabled -InterfaceMetric 1
Set-DnsClientServerAddress -InterfaceIndex $tun.InterfaceIndex -ServerAddresses @([string]$i.TUNDNS)
foreach ($physical in @($i.Interfaces)) {
  Set-DnsClientServerAddress -InterfaceIndex $physical.Index -ServerAddresses @([string]$i.TUNDNS)
}
foreach ($prefix in @($i.TUNRoutePrefixes)) {
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -eq [int]$i.RouteMetric } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
  New-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $tun.InterfaceIndex -NextHop '0.0.0.0' -RouteMetric $i.RouteMetric -PolicyStore ActiveStore | Out-Null
}
if (-not [bool]$i.NodeRoutePresent) {
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix (([string]$i.NodeAddress) + '/32') -InterfaceIndex $i.DefaultInterfaceIndex -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -eq [int]$i.RouteMetric -and $_.NextHop -eq [string]$i.DefaultGateway } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
  New-NetRoute -AddressFamily IPv4 -DestinationPrefix (([string]$i.NodeAddress) + '/32') -InterfaceIndex $i.DefaultInterfaceIndex -NextHop $i.DefaultGateway -RouteMetric $i.RouteMetric -PolicyStore ActiveStore | Out-Null
}`

const restoreNetworkPowerShell = `$ErrorActionPreference = 'Stop'
$i = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
foreach ($physical in @($i.Interfaces)) {
  if ([bool]$physical.DNSAutomatic) {
    Set-DnsClientServerAddress -InterfaceIndex $physical.Index -ResetServerAddresses
  } else {
    Set-DnsClientServerAddress -InterfaceIndex $physical.Index -ServerAddresses @($physical.DNSServers)
  }
  Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $physical.Index -AutomaticMetric $(if ([bool]$physical.AutomaticMetric) { 'Enabled' } else { 'Disabled' }) -InterfaceMetric $physical.InterfaceMetric
}
foreach ($prefix in @($i.TUNRoutePrefixes)) {
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -eq [int]$i.RouteMetric } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
if (-not [bool]$i.NodeRoutePresent) {
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix (([string]$i.NodeAddress) + '/32') -InterfaceIndex $i.DefaultInterfaceIndex -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -eq [int]$i.RouteMetric -and $_.NextHop -eq [string]$i.DefaultGateway } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
foreach ($name in @($i.FirewallRuleNames[2], $i.FirewallRuleNames[1], $i.FirewallRuleNames[0])) {
  Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
}`
