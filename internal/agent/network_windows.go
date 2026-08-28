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
	networkOperationReady    = "ready"
	networkOperationActivate = "activate"
	networkOperationRestore  = "restore"

	windowsTUNInterface     = "RegenBioOverseasAccess"
	windowsTUNAddress       = "172.19.0.1/30"
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
	RouteMetric               int                        `json:"RouteMetric"`
}

type windowsNetworkInput struct {
	Interfaces             []WindowsInterfaceSnapshot `json:"Interfaces,omitempty"`
	FirewallRuleNames      []string                   `json:"FirewallRuleNames,omitempty"`
	BlockedRemoteAddresses []string                   `json:"BlockedRemoteAddresses,omitempty"`
	FirewallInterfaceTypes []string                   `json:"FirewallInterfaceTypes,omitempty"`
	TUNInterface           string                     `json:"TUNInterface,omitempty"`
	TUNAddress             string                     `json:"TUNAddress,omitempty"`
	TUNDNS                 string                     `json:"TUNDNS,omitempty"`
	TUNRoutePrefixes       []string                   `json:"TUNRoutePrefixes,omitempty"`
	RouteMetric            int                        `json:"RouteMetric,omitempty"`
	NodeAddresses          []string                   `json:"NodeAddresses,omitempty"`
	BaselineAdapterGuids   []string                   `json:"BaselineAdapterGuids,omitempty"`
	OwnedTUN               *WindowsTUNIdentity        `json:"OwnedTUN,omitempty"`
	OwnedRoutes            []WindowsOwnedRoute        `json:"OwnedRoutes,omitempty"`
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
	nodeAddresses   []string
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
	nodeAddresses := make([]string, 0, len(nodes))
	excluded4 := standardNonPublicIPv4Prefixes()
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
	return &WindowsNetworkManager{
		policy:          clonePolicy(policy),
		statePath:       statePath,
		runner:          runner,
		store:           store,
		nodeAddresses:   nodeAddresses,
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
		TUNInterface:      windowsTUNInterface,
		TUNAddress:        windowsTUNAddress,
		NodeAddresses:     append([]string(nil), m.nodeAddresses...),
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
	snapshot.RouteMetric = windowsOwnedRouteMetric
	if err := validateWindowsSnapshot(snapshot); err != nil {
		return nil, err
	}
	if err := validateCapturedNodeRoutes(snapshot.NodeRoutes, m.nodeAddresses); err != nil {
		return nil, err
	}
	if len(snapshot.OwnedFirewallRulesPresent) != 0 {
		return nil, errors.New("owned firewall rule names already exist")
	}
	if len(snapshot.ConflictingTUNRoutes) != 0 {
		return nil, errors.New("managed TUN route prefixes already exist")
	}
	if snapshot.TUNAliasPresent || snapshot.TUNAddressPresent {
		return nil, errors.New("fixed TUN alias or address already exists before core launch")
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
		// Windows Firewall applies these interface types dynamically, including
		// adapters attached after Connect. Wintun is virtual/prop-virtual and is
		// identity-checked separately, so it is intentionally outside this scope.
		FirewallInterfaceTypes: []string{"Wired", "Wireless"},
	}
	_, err := m.run(ctx, networkOperationBlock, input)
	return err
}

func (m *WindowsNetworkManager) WaitTUNReady(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return errors.New("network state was not captured")
	}
	input := windowsNetworkInput{
		TUNInterface:         windowsTUNInterface,
		TUNAddress:           windowsTUNAddress,
		BaselineAdapterGuids: append([]string(nil), m.current.BaselineAdapterGuids...),
	}
	output, err := m.run(ctx, networkOperationReady, input)
	if err != nil {
		return err
	}
	var identity WindowsTUNIdentity
	if err := json.Unmarshal(output, &identity); err != nil {
		return fmt.Errorf("decode TUN identity: %w", err)
	}
	if err := validateTUNIdentity(identity, m.current.BaselineAdapterGuids); err != nil {
		return err
	}
	ownedRoutes := []WindowsOwnedRoute{
		{DestinationPrefix: "0.0.0.0/1", InterfaceIndex: identity.InterfaceIndex, NextHop: "0.0.0.0", RouteMetric: windowsOwnedRouteMetric},
		{DestinationPrefix: "128.0.0.0/1", InterfaceIndex: identity.InterfaceIndex, NextHop: "0.0.0.0", RouteMetric: windowsOwnedRouteMetric},
	}
	for _, route := range m.current.NodeRoutes {
		if route.BypassRequired {
			ownedRoutes = append(ownedRoutes, WindowsOwnedRoute{
				DestinationPrefix: route.NodeAddress + "/32",
				InterfaceIndex:    route.InterfaceIndex,
				NextHop:           route.NextHop,
				RouteMetric:       route.RouteMetric,
			})
		}
	}
	m.current.OwnedTUN = &identity
	m.current.OwnedRoutes = ownedRoutes
	return m.store.Save(m.statePath, *m.current)
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
	if m.current != nil {
		snapshot = *m.current
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
	if err := validateCapturedNodeRoutes(snapshot.NodeRoutes, m.nodeAddresses); err != nil {
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
		Interfaces:        append([]WindowsInterfaceSnapshot(nil), snapshot.Interfaces...),
		FirewallRuleNames: []string{windowsTCPBlockRule, windowsQUICBlockRule, windowsUDPBlockRule},
		TUNInterface:      windowsTUNInterface,
		TUNAddress:        windowsTUNAddress,
		TUNDNS:            windowsTUNDNS,
		TUNRoutePrefixes:  []string{"0.0.0.0/1", "128.0.0.0/1"},
		RouteMetric:       snapshot.RouteMetric,
		OwnedTUN:          snapshot.OwnedTUN,
		OwnedRoutes:       append([]WindowsOwnedRoute(nil), snapshot.OwnedRoutes...),
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
	if identity.HardwareInterface || !identity.Virtual || !strings.HasPrefix(identity.InterfaceDescription, "Wintun Userspace Tunnel") {
		return errors.New("TUN adapter type or description is not owned")
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

func complementIPv6Prefixes(excluded []netip.Prefix) []string {
	remaining := []netip.Prefix{netip.MustParsePrefix("::/0")}
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

var networkPowerShellScripts = map[string]string{
	networkOperationCapture:  captureNetworkPowerShell,
	networkOperationBlock:    blockNetworkPowerShell,
	networkOperationReady:    readyNetworkPowerShell,
	networkOperationActivate: activateNetworkPowerShell,
	networkOperationRestore:  restoreNetworkPowerShell,
}

const captureNetworkPowerShell = `$ErrorActionPreference = 'Stop'
$i = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
$defaults = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric)
if ($defaults.Count -eq 0) { throw 'No IPv4 default route exists.' }
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
$allAdapters = @(Get-NetAdapter -IncludeHidden)
$baselineGuids = @($allAdapters | ForEach-Object { [string]$_.InterfaceGuid })
$tunAliasPresent = [bool]($allAdapters | Where-Object { $_.InterfaceAlias -eq [string]$i.TUNInterface })
$tunAddressIP = ([string]$i.TUNAddress).Split('/')[0]
$tunAddressPresent = [bool](Get-NetIPAddress -AddressFamily IPv4 -IPAddress $tunAddressIP -ErrorAction SilentlyContinue)
$nodeRoutes = @()
foreach ($node in @($i.NodeAddresses)) {
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
  ConflictingTUNRoutes = @($conflicting)
  BaselineAdapterGuids = @($baselineGuids)
  TUNAliasPresent = $tunAliasPresent
  TUNAddressPresent = $tunAddressPresent
  NodeRoutes = @($nodeRoutes)
} | ConvertTo-Json -Compress -Depth 8`

const blockNetworkPowerShell = `$ErrorActionPreference = 'Stop'
$i = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
$remote = @($i.BlockedRemoteAddresses)
$types = @($i.FirewallInterfaceTypes)
if (-not (Get-NetFirewallRule -Name $i.FirewallRuleNames[0] -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $i.FirewallRuleNames[0] -DisplayName $i.FirewallRuleNames[0] -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $remote -InterfaceType $types -Profile Any | Out-Null }
if (-not (Get-NetFirewallRule -Name $i.FirewallRuleNames[1] -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $i.FirewallRuleNames[1] -DisplayName $i.FirewallRuleNames[1] -Direction Outbound -Action Block -Protocol UDP -RemotePort 443 -RemoteAddress $remote -InterfaceType $types -Profile Any | Out-Null }
if (-not (Get-NetFirewallRule -Name $i.FirewallRuleNames[2] -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $i.FirewallRuleNames[2] -DisplayName $i.FirewallRuleNames[2] -Direction Outbound -Action Block -Protocol UDP -RemoteAddress $remote -InterfaceType $types -Profile Any | Out-Null }`

const readyNetworkPowerShell = `$ErrorActionPreference = 'Stop'
$i = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
$deadline = [DateTime]::UtcNow.AddSeconds(2)
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

const activateNetworkPowerShell = `$ErrorActionPreference = 'Stop'
$i = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
$tun = Get-NetAdapter -InterfaceIndex $i.OwnedTUN.InterfaceIndex -IncludeHidden -ErrorAction Stop
if ([string]$tun.InterfaceGuid -ne [string]$i.OwnedTUN.InterfaceGuid -or [string]$tun.InterfaceAlias -ne [string]$i.OwnedTUN.InterfaceAlias -or [string]$tun.InterfaceDescription -ne [string]$i.OwnedTUN.InterfaceDescription -or [bool]$tun.HardwareInterface -ne [bool]$i.OwnedTUN.HardwareInterface -or [bool]$tun.Virtual -ne [bool]$i.OwnedTUN.Virtual) { throw 'Owned TUN identity changed before activation.' }
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $tun.InterfaceIndex -ErrorAction Stop | ForEach-Object { ([string]$_.IPAddress) + '/' + ([string]$_.PrefixLength) })
if ($addresses.Count -ne 1 -or $addresses[0] -ne [string]$i.TUNAddress) { throw 'Owned TUN address changed before activation.' }
Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $i.OwnedTUN.InterfaceIndex -AutomaticMetric Disabled -InterfaceMetric 1
Set-DnsClientServerAddress -InterfaceIndex $i.OwnedTUN.InterfaceIndex -ServerAddresses @([string]$i.TUNDNS)
foreach ($physical in @($i.Interfaces)) {
  Set-DnsClientServerAddress -InterfaceIndex $physical.Index -ServerAddresses @([string]$i.TUNDNS)
}
foreach ($route in @($i.OwnedRoutes)) {
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -eq [int]$route.InterfaceIndex -and $_.NextHop -eq [string]$route.NextHop -and $_.RouteMetric -eq [int]$route.RouteMetric } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
  New-NetRoute -AddressFamily IPv4 -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop -RouteMetric $route.RouteMetric -PolicyStore ActiveStore | Out-Null
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
foreach ($route in @($i.OwnedRoutes)) {
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -eq [int]$route.InterfaceIndex -and $_.NextHop -eq [string]$route.NextHop -and $_.RouteMetric -eq [int]$route.RouteMetric } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
foreach ($name in @($i.FirewallRuleNames[2], $i.FirewallRuleNames[1], $i.FirewallRuleNames[0])) {
  Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
}`
