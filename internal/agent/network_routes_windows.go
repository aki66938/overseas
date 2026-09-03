//go:build windows

package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                  = windows.NewLazySystemDLL("iphlpapi.dll")
	procCreateIpForwardEntry2 = iphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2 = iphlpapi.NewProc("DeleteIpForwardEntry2")
	procSetIpInterfaceEntry   = iphlpapi.NewProc("SetIpInterfaceEntry")
)

const mibIPRouteProtocolNetMgmt = 3

// windowsRouteApplier applies and revokes the product-owned TUN routes and
// the TUN interface metric through the IP Helper API. One native call per
// route replaces 119 slow WMI round trips on the connect path.
type windowsRouteApplier struct{}

func forwardRow(interfaceIndex uint32, route WindowsOwnedRoute) (windows.MibIpForwardRow2, error) {
	prefix, err := netip.ParsePrefix(route.DestinationPrefix)
	if err != nil || !prefix.Addr().Is4() {
		return windows.MibIpForwardRow2{}, fmt.Errorf("route %s: %w", route.DestinationPrefix, err)
	}
	nextHop, err := netip.ParseAddr(route.NextHop)
	if err != nil || !nextHop.Is4() {
		return windows.MibIpForwardRow2{}, fmt.Errorf("route %s next hop: %w", route.DestinationPrefix, err)
	}
	row := windows.MibIpForwardRow2{
		InterfaceIndex: interfaceIndex,
		Protocol:       mibIPRouteProtocolNetMgmt,
		Metric:         uint32(route.RouteMetric),
	}
	prefixBytes := prefix.Addr().As4()
	row.DestinationPrefix = windows.IpAddressPrefix{
		Prefix:       sockaddrInet4(prefixBytes),
		PrefixLength: uint8(prefix.Bits()),
	}
	hop := nextHop.As4()
	row.NextHop = sockaddrInet4(hop)
	return row, nil
}

func sockaddrInet4(addr [4]byte) windows.RawSockaddrInet {
	raw := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: addr}
	return *(*windows.RawSockaddrInet)(unsafe.Pointer(&raw))
}

func (windowsRouteApplier) ApplyOwnedRoutes(snapshot WindowsNetworkSnapshot) error {
	if snapshot.OwnedTUN == nil {
		return errors.New("owned TUN identity is missing for route activation")
	}
	index := uint32(snapshot.OwnedTUN.InterfaceIndex)
	for _, route := range snapshot.OwnedRoutes {
		if route.AddressFamily != "IPv4" {
			continue
		}
		row, err := forwardRow(index, route)
		if err != nil {
			return err
		}
		_ = deleteIpForwardEntry(row)
		if err := createIpForwardEntry(row); err != nil {
			return fmt.Errorf("activate route %s: %w", route.DestinationPrefix, err)
		}
	}
	return setIPv4InterfaceMetric(index, 1, false)
}

func (windowsRouteApplier) RevokeOwnedRoutes(snapshot WindowsNetworkSnapshot) error {
	if snapshot.OwnedTUN == nil {
		return nil
	}
	index := uint32(snapshot.OwnedTUN.InterfaceIndex)
	for _, route := range snapshot.OwnedRoutes {
		if route.AddressFamily != "IPv4" {
			continue
		}
		row, err := forwardRow(index, route)
		if err != nil {
			continue
		}
		_ = deleteIpForwardEntry(row)
	}
	return nil
}

func createIpForwardEntry(row windows.MibIpForwardRow2) error {
	result, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if result != 0 {
		return fmt.Errorf("CreateIpForwardEntry2: winerror %d", result)
	}
	return nil
}

func deleteIpForwardEntry(row windows.MibIpForwardRow2) error {
	result, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if result != 0 {
		return fmt.Errorf("DeleteIpForwardEntry2: winerror %d", result)
	}
	return nil
}

func setIPv4InterfaceMetric(index uint32, metric uint32, automatic bool) error {
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: index}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return fmt.Errorf("read interface %d: %w", index, err)
	}
	row.SitePrefixLength = 0
	row.Metric = metric
	row.UseAutomaticMetric = boolToUint8(automatic)
	result, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if result != 0 {
		return fmt.Errorf("SetIpInterfaceEntry: winerror %d", result)
	}
	return nil
}

func boolToUint8(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}
