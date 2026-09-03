//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const maxAdapterAddressBufferAttempts = 3

type windowsIPHelperAPI struct{}

func newWindowsNativeNetworkReader() nativeNetworkReader {
	return ipHelperNetworkReader{api: windowsIPHelperAPI{}}
}

func (windowsIPHelperAPI) Adapters(ctx context.Context) ([]ipHelperAdapter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	size := uint32(15 * 1024)
	flags := uint32(windows.GAA_FLAG_INCLUDE_GATEWAYS)
	for attempt := 0; attempt < maxAdapterAddressBufferAttempts; attempt++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(uint32(windows.AF_UNSPEC), flags, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result := make([]ipHelperAdapter, 0)
		for current := first; current != nil; current = current.Next {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			name := strings.TrimSpace(windows.BytePtrToString(current.AdapterName))
			alias := strings.TrimSpace(windows.UTF16PtrToString(current.FriendlyName))
			if current.IfIndex == 0 || name == "" || alias == "" {
				continue
			}
			dns := make([]string, 0)
			for server := current.FirstDnsServerAddress; server != nil; server = server.Next {
				address, addressErr := socketAddressIP(server.Address)
				if addressErr != nil {
					return nil, fmt.Errorf("adapter %s DNS address: %w", name, addressErr)
				}
				if address.Is4() {
					dns = append(dns, address.String())
				}
			}
			addresses := make([]string, 0)
			for unicast := current.FirstUnicastAddress; unicast != nil; unicast = unicast.Next {
				address, addressErr := socketAddressIP(unicast.Address)
				if addressErr != nil {
					return nil, fmt.Errorf("adapter %s unicast address: %w", name, addressErr)
				}
				if address.Is4() {
					addresses = append(addresses, fmt.Sprintf("%s/%d", address.String(), unicast.OnLinkPrefixLength))
				}
			}
			result = append(result, ipHelperAdapter{
				InterfaceIndex: int(current.IfIndex), LUID: current.Luid, InterfaceGuid: canonicalAdapterGUID(name),
				InterfaceAlias: alias, Status: adapterOperationalStatus(current.OperStatus),
				DNSServers: dns, DNSAutomatic: adapterDNSAutomatic(name), IPAddresses: addresses,
				Description: strings.TrimSpace(windows.UTF16PtrToString(current.Description)),
			})
		}
		runtime.KeepAlive(buffer)
		if len(result) == 0 {
			return nil, errors.New("IP Helper returned no IPv4 adapters")
		}
		return result, nil
	}
	return nil, errors.New("GetAdaptersAddresses buffer did not stabilize")
}

func (windowsIPHelperAPI) IPv4Interfaces(ctx context.Context, adapters []ipHelperAdapter) ([]ipHelperInterface, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]ipHelperInterface, 0, len(adapters))
	for _, adapter := range adapters {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: adapter.LUID, InterfaceIndex: uint32(adapter.InterfaceIndex)}
		if err := windows.GetIpInterfaceEntry(&row); errors.Is(err, windows.ERROR_NOT_FOUND) {
			continue
		} else if err != nil {
			return nil, err
		}
		result = append(result, ipHelperInterface{
			InterfaceIndex: int(row.InterfaceIndex), LUID: row.InterfaceLuid, AutomaticMetric: row.UseAutomaticMetric != 0,
			Metric: int(row.Metric), DisableDefaultRoute: row.DisableDefaultRoutes != 0,
		})
	}
	if len(result) == 0 {
		return nil, errors.New("IP Helper returned no IPv4 interfaces")
	}
	return result, nil
}

// TUNReady reports the fixed TUN identity when the adapter exists with the
// expected address. found=false means not present yet; a present adapter
// failing the baseline check still returns found=true so the caller can
// validate and report an identity mismatch.
func (r ipHelperNetworkReader) TUNReady(ctx context.Context, alias, address string, baseline []string) (WindowsTUNIdentity, bool, error) {
	adapters, err := r.api.Adapters(ctx)
	if err != nil {
		return WindowsTUNIdentity{}, false, err
	}
	target, _, _ := strings.Cut(address, "/")
	for _, adapter := range adapters {
		if !strings.EqualFold(adapter.InterfaceAlias, alias) {
			continue
		}
		matching := make([]string, 0)
		for _, value := range adapter.IPAddresses {
			if candidate, _, _ := strings.Cut(value, "/"); candidate == target {
				matching = append(matching, value)
			}
		}
		if len(matching) == 0 {
			continue
		}
		identity := WindowsTUNIdentity{
			InterfaceIndex: adapter.InterfaceIndex, InterfaceGuid: adapter.InterfaceGuid,
			InterfaceAlias: adapter.InterfaceAlias, Addresses: matching,
		}
		return identity, true, nil
	}
	return WindowsTUNIdentity{}, false, nil
}

func (windowsIPHelperAPI) IPv4Routes(ctx context.Context) ([]ipHelperRoute, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, errors.New("GetIpForwardTable2 returned nil")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	rows := table.Rows()
	result := make([]ipHelperRoute, 0, len(rows))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.InterfaceIndex == 0 || row.DestinationPrefix.Prefix.Family != windows.AF_INET || row.NextHop.Family != windows.AF_INET {
			continue
		}
		prefixAddress, err := rawSockaddrInet4IP(row.DestinationPrefix.Prefix)
		if err != nil || row.DestinationPrefix.PrefixLength > 32 {
			return nil, errors.New("IP Helper returned an invalid IPv4 prefix")
		}
		nextHop, err := rawSockaddrInet4IP(row.NextHop)
		if err != nil {
			return nil, errors.New("IP Helper returned an invalid IPv4 next hop")
		}
		prefix := netip.PrefixFrom(prefixAddress, int(row.DestinationPrefix.PrefixLength)).Masked()
		result = append(result, ipHelperRoute{
			DestinationPrefix: prefix.String(), InterfaceIndex: int(row.InterfaceIndex), LUID: row.InterfaceLuid,
			NextHop: nextHop.String(), Metric: int(row.Metric), Protocol: int(row.Protocol),
		})
	}
	if len(result) == 0 {
		return nil, errors.New("IP Helper returned no IPv4 routes")
	}
	return result, nil
}

func socketAddressIP(address windows.SocketAddress) (netip.Addr, error) {
	if address.Sockaddr == nil {
		return netip.Addr{}, errors.New("socket address is nil")
	}
	value := address.IP()
	if value == nil {
		return netip.Addr{}, errors.New("socket address family or length is invalid")
	}
	result, ok := netip.AddrFromSlice(value)
	if !ok {
		return netip.Addr{}, errors.New("socket address bytes are invalid")
	}
	return result.Unmap(), nil
}

func rawSockaddrInet4IP(address windows.RawSockaddrInet) (netip.Addr, error) {
	if address.Family != windows.AF_INET {
		return netip.Addr{}, errors.New("raw socket address is not IPv4")
	}
	raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(&address))
	return netip.AddrFrom4(raw.Addr), nil
}

func canonicalAdapterGUID(value string) string {
	trimmed := strings.Trim(strings.TrimSpace(value), "{}")
	if guid, err := windows.GUIDFromString("{" + trimmed + "}"); err == nil {
		return strings.ToUpper(guid.String())
	}
	return strings.ToUpper(value)
}

func adapterOperationalStatus(status uint32) string {
	switch status {
	case windows.IfOperStatusUp:
		return "Up"
	case windows.IfOperStatusDown:
		return "Down"
	case windows.IfOperStatusDormant:
		return "Dormant"
	case windows.IfOperStatusNotPresent:
		return "NotPresent"
	case windows.IfOperStatusLowerLayerDown:
		return "LowerLayerDown"
	default:
		return "Unknown"
	}
}

func adapterDNSAutomatic(adapterName string) bool {
	path := `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + canonicalAdapterGUID(adapterName)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer key.Close()
	nameServer, _, err := key.GetStringValue("NameServer")
	return err != nil || strings.TrimSpace(nameServer) == ""
}
