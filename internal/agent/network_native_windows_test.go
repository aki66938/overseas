//go:build windows

package agent

import (
	"context"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

type countingIPHelperAPI struct {
	adaptersCalls   int
	interfacesCalls int
	routesCalls     int
	cancel          context.CancelFunc
	interfaceInput  []ipHelperAdapter
}

func (a *countingIPHelperAPI) Adapters(context.Context) ([]ipHelperAdapter, error) {
	a.adaptersCalls++
	if a.cancel != nil {
		a.cancel()
	}
	return []ipHelperAdapter{{InterfaceIndex: 4, InterfaceGuid: "a", InterfaceAlias: "Ethernet", Status: "Up"}}, nil
}

func (a *countingIPHelperAPI) IPv4Interfaces(_ context.Context, adapters []ipHelperAdapter) ([]ipHelperInterface, error) {
	a.interfacesCalls++
	a.interfaceInput = append([]ipHelperAdapter(nil), adapters...)
	return []ipHelperInterface{{InterfaceIndex: 4, Metric: 10}}, nil
}

func (a *countingIPHelperAPI) IPv4Routes(context.Context) ([]ipHelperRoute, error) {
	a.routesCalls++
	return []ipHelperRoute{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, NextHop: "172.20.10.1"}}, nil
}

func TestWindowsIPHelperReaderStopsBetweenNativeCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	api := &countingIPHelperAPI{cancel: cancel}
	_, err := (ipHelperNetworkReader{api: api}).Baseline(ctx, []string{"172.20.9.15"})
	if err == nil || api.adaptersCalls != 1 || api.interfacesCalls != 0 || api.routesCalls != 0 {
		t.Fatalf("err=%v calls=%d/%d/%d", err, api.adaptersCalls, api.interfacesCalls, api.routesCalls)
	}
}

func TestWindowsIPHelperReaderBindsInterfaceReadsToAdapterLUIDs(t *testing.T) {
	api := &countingIPHelperAPI{}
	_, err := (ipHelperNetworkReader{api: api}).Baseline(context.Background(), []string{"172.20.9.15"})
	if err != nil {
		t.Fatal(err)
	}
	if len(api.interfaceInput) != 1 || api.interfaceInput[0].InterfaceIndex != 4 {
		t.Fatalf("interface input = %+v", api.interfaceInput)
	}
}

func TestWindowsIPHelperRejectsMalformedSocketAddress(t *testing.T) {
	if _, err := socketAddressIP(windows.SocketAddress{}); err == nil {
		t.Fatal("nil socket address was accepted")
	}
	var raw syscall.RawSockaddrAny
	raw.Addr.Family = windows.AF_INET
	if _, err := socketAddressIP(windows.SocketAddress{Sockaddr: &raw, SockaddrLength: 2}); err == nil {
		t.Fatal("short IPv4 socket address was accepted")
	}
}

func TestWindowsIPHelperReadsLiveBaselineWithoutPowerShell(t *testing.T) {
	reader := newWindowsNativeNetworkReader()
	baseline, err := reader.Baseline(context.Background(), []string{"172.20.9.15"})
	if err != nil {
		api := windowsIPHelperAPI{}
		adapters, _ := api.Adapters(context.Background())
		interfaces, _ := api.IPv4Interfaces(context.Background(), adapters)
		routes, _ := api.IPv4Routes(context.Background())
		t.Logf("adapters=%+v", adapters)
		t.Logf("interfaces=%+v", interfaces)
		t.Logf("routes=%+v", routes)
		t.Fatal(err)
	}
	if len(baseline.Adapters) == 0 || len(baseline.Interfaces) == 0 || len(baseline.Routes) == 0 || len(baseline.NodeRoutes) != 1 {
		t.Fatalf("incomplete live baseline: adapters=%d interfaces=%d routes=%d nodes=%d", len(baseline.Adapters), len(baseline.Interfaces), len(baseline.Routes), len(baseline.NodeRoutes))
	}
	fingerprint, err := fingerprintNativeNetwork(baseline)
	if err != nil || !lowercaseSHA256Pattern.MatchString(fingerprint) {
		t.Fatalf("fingerprint=%q err=%v", fingerprint, err)
	}
}

func TestWindowsNetworkManagerOwnsNativeReader(t *testing.T) {
	api := &countingIPHelperAPI{}
	reader := ipHelperNetworkReader{api: api}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{}, withWindowsNativeNetworkReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	if manager.native == nil {
		t.Fatal("native network reader is nil")
	}
}
