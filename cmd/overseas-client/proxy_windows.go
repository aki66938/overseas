//go:build windows

package main

import (
	"sync"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows"
)

// proxyGuard takes over the per-user WinINET proxy while connected: leftover
// proxies from Clash-family tools (ikuuu/Sakura/...) point browsers at dead
// local ports and break every site even though the tun works. Chrome and
// Edge honour these settings; on disconnect the previous values return.
type proxyGuard struct {
	mu             sync.Mutex
	taken          bool
	hadProxyEnable bool
	hadProxyServer bool
	proxyServer    string
	hadAutoConfig  bool
	autoConfigURL  string
}

const internetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininet                    = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption      = wininet.NewProc("InternetSetOptionW")
	internetOptionSettingsChg = 39
	internetOptionRefresh     = 37
)

func notifyProxyChange() {
	procInternetSetOption.Call(0, uintptr(internetOptionSettingsChg), 0, 0)
	procInternetSetOption.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

// Take disables the per-user system proxy, remembering the prior values.
// It returns whether a proxy was actually configured.
func (g *proxyGuard) Take() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.taken {
		return false
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	enabled, _, err := key.GetIntegerValue("ProxyEnable")
	active := err == nil && enabled != 0
	server, _, srvErr := key.GetStringValue("ProxyServer")
	auto, _, autoErr := key.GetStringValue("AutoConfigURL")
	if !active && srvErr != nil && autoErr != nil {
		return false
	}
	g.taken = true
	g.hadProxyEnable = active
	g.proxyServer = server
	g.hadProxyServer = srvErr == nil
	g.autoConfigURL = auto
	g.hadAutoConfig = autoErr == nil
	if active {
		_ = key.SetDWordValue("ProxyEnable", 0)
	}
	if srvErr == nil {
		_ = key.DeleteValue("ProxyServer")
	}
	if autoErr == nil {
		_ = key.DeleteValue("AutoConfigURL")
	}
	notifyProxyChange()
	return true
}

// Restore puts back the exact pre-takeover configuration.
func (g *proxyGuard) Restore() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.taken {
		return
	}
	g.taken = false
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	if g.hadProxyEnable {
		_ = key.SetDWordValue("ProxyEnable", 1)
	} else {
		_ = key.SetDWordValue("ProxyEnable", 0)
	}
	if g.hadProxyServer {
		_ = key.SetStringValue("ProxyServer", g.proxyServer)
	}
	if g.hadAutoConfig {
		_ = key.SetStringValue("AutoConfigURL", g.autoConfigURL)
	}
	notifyProxyChange()
}
