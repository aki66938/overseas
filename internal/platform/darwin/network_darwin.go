//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const journalName = "network-session.json"

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type systemCommands struct{}

func (systemCommands) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, path, args...)
	c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "LANG=C"}
	out, e := c.Output()
	if e != nil {
		return nil, fmt.Errorf("%s failed: %w", filepath.Base(path), e)
	}
	if len(out) > 1<<20 {
		return nil, errors.New("command output exceeds limit")
	}
	return out, nil
}

type darwinSystem struct{ commands commandRunner }

func (d darwinSystem) BootSession(ctx context.Context) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	value, e := unix.Sysctl("kern.bootsessionuuid")
	if e != nil {
		return "", e
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("boot session unavailable")
	}
	return value, nil
}

func NewNetworkManager(stateDirectory string) *NetworkManager {
	return newNetworkManager(darwinSystem{systemCommands{}}, fileJournal{stateDirectory})
}
func (d darwinSystem) Discover(ctx context.Context) (baseline, error) {
	var b baseline
	out, e := d.commands.Run(ctx, "/sbin/route", "-n", "get", "default")
	if e != nil {
		return b, e
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			if _, exists := fields[k]; exists {
				return b, errors.New("duplicate default route field")
			}
			fields[k] = strings.TrimSpace(v)
		}
	}
	b.Interface = fields["interface"]
	b.Gateway = fields["gateway"]
	a, e := netip.ParseAddr(b.Gateway)
	if e != nil || !a.Is4() || !strings.HasPrefix(b.Interface, "en") {
		return b, errors.New("unsupported physical default route")
	}
	iface, e := net.InterfaceByName(b.Interface)
	if e != nil {
		return b, e
	}
	if iface.Flags&net.FlagUp == 0 {
		return b, errors.New("physical interface down")
	}
	b.Index = iface.Index
	// Reject globally routable IPv6 on any active interface, including a VPN.
	// Link-local Apple utun interfaces are normal and need no mutation.
	ifaces, e := net.Interfaces()
	if e != nil {
		return b, e
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, e := i.Addrs()
		if e != nil {
			return b, e
		}
		for _, v := range addrs {
			p, e := netip.ParsePrefix(v.String())
			if e != nil {
				return b, e
			}
			ip := p.Addr()
			if ip.Is6() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
				return b, errors.New("active IPv6 unsupported by IPv4 PoC")
			}
		}
	}
	out, e = d.commands.Run(ctx, "/usr/sbin/networksetup", "-listnetworkserviceorder")
	if e != nil {
		return b, e
	}
	b.Service, e = parseService(string(out), b.Interface)
	if e != nil {
		return b, e
	}
	b.DNS, e = d.DNS(ctx, b.Service)
	return b, e
}
func parseService(text, device string) (string, error) {
	var current string
	var found []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(Hardware Port:") {
			_, tail, ok := strings.Cut(line, ", Device: ")
			if !ok || !strings.HasSuffix(tail, ")") {
				return "", errors.New("invalid service hardware row")
			}
			if strings.TrimSuffix(tail, ")") == device && current != "" {
				found = append(found, current)
			}
			current = ""
			continue
		}
		if strings.HasPrefix(line, "(") {
			n, name, ok := strings.Cut(line, ") ")
			if !ok {
				return "", errors.New("invalid service order row")
			}
			number := strings.TrimPrefix(n, "(")
			if number == "*" {
				current = ""
				continue
			}
			if _, e := strconv.Atoi(number); e != nil {
				return "", errors.New("invalid service order")
			}
			current = name
		}
	}
	if len(found) != 1 || strings.TrimSpace(found[0]) == "" {
		return "", errors.New("no unique enabled service for physical interface")
	}
	return found[0], nil
}
func parseDNS(text, service string) ([]string, error) {
	text = strings.TrimSpace(text)
	if text == "There aren't any DNS Servers set on "+service+"." {
		return nil, nil
	}
	var result []string
	for _, line := range strings.Split(text, "\n") {
		a, e := netip.ParseAddr(strings.TrimSpace(line))
		if e != nil {
			return nil, errors.New("ambiguous networksetup DNS output")
		}
		result = append(result, a.String())
	}
	return result, nil
}
func (d darwinSystem) DNS(ctx context.Context, service string) ([]string, error) {
	out, e := d.commands.Run(ctx, "/usr/sbin/networksetup", "-getdnsservers", service)
	if e != nil {
		return nil, e
	}
	return parseDNS(string(out), service)
}
func (d darwinSystem) SetDNS(ctx context.Context, service string, dns []string) error {
	args := []string{"-setdnsservers", service}
	if len(dns) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, dns...)
	}
	_, e := d.commands.Run(ctx, "/usr/sbin/networksetup", args...)
	if e != nil {
		return e
	}
	actual, e := d.DNS(ctx, service)
	if e == nil && !sameDNS(actual, dns) {
		e = errors.New("DNS mutation did not verify")
	}
	return e
}
func (d darwinSystem) TUN(ctx context.Context) (tunIdentity, error) {
	if e := ctx.Err(); e != nil {
		return tunIdentity{}, e
	}
	ifaces, e := net.Interfaces()
	if e != nil {
		return tunIdentity{}, e
	}
	for _, i := range ifaces {
		if i.Name != TUNName {
			continue
		}
		t := tunIdentity{Name: i.Name, Index: i.Index}
		a, e := i.Addrs()
		if e != nil {
			return t, e
		}
		for _, v := range a {
			p, e := netip.ParsePrefix(v.String())
			if e != nil {
				return t, e
			}
			if p.Addr().Is4() {
				if t.Address != "" {
					return t, errors.New("ambiguous TUN IPv4 identity")
				}
				t.Address = p.String()
			}
		}
		return t, nil
	}
	return tunIdentity{}, nil
}
func (d darwinSystem) Routes(ctx context.Context) ([]ownedRoute, error) {
	ifaces, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	indexes := map[string]int{}
	for _, i := range ifaces {
		indexes[i.Name] = i.Index
	}
	out, e := d.commands.Run(ctx, "/usr/sbin/netstat", "-rn", "-f", "inet")
	if e != nil {
		return nil, e
	}
	return parseRoutes(string(out), indexes)
}
func parseRoutes(text string, indexes map[string]int) ([]ownedRoute, error) {
	var result []ownedRoute
	header := false
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "Destination" {
			if len(f) < 4 || f[1] != "Gateway" || f[2] != "Flags" || f[3] != "Netif" {
				return nil, errors.New("unexpected route columns")
			}
			header = true
			continue
		}
		if !header {
			continue
		}
		if len(f) < 4 || len(f) > 5 {
			return nil, errors.New("ambiguous route row")
		}
		dest, e := routePrefix(f[0], f[2])
		if e != nil {
			return nil, e
		}
		index, ok := indexes[f[3]]
		if !ok || index <= 0 {
			return nil, errors.New("route interface identity missing")
		}
		gateway := f[1]
		// Darwin renders an interface-only utun route with either its name or
		// link#<index>. Normalize only the owned interface and non-gateway route;
		// never disguise a different interface, index, or IP next hop.
		if f[3] == TUNName && gateway == TUNName && !strings.Contains(f[2], "G") {
			gateway = fmt.Sprintf("link#%d", index)
		}
		result = append(result, ownedRoute{dest, gateway, f[3], index})
	}
	if !header {
		return nil, errors.New("route table missing header")
	}
	return result, nil
}
func routePrefix(text, flags string) (string, error) {
	if text == "default" {
		return "0.0.0.0/0", nil
	}
	ip, bits, has := strings.Cut(text, "/")
	parts := strings.Split(ip, ".")
	if len(parts) > 4 {
		return "", errors.New("invalid route destination")
	}
	if !has {
		bits = "32"
		if !strings.Contains(flags, "H") {
			// Darwin netstat abbreviates byte-aligned network routes: 127,
			// 169.254 and 172.20 represent /8, /16 and /16. RTF_HOST (H)
			// identifies host routes; explicit CIDR masks always take precedence.
			bits = strconv.Itoa(len(parts) * 8)
		}
	}
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	p, e := netip.ParsePrefix(strings.Join(parts, ".") + "/" + bits)
	if e != nil {
		return "", e
	}
	return p.Masked().String(), nil
}
func (d darwinSystem) AddRoute(ctx context.Context, r ownedRoute) error {
	args := []string{"-n", "add", "-net", r.Destination}
	if r.Interface == TUNName {
		args = append(args, "-interface", TUNName)
	} else {
		args = append(args, r.Gateway)
	}
	if _, e := d.commands.Run(ctx, "/sbin/route", args...); e != nil {
		return e
	}
	routes, e := d.Routes(ctx)
	if e != nil {
		return e
	}
	for _, v := range routes {
		if v == r {
			return nil
		}
	}
	return errors.New("added route identity did not verify")
}
func (d darwinSystem) DeleteRoute(ctx context.Context, r ownedRoute) error {
	args := []string{"-n", "delete", "-net", r.Destination}
	if r.Interface == TUNName {
		args = append(args, "-interface", TUNName)
	} else {
		args = append(args, r.Gateway)
	}
	_, commandErr := d.commands.Run(ctx, "/sbin/route", args...)
	routes, e := d.Routes(ctx)
	if e != nil {
		return errors.Join(commandErr, e)
	}
	for _, current := range routes {
		if current.Destination == r.Destination {
			return errors.Join(commandErr, errors.New("route remains after scoped removal; needs action"))
		}
	}
	return nil
}

type fileJournal struct{ directory string }

func (j fileJournal) openDirectory() (*os.File, error) {
	if !filepath.IsAbs(j.directory) {
		return nil, errors.New("journal directory must be absolute")
	}
	resolved, e := filepath.EvalSymlinks(j.directory)
	if e != nil {
		return nil, e
	}
	if resolved != filepath.Clean(j.directory) {
		return nil, errors.New("journal directory must not traverse symlinks")
	}
	fd, e := unix.Open(j.directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), j.directory)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil || st.Uid != 0 || st.Mode&0077 != 0 {
		f.Close()
		return nil, errors.New("journal directory must be root-owned and private")
	}
	return f, nil
}
func (j fileJournal) Load() (*networkSnapshot, error) {
	dir, e := j.openDirectory()
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	fd, e := unix.Openat(int(dir.Fd()), journalName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), journalName)
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil || st.Uid != 0 || st.Mode&0077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size > 65536 {
		return nil, errors.New("unsafe network journal")
	}
	data, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return nil, e
	}
	if len(data) > 65536 {
		return nil, errors.New("journal too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s networkSnapshot
	if e = dec.Decode(&s); e != nil {
		return nil, e
	}
	if e = dec.Decode(new(any)); e != io.EOF {
		return nil, errors.New("journal has trailing data")
	}
	if e = validateSnapshot(&s); e != nil {
		return nil, e
	}
	return &s, nil
}
func validateSnapshot(s *networkSnapshot) error {
	b := s.Baseline
	if s.Version != 1 || s.BootSession == "" || len(s.BootSession) > 128 || !strings.HasPrefix(b.Interface, "en") || b.Index <= 0 || b.Service == "" || strings.ContainsAny(b.Service, "\x00\r\n") {
		return errors.New("invalid network journal baseline")
	}
	a, e := netip.ParseAddr(b.Gateway)
	if e != nil || !a.Is4() {
		return errors.New("invalid journal gateway")
	}
	for _, v := range b.DNS {
		if _, e = netip.ParseAddr(v); e != nil {
			return e
		}
	}
	if s.TUN != (tunIdentity{}) && (s.TUN.Name != TUNName || s.TUN.Index <= 0 || s.TUN.Address != TUNAddress) {
		return errors.New("invalid journal TUN")
	}
	if len(s.Routes) > 3 {
		return errors.New("invalid journal routes")
	}
	seen := map[string]bool{}
	for _, r := range s.Routes {
		if !plannedDestination(r.Destination) || seen[r.Destination] {
			return errors.New("invalid journal route destination")
		}
		seen[r.Destination] = true
		if r.Destination == "172.20.0.0/16" {
			if r.Gateway != b.Gateway || r.Interface != b.Interface || r.Index != b.Index {
				return errors.New("invalid direct route")
			}
		} else if r.Interface != TUNName || r.Index != s.TUN.Index || r.Index <= 0 || r.Gateway != fmt.Sprintf("link#%d", r.Index) {
			return errors.New("invalid TUN route")
		}
	}
	if s.DNSIntended && s.TUN.Index <= 0 {
		return errors.New("DNS intent without TUN identity")
	}
	return nil
}
func (j fileJournal) Save(s *networkSnapshot) error {
	if e := validateSnapshot(s); e != nil {
		return e
	}
	data, e := json.Marshal(s)
	if e != nil {
		return e
	}
	dir, e := j.openDirectory()
	if e != nil {
		return e
	}
	defer dir.Close()
	name := fmt.Sprintf(".network-%d-%d", os.Getpid(), time.Now().UnixNano())
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), name)
	defer unix.Unlinkat(int(dir.Fd()), name, 0)
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = unix.Renameat(int(dir.Fd()), name, int(dir.Fd()), journalName); e != nil {
		return e
	}
	return dir.Sync()
}
func (j fileJournal) Remove() error {
	dir, e := j.openDirectory()
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = unix.Unlinkat(int(dir.Fd()), journalName, 0); e != nil && !errors.Is(e, unix.ENOENT) {
		return e
	}
	return dir.Sync()
}
