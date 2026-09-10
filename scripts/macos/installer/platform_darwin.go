//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"corp.example/overseas-access-gateway/internal/clientapi"
	"golang.org/x/sys/unix"
)

// These are fixed arguments to native programs, never shell source.
func command(program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 115*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, program, args...)
	c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root", "LANG=C"}
	out, e := c.CombinedOutput()
	if ctx.Err() != nil {
		return out, fmt.Errorf("%s failed: %w", filepath.Base(program), ctx.Err())
	}
	if e != nil {
		return out, fmt.Errorf("%s failed: %w (%s)", filepath.Base(program), e, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Do not chmod system ancestors. /private/var/run is normally root:daemon 0775.
func protect(p string, missingOK bool) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return errors.New("noncanonical destination")
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := "/"
	for i, v := range parts {
		cur = filepath.Join(cur, v)
		s, e := os.Lstat(cur)
		if errors.Is(e, os.ErrNotExist) && missingOK && i == len(parts)-1 {
			return nil
		}
		if e != nil {
			return e
		}
		st, ok := s.Sys().(*unix.Stat_t)
		if !ok { // os.FileInfo uses syscall.Stat_t on Darwin.
			var u unix.Stat_t
			if e = unix.Lstat(cur, &u); e != nil {
				return e
			}
			st = &u
		}
		if s.Mode()&os.ModeSymlink != 0 || st.Uid != 0 {
			return fmt.Errorf("unsafe ownership/link: %s", cur)
		}
		if cur == "/private/var/run" {
			if !s.IsDir() || st.Gid != 1 || s.Mode().Perm() != 0775 {
				return errors.New("unexpected /private/var/run; refusing to change system permissions")
			}
			continue
		}
		if s.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("writable protected path: %s", cur)
		}
		if i < len(parts)-1 && !s.IsDir() {
			return errors.New("non-directory ancestor")
		}
	}
	return nil
}

// Darwin inherits the containing directory's group even after setgid(0).
// These helpers are called only for objects just created by this installer.
func ownFD(fd int, mode uint32, kind uint16) error {
	if e := unix.Fchown(fd, 0, 0); e != nil {
		return e
	}
	if e := unix.Fchmod(fd, mode); e != nil {
		return e
	}
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return e
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != kind || uint32(st.Mode&07777) != mode {
		return errors.New("created object is not root:wheel with required mode")
	}
	return nil
}
func ownDirectory(p string, mode os.FileMode) error {
	fd, e := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	return ownFD(fd, uint32(mode.Perm()), unix.S_IFDIR)
}
func mkdirOwned(p string, mode os.FileMode) error {
	if e := os.Mkdir(p, mode); e != nil {
		return e
	}
	return ownDirectory(p, mode)
}
func verifyOwnedDirectory(p string, mode os.FileMode) error {
	var st unix.Stat_t
	if e := unix.Lstat(p, &st); e != nil {
		return e
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(st.Mode&07777) != mode {
		return errors.New("existing owned directory must be root:wheel with required mode")
	}
	return nil
}
func ownLink(p string) error {
	var st unix.Stat_t
	if e := unix.Lstat(p, &st); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return errors.New("created link changed type")
	}
	if e := unix.Lchown(p, 0, 0); e != nil {
		return e
	}
	if e := unix.Lstat(p, &st); e != nil {
		return e
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return errors.New("created link is not root:wheel")
	}
	return nil
}
func privateWrite(p string, data []byte, mode os.FileMode) error {
	if e := protect(filepath.Dir(p), false); e != nil {
		return e
	}
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	if e = ownFD(int(f.Fd()), uint32(mode.Perm()), unix.S_IFREG); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	return syncDir(filepath.Dir(p))
}
func syncDir(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func lookupOwner(name string) (account, error) {
	a := account{Name: name}
	if !safeName(name) || strings.Contains(name, "/") {
		return a, errors.New("invalid account name")
	}
	out, e := command("/usr/bin/dscl", ".", "-read", "/Users/"+name, "UniqueID", "NFSHomeDirectory")
	if e != nil {
		return a, e
	}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(l, ": ")
		if !ok {
			continue
		}
		switch k {
		case "UniqueID":
			a.UID, e = strconv.Atoi(strings.TrimSpace(v))
			if e != nil {
				return a, e
			}
		case "NFSHomeDirectory":
			a.Home = strings.TrimSpace(v)
		}
	}
	if e = validateAccount(a); e != nil {
		return a, e
	}
	s, e := os.Stat(a.Home)
	if e != nil || !s.IsDir() {
		return a, errors.New("daily owner's home does not exist")
	}
	return a, nil
}

type macLife struct {
	payload                 string
	m                       manifest
	owner                   account
	old                     bool
	backup, stage, oldPlist string
	r                       receipt
	addedNow                bool
	runNative               func(string, ...string) ([]byte, error)
}

func (l *macLife) run(program string, args ...string) ([]byte, error) {
	if l.runNative != nil {
		return l.runNative(program, args...)
	}
	return command(program, args...)
}
func (l *macLife) registered() (bool, error) {
	out, e := l.run("/bin/launchctl", "print", "system/"+label)
	code := 0
	if e != nil {
		code = -1
		var exit *exec.ExitError
		if errors.As(e, &exit) {
			code = exit.ExitCode()
		}
	}
	return classifyLaunchQuery(out, code, e)
}

func (l *macLife) status() (string, error) {
	present, e := l.registered()
	if e != nil {
		return "", e
	}
	if !present {
		return "absent", nil
	}
	if !l.old {
		return "", errors.New("orphan registered service")
	}
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	r, e := clientapi.New().StatusDetailsV1(ctx)
	if e != nil {
		return "", fmt.Errorf("running service status uncertain: %w", e)
	}
	if r.ErrorCode != "" || r.Status.ErrorCode != "" {
		return "", errors.New("service reports recovery error")
	}
	return r.Status.State, nil
}
func (l *macLife) step(s string) error {
	switch s {
	case "stop":
		present, e := l.registered()
		if e != nil {
			return e
		}
		if present {
			if _, e = l.run("/bin/launchctl", "bootout", "system/"+label); e != nil {
				return e
			}
			present, e = l.registered()
			if e != nil {
				return e
			}
			if present {
				return errors.New("service still registered after bootout; state preserved")
			}
		}
		// Wait for the stopped daemon to release its persistent lock, but never unlink it.
		deadline := time.Now().Add(105 * time.Second)
		for {
			fd, e := unix.Open(runtimeRoot+"/daemon.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e == unix.ENOENT {
				return nil
			}
			if e != nil {
				return e
			}
			e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
			unix.Close(fd)
			if e == nil {
				return nil
			}
			if time.Now().After(deadline) {
				return errors.New("daemon did not stop; state preserved")
			}
			time.Sleep(200 * time.Millisecond)
		}
	case "restore":
		if _, e := os.Lstat(installRoot); errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e := validateInstalled(); e != nil {
			return e
		}
		_, e := command(installRoot+"/regen-access-service", "--restore")
		return e
	case "stage":
		return l.prepareStage()
	case "activate":
		return l.activate()
	case "start":
		if _, e := command("/bin/launchctl", "bootstrap", "system", plistPath); e != nil {
			return e
		}
		if e := waitIdle(); e != nil {
			return e
		}
		return l.installCA()
	case "rollback":
		if l.addedNow {
			if e := removeCA(l.r); e != nil {
				return e
			}
		}
		failed := installRoot + ".failed-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if e := os.Rename(installRoot, failed); e != nil {
			return e
		}
		if e := os.Rename(plistPath, failed+".plist"); e != nil {
			return e
		}
		if l.old {
			if e := os.Rename(l.backup, installRoot); e != nil {
				return e
			}
			if l.oldPlist != "" {
				if e := os.Rename(l.oldPlist, plistPath); e != nil {
					return e
				}
			}
		}
		return syncDir(filepath.Dir(installRoot))
	case "start-old":
		if l.old {
			if _, e := os.Stat(plistPath); e == nil {
				_, e = command("/bin/launchctl", "bootstrap", "system", plistPath)
				if e != nil {
					return e
				}
				return waitIdle()
			}
		}
		return nil
	}
	return errors.New("unknown lifecycle step")
}
func waitIdle() error {
	end := time.Now().Add(25 * time.Second)
	for {
		ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
		r, e := clientapi.New().StatusDetailsV1(ctx)
		c()
		if e == nil {
			if r.Status.State == "idle" && r.Status.ErrorCode == "" && r.ErrorCode == "" {
				return nil
			}
			return errors.New("started service did not recover to idle")
		}
		if time.Now().After(end) {
			return errors.New("started service did not become ready")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func validateInstalled() error {
	for _, p := range []string{installRoot, installRoot + "/state", installRoot + "/service.json", installRoot + "/manifest.json", installRoot + "/receipt.json"} {
		if e := protect(p, false); e != nil {
			return e
		}
	}
	data, e := os.ReadFile(installRoot + "/manifest.json")
	if e != nil {
		return e
	}
	m, e := parseManifest(data)
	if e != nil {
		return e
	}
	for _, n := range []string{"regen-access-service", "sing-box"} {
		if e = protect(installRoot+"/"+n, false); e != nil {
			return e
		}
		h, e := digestFile(installRoot + "/" + n)
		if e != nil {
			return e
		}
		match := false
		for _, f := range m.Files {
			if f.Path == n && f.Kind == "file" && f.SHA256 == h {
				match = true
			}
		}
		if !match || (n == "sing-box" && h != coreDigest) {
			return errors.New("installed binary integrity failure")
		}
	}
	return nil
}
func copyPayload(source, dest string, m manifest) error {
	for _, e := range m.Files {
		p := filepath.Join(dest, filepath.FromSlash(e.Path))
		switch e.Kind {
		case "dir":
			if err := mkdirOwned(p, 0755); err != nil {
				return err
			}
		case "link":
			if err := os.Symlink(e.Target, p); err != nil {
				return err
			}
			if err := ownLink(p); err != nil {
				return err
			}
		case "file":
			mode := os.FileMode(0644)
			if e.Executable {
				mode = 0755
			}
			if e.Path == "policy.json" {
				mode = 0600
			}
			in, err := os.Open(filepath.Join(source, filepath.FromSlash(e.Path)))
			if err != nil {
				return err
			}
			out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				in.Close()
				return err
			}
			if err = ownFD(int(out.Fd()), uint32(mode.Perm()), unix.S_IFREG); err != nil {
				out.Close()
				in.Close()
				return err
			}
			_, err = io.Copy(out, io.LimitReader(in, 512*1024*1024+1))
			if err == nil {
				err = out.Sync()
			}
			err = errors.Join(err, out.Close(), in.Close())
			if err != nil {
				return err
			}
			h, err := digestFile(p)
			if err != nil || h != e.SHA256 {
				return errors.New("source changed during verified copy")
			}
		}
	}
	return nil
}
func (l *macLife) prepareStage() error {
	var e error
	l.stage, e = os.MkdirTemp(filepath.Dir(installRoot), ".RegenBioAccess-stage-")
	if e != nil {
		return e
	}
	if e = ownDirectory(l.stage, 0700); e != nil {
		return e
	}
	if e = copyPayload(l.payload, l.stage, l.m); e != nil {
		return e
	}
	if e = mkdirOwned(l.stage+"/state", 0700); e != nil {
		return e
	}
	config := fmt.Sprintf(`{"schema_version":1,"owner_uid":%d,"core_sha256":%q,"policy":%s}`, l.owner.UID, coreDigest, fixedPolicy)
	if e = privateWrite(l.stage+"/service.json", []byte(config), 0600); e != nil {
		return e
	}
	b, _ := json.Marshal(l.m)
	if e = privateWrite(l.stage+"/manifest.json", b, 0600); e != nil {
		return e
	}
	l.r = receipt{Version: 1, OwnerUID: l.owner.UID, CASHA256: caDigest}
	if l.old {
		b, e = os.ReadFile(installRoot + "/receipt.json")
		if e != nil {
			return e
		}
		var r receipt
		if e = strictJSON(b, &r); e != nil {
			return e
		}
		if r.Version != 1 || r.CASHA256 != caDigest {
			return errors.New("unknown installed CA receipt")
		}
		l.r.CAAdded = r.CAAdded
	}
	b, _ = json.Marshal(l.r)
	if e = privateWrite(l.stage+"/receipt.json", b, 0600); e != nil {
		return e
	}
	if _, e = command("/usr/bin/codesign", "--verify", "--deep", "--strict", l.stage+"/"+appName); e != nil {
		return e
	}
	return ownDirectory(l.stage, 0755)
}
func (l *macLife) activate() (result error) {
	suffix := time.Now().UTC().Format("20060102T150405.000000000Z")
	l.backup = installRoot + ".backup-" + suffix
	movedOld, movedPlist, newActive := false, false, false
	defer func() {
		if result == nil {
			return
		}
		var recovery error
		if newActive {
			if _, e := os.Lstat(plistPath); e == nil {
				recovery = errors.Join(recovery, os.Rename(plistPath, l.stage+".plist"))
			}
			recovery = errors.Join(recovery, os.Rename(installRoot, l.stage))
		}
		if movedOld {
			recovery = errors.Join(recovery, os.Rename(l.backup, installRoot))
		}
		if movedPlist {
			recovery = errors.Join(recovery, os.Rename(l.oldPlist, plistPath))
		}
		result = errors.Join(result, recovery)
		if recovery == nil && l.old {
			result = errors.Join(result, l.step("start-old"))
		}
	}()
	if l.old {
		if result = os.Rename(installRoot, l.backup); result != nil {
			return
		}
		movedOld = true
	}
	if _, e := os.Lstat(plistPath); e == nil {
		l.oldPlist = plistPath + ".backup-" + suffix
		if result = os.Rename(plistPath, l.oldPlist); result != nil {
			return
		}
		movedPlist = true
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if result = os.Rename(l.stage, installRoot); result != nil {
		return
	}
	newActive = true
	result = privateWrite(plistPath, []byte(launchPlist()), 0644)
	if result != nil {
		return
	}
	result = syncDir(filepath.Dir(installRoot))
	return
}

func caPresent() (bool, error) {
	b, e := command("/usr/bin/security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
	if e != nil {
		return false, e
	}
	return strings.Contains(strings.ToUpper(string(b)), strings.ToUpper(caDigest)), nil
}
func (l *macLife) installCA() error {
	exists, e := caPresent()
	if e != nil {
		return e
	}
	if exists { // Preserve an exact preexisting certificate and all its trust settings.
		_, e = command("/usr/bin/security", "verify-cert", "-c", installRoot+"/Telecom-GoMITM-Root.cer", "-p", "ssl")
		if e != nil {
			return errors.New("exact CA already exists but trust verification failed; existing trust was preserved")
		}
		return nil
	}
	// Record intent durably before trust mutation, so interruption does not lose ownership.
	l.r.CAAdded = true
	b, _ := json.Marshal(l.r)
	tmp := installRoot + "/receipt.pending.json"
	if e = privateWrite(tmp, b, 0600); e != nil {
		return e
	}
	if e = os.Rename(tmp, installRoot+"/receipt.json"); e != nil {
		return e
	}
	if e = syncDir(installRoot); e != nil {
		return e
	}
	l.addedNow = true
	if _, e = command("/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl", "-k", "/Library/Keychains/System.keychain", installRoot+"/Telecom-GoMITM-Root.cer"); e != nil {
		return e
	}
	_, e = command("/usr/bin/security", "verify-cert", "-c", installRoot+"/Telecom-GoMITM-Root.cer", "-p", "ssl")
	return e
}
func removeCA(r receipt) error {
	if !shouldRemoveCA(r) {
		return nil
	}
	exists, e := caPresent()
	if e != nil || !exists {
		return e
	}
	h, e := digestFile(installRoot + "/Telecom-GoMITM-Root.cer")
	if e != nil || h != caDigest {
		return errors.New("CA copy integrity failure; trust retained")
	}
	return finishOwnedCARemoval(r, h, func() ([]byte, int, error) {
		out, err := command("/usr/bin/security", "remove-trusted-cert", "-d", installRoot+"/Telecom-GoMITM-Root.cer")
		code := 0
		if err != nil {
			code = -1
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			}
		}
		return out, code, err
	}, func() error {
		_, err := command("/usr/bin/security", "delete-certificate", "-Z", caSHA1, "/Library/Keychains/System.keychain")
		return err
	})
}

func uninstall(l *macLife) error {
	if !l.old {
		return errors.New("no verified installation exists")
	}
	// Disconnect through the authenticated existing client, then stop and restore offline.
	present, e := l.registered()
	if e != nil {
		return e
	}
	if present {
		ctx, c := context.WithTimeout(context.Background(), 105*time.Second)
		s, e := clientapi.New().DisconnectV1(ctx)
		c()
		if e != nil || s.State != "idle" || s.ErrorCode != "" {
			return errors.New("disconnect uncertain; uninstall refused")
		}
	}
	if e := l.step("stop"); e != nil {
		return e
	}
	if e := l.step("restore"); e != nil {
		return e
	}
	b, e := os.ReadFile(installRoot + "/receipt.json")
	if e != nil {
		return e
	}
	var r receipt
	if e = strictJSON(b, &r); e != nil {
		return e
	}
	if r.Version != 1 || r.CASHA256 != caDigest {
		return errors.New("unknown receipt; uninstall refused")
	}
	if e = removeCA(r); e != nil {
		return e
	}
	// Recoverable removal only. Never recursively delete state or the runtime lock directory.
	suffix := ".uninstalled-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	for _, p := range []string{plistPath, installRoot} {
		if !ownedRemovalTarget(p) {
			return errors.New("invalid removal scope")
		}
		if _, e = os.Lstat(p); errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e = os.Rename(p, p+suffix); e != nil {
			return e
		}
	}
	fmt.Println("Uninstalled. Exact installation retained as", installRoot+suffix, "; runtime locks and earlier backups preserved.")
	return nil
}

func runPlatform(args []string) error {
	if runtime.GOARCH != "arm64" || os.Geteuid() != 0 {
		return errors.New("run this arm64 installer through sudo")
	}
	unix.Umask(0022)
	if e := unix.Setgid(0); e != nil {
		return e
	} // New objects also explicitly chown: Darwin inherits parent-directory GID.
	if len(args) < 1 {
		return errors.New("usage: install --payload DIR --owner DAILY_USER --accept-ca SHA256 | uninstall")
	}
	mode := args[0]
	if mode != "install" && mode != "uninstall" {
		return errors.New("unsupported action")
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	payload := flags.String("payload", "", "package payload")
	owner := flags.String("owner", "", "existing daily local user")
	accept := flags.String("accept-ca", "", "explicit traffic CA SHA256 consent")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	for _, p := range []string{installRoot, plistPath, runtimeRoot} {
		if e := protect(p, true); e != nil {
			return e
		}
	}
	l := &macLife{}
	if _, e := os.Lstat(installRoot); e == nil {
		l.old = true
		if e = validateInstalled(); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if !l.old {
		if _, e := os.Lstat(plistPath); e == nil {
			return errors.New("orphan launch plist; manual audit required")
		}
	}
	{
		present, e := l.registered()
		if e != nil {
			return e
		}
		if present && !l.old {
			return errors.New("orphan live daemon; manual audit required")
		}
	}
	if mode == "install" {
		if strings.ToLower(*accept) != caDigest {
			return errors.New("explicit traffic inspection CA consent required")
		}
		var e error
		l.owner, e = lookupOwner(*owner)
		if e != nil {
			return e
		}
		l.payload, e = filepath.Abs(*payload)
		if e != nil || *payload == "" {
			return errors.New("payload required")
		}
		b, e := os.ReadFile(l.payload + "/manifest.json")
		if e != nil {
			return e
		}
		l.m, e = parseManifest(b)
		if e != nil {
			return e
		}
		if e = verifyTree(l.payload, l.m, true); e != nil {
			return e
		}
	}
	if _, e := os.Stat(runtimeRoot); errors.Is(e, os.ErrNotExist) {
		if e = mkdirOwned(runtimeRoot, 0755); e != nil {
			return e
		}
	}
	if e := protect(runtimeRoot, false); e != nil {
		return e
	}
	if e := verifyOwnedDirectory(runtimeRoot, 0755); e != nil {
		return e
	}
	fd, e := unix.Open(runtimeRoot+"/installer.lock", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	created := e == nil
	if e == unix.EEXIST {
		fd, e = unix.Open(runtimeRoot+"/installer.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if created {
		if e = ownFD(fd, 0600, unix.S_IFREG); e != nil {
			return e
		}
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return e
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("unsafe installer lock")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("another installation is active")
	}
	// Revalidate under the installer lock; a preceding invocation may have finished
	// between preflight and acquiring this lock.
	for _, p := range []string{installRoot, plistPath, runtimeRoot} {
		if e = protect(p, true); e != nil {
			return e
		}
	}
	l.old = false
	if _, e = os.Lstat(installRoot); e == nil {
		l.old = true
		if e = validateInstalled(); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if !l.old {
		if _, e = os.Lstat(plistPath); e == nil {
			return errors.New("orphan plist; audit required")
		}
	}
	{
		present, e := l.registered()
		if e != nil {
			return e
		}
		if present && !l.old {
			return errors.New("orphan daemon; audit required")
		}
	}
	if mode == "uninstall" {
		return uninstall(l)
	}
	if e = replace(l); e != nil {
		return e
	}
	fmt.Println("Installed for", l.owner.Name, "(UID", l.owner.UID, "). Open", installRoot+"/"+appName, "as that ordinary user. Existing backups retained at", l.backup)
	return nil
}
