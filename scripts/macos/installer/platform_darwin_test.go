//go:build darwin

package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestQueryFailureStopsStatusStopAndUninstall(t *testing.T) {
	for _, action := range []string{"status", "stop", "uninstall"} {
		t.Run(action, func(t *testing.T) {
			queryErr := errors.New("launchd communication failed")
			calls := 0
			l := &macLife{old: true, runNative: func(program string, args ...string) ([]byte, error) {
				calls++
				if program != "/bin/launchctl" || len(args) != 2 || args[0] != "print" {
					t.Fatalf("mutation attempted: %s %v", program, args)
				}
				return nil, queryErr
			}}
			var e error
			switch action {
			case "status":
				_, e = l.status()
			case "stop":
				e = l.step("stop")
			case "uninstall":
				e = uninstall(l)
			}
			if !errors.Is(e, queryErr) || calls != 1 {
				t.Fatalf("query failure not propagated: calls=%d err=%v", calls, e)
			}
		})
	}
}

func TestStopRequiresConfirmedLaunchdUnregistration(t *testing.T) {
	for _, failQuery := range []bool{false, true} {
		calls := 0
		l := &macLife{runNative: func(program string, args ...string) ([]byte, error) {
			calls++
			if program != "/bin/launchctl" {
				t.Fatal(program)
			}
			if calls == 2 {
				if args[0] != "bootout" {
					t.Fatal(args)
				}
				return nil, nil
			}
			if calls > 3 {
				t.Fatal("extra command after uncertain unregistration")
			}
			if calls == 3 && failQuery {
				return nil, errors.New("launchd unavailable")
			}
			return []byte("service remains registered"), nil
		}}
		if e := l.step("stop"); e == nil || calls != 3 {
			t.Fatalf("unregistration not proved: calls=%d err=%v", calls, e)
		}
	}
}

func TestProtectedAncestorRejectsSymlinkAndWritablePaths(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root fixture required")
	}
	d, e := os.MkdirTemp("/Library/Application Support", ".regenbio-installer-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(d) // Exact generated fixture only; never an installation path.
	if e = protect(d, false); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(d, "real")
	os.Mkdir(p, 0755)
	l := filepath.Join(d, "link")
	os.Symlink(p, l)
	if protect(l, false) == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(p, 0777)
	if protect(p, false) == nil {
		t.Fatal("writable path accepted")
	}
}

func TestCreatedPayloadAndPrivateFileUseWheelUnderDaemonParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root fixture required")
	}
	parent, e := os.MkdirTemp("/Library/Application Support", ".regenbio-installer-gid-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(parent)
	if e = os.Chown(parent, 0, 1); e != nil {
		t.Fatal(e)
	}
	if e = privateWrite(filepath.Join(parent, "receipt.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	assertOwner := func(p string, gid uint32) {
		t.Helper()
		var st unix.Stat_t
		if e := unix.Lstat(p, &st); e != nil {
			t.Fatal(e)
		}
		if st.Uid != 0 || st.Gid != gid {
			t.Errorf("%s uid=%d gid=%d, want root gid=%d", p, st.Uid, st.Gid, gid)
		}
	}
	assertOwner(filepath.Join(parent, "receipt.json"), 0)
	source := t.TempDir()
	if e = os.MkdirAll(filepath.Join(source, appName, "Contents"), 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(source, appName, "Contents", "data"), []byte("payload"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("data", filepath.Join(source, appName, "Contents", "link")); e != nil {
		t.Fatal(e)
	}
	m, e := makeManifest(source)
	if e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(parent, "stage")
	if e = os.Mkdir(dest, 0755); e != nil {
		t.Fatal(e)
	}
	assertOwner(dest, 1) // Darwin actually inherited non-wheel GID; fixture exercises the bug.
	if e = verifyOwnedDirectory(dest, 0755); e == nil {
		t.Fatal("existing non-wheel directory accepted")
	}
	runDir := filepath.Join(parent, "runtime")
	if e = mkdirOwned(runDir, 0755); e != nil {
		t.Fatal(e)
	}
	assertOwner(runDir, 0)
	if e = verifyOwnedDirectory(runDir, 0755); e != nil {
		t.Fatal(e)
	}
	if e = copyPayload(source, dest, m); e != nil {
		t.Fatal(e)
	}
	for _, entry := range m.Files {
		assertOwner(filepath.Join(dest, entry.Path), 0)
	}
	assertOwner(parent, 1) // No system/containing directory ownership changes.
}

func TestCopyStageDoesNotFollowEscapingLink(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, appName, "Contents"), 0755)
	os.Symlink("/etc/passwd", filepath.Join(d, appName, "Contents", "evil"))
	if _, e := makeManifest(d); e == nil {
		t.Fatal("escaping link accepted")
	}
}
