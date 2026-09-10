package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchQueryFailsClosedOnErrorsAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		out  string
		code int
		err  error
	}{
		{"", 5, errors.New("communication failure")},
		{"", -1, context.DeadlineExceeded},
		{"Could not find service", 113, errors.New("truncated response")},
		{"Could not find service \"other.service\" in domain for system", 113, errors.New("missing different service")},
	} {
		if present, e := classifyLaunchQuery([]byte(tc.out), tc.code, tc.err); e == nil || present {
			t.Fatalf("query uncertainty accepted as absence: %#v", tc)
		}
	}
	if present, e := classifyLaunchQuery([]byte("system/com.regenbio.access.poc = {}"), 0, nil); e != nil || !present {
		t.Fatal(present, e)
	}
}

func TestLaunchQueryAcceptsOnlyObservedExactAbsence(t *testing.T) {
	output := []byte("Bad request.\nCould not find service \"com.regenbio.access.poc\" in domain for system\n")
	if present, e := classifyLaunchQuery(output, 113, errors.New("exit status 113")); e != nil || present {
		t.Fatalf("explicit absence rejected: present=%v err=%v", present, e)
	}
	for _, e := range []error{context.DeadlineExceeded, context.Canceled} {
		if _, got := classifyLaunchQuery(output, 113, e); got == nil {
			t.Fatal("timeout/cancel accepted as absence")
		}
	}
	if _, e := classifyLaunchQuery(output, 5, errors.New("communication failure")); e == nil {
		t.Fatal("wrong exit status accepted")
	}
}

func TestManifestRejectsMalformedAndEscapingEntries(t *testing.T) {
	for _, raw := range []string{`{`, `{"version":1,"files":[],"extra":true}`, `{"version":1,"files":[]} {}`, `{"version":1,"files":[{"path":"../escape","kind":"file","sha256":"00"}]}`, `{"version":1,"files":[{"path":"/etc/passwd","kind":"file"}]}`} {
		if _, err := parseManifest([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestAccountSelectionRejectsSystemAndUnmappedOwner(t *testing.T) {
	for _, a := range []account{{"root", 0, "/var/root"}, {"_daemon", 501, "/Users/_daemon"}, {"someone", 502, "/var/empty"}, {"user;touch x", 501, "/Users/user"}} {
		if err := validateAccount(a); err == nil {
			t.Fatalf("accepted %#v", a)
		}
	}
	if err := validateAccount(account{"regen-bio", 501, "/Users/regen-bio"}); err != nil {
		t.Fatal(err)
	}
	if err := validateAccount(account{"daily", 709, "/Users/daily"}); err != nil {
		t.Fatal("hardcoded owner uid", err)
	}
}

func TestManifestDetectsTamperAndAllowsOnlyContainedAppLinks(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "RegenBio Access.app", "Contents"), 0755)
	os.WriteFile(filepath.Join(root, "RegenBio Access.app", "Contents", "test"), []byte("ok"), 0644)
	m, err := makeManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyTree(root, m, false); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "RegenBio Access.app", "Contents", "test"), []byte("changed"), 0644)
	if verifyTree(root, m, false) == nil {
		t.Fatal("accepted tamper")
	}
	if safeLink("RegenBio Access.app/Contents/Frameworks/F.framework/Versions/Current", "A") == false {
		t.Fatal("valid framework link rejected")
	}
	for _, target := range []string{"/etc/passwd", "../../../../../../escape"} {
		if safeLink("RegenBio Access.app/Contents/link", target) {
			t.Fatal("escaping link accepted")
		}
	}
	if safeLink("sing-box", "RegenBio Access.app/Contents/test") {
		t.Fatal("binary symlink accepted")
	}
}

func TestLifecycleRefusesConnectedUpgradeWithoutMutation(t *testing.T) {
	f := &fakeLife{current: "connected"}
	if err := replace(f); err == nil {
		t.Fatal("connected upgrade accepted")
	}
	if strings.Join(f.events, ",") != "status" {
		t.Fatalf("mutated %v", f.events)
	}
}

func TestLifecycleFailedBootstrapRestoresPreviousInstall(t *testing.T) {
	f := &fakeLife{current: "idle", failStart: true}
	if replace(f) == nil {
		t.Fatal("failed bootstrap accepted")
	}
	got := strings.Join(f.events, ",")
	want := "status,stop,restore,stage,activate,start,stop,restore,rollback,start-old"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestStageFailureRestartsUnchangedPreviousService(t *testing.T) {
	f := &fakeLife{current: "idle", failStage: true}
	if replace(f) == nil {
		t.Fatal("stage failure accepted")
	}
	if got := strings.Join(f.events, ","); got != "status,stop,restore,stage,start-old" {
		t.Fatal(got)
	}
}

func TestLifecycleDoesNotDeleteUnresolvedState(t *testing.T) {
	f := &fakeLife{current: "idle", failRestore: true}
	if replace(f) == nil {
		t.Fatal("unresolved restore accepted")
	}
	if strings.Join(f.events, ",") != "status,stop,restore" {
		t.Fatal(f.events)
	}
	for _, p := range []string{"/", "/Library", "/Library/Application Support", "/private/var/run", "/Applications/RegenBio-UI-Preview.app"} {
		if ownedRemovalTarget(p) {
			t.Fatal("overbroad removal", p)
		}
	}
	if !ownedRemovalTarget(installRoot) || !ownedRemovalTarget(plistPath) {
		t.Fatal("fixed targets rejected")
	}
}

func TestLaunchDaemonContainsChildrenAndBoundedStop(t *testing.T) {
	p := launchPlist()
	for _, s := range []string{"<key>AbandonProcessGroup</key><false/>", "<key>ExitTimeOut</key><integer>100</integer>", "/usr/bin:/bin:/usr/sbin:/sbin", "com.regenbio.access.poc", "<key>KeepAlive</key><true/>"} {
		if !strings.Contains(p, s) {
			t.Fatal("missing launch constraint", s)
		}
	}
}

func TestRecoveryReceiptIsNotAuthorizationToRemovePreexistingTrust(t *testing.T) {
	if shouldRemoveCA(receipt{CAAdded: false, CASHA256: caDigest}) {
		t.Fatal("preexisting CA would be removed")
	}
	if shouldRemoveCA(receipt{CAAdded: true, CASHA256: "untrusted"}) {
		t.Fatal("wrong CA would be removed")
	}
	if !shouldRemoveCA(receipt{CAAdded: true, CASHA256: caDigest}) {
		t.Fatal("owned CA not recognized")
	}
}

type fakeLife struct {
	current                           string
	failStart, failRestore, failStage bool
	events                            []string
}

func (f *fakeLife) step(s string) error {
	f.events = append(f.events, s)
	if s == "stage" && f.failStage {
		return os.ErrPermission
	}
	if s == "start" && f.failStart {
		return os.ErrInvalid
	}
	if s == "restore" && f.failRestore {
		return os.ErrPermission
	}
	return nil
}
func (f *fakeLife) status() (string, error) {
	f.events = append(f.events, "status")
	return f.current, nil
}
