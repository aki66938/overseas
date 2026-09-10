package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const installRoot = "/Library/Application Support/RegenBioAccess"
const plistPath = "/Library/LaunchDaemons/com.regenbio.access.poc.plist"
const runtimeRoot = "/private/var/run/regen-access"
const label = "com.regenbio.access.poc"
const coreDigest = "5b75c1dec19488675f725adc7a6e3a7301a553117af835dc47669b1fa918976b"
const caDigest = "0d344a6f39fd4252c96f0e5606e2f4e7205cb2e59c44603c542aa8c132a711f8"
const caSHA1 = "7903068AAA22CA51185706C23611E6B5EEEF2729"
const appName = "RegenBio Access.app"
const fixedPolicy = `{"schema_version":2,"mode":"poc","nodes":[{"id":"vm101","transport":"http-connect","address":"172.20.9.15","port":8080,"priority":10}],"corporate_cidrs":["172.20.8.0/22"],"corporate_dns":["172.20.9.1","172.20.9.2"],"internal_suffixes":["ad.intra.regen-bio.com","intra.regen-bio.com"],"block_udp":true,"block_quic":true,"credential":{"kind":"","path":""}}`

type entry struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	SHA256     string `json:"sha256,omitempty"`
	Target     string `json:"target,omitempty"`
	Executable bool   `json:"executable,omitempty"`
}
type manifest struct {
	Version int     `json:"version"`
	Files   []entry `json:"files"`
}

func strictJSON(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func safeName(p string) bool {
	return p != "" && p != "." && path.Clean(p) == p && !path.IsAbs(p) && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\:\x00\r\n")
}
func safeLink(p, target string) bool {
	if !strings.HasPrefix(p, appName+"/") || target == "" || path.IsAbs(target) || strings.ContainsAny(target, "\\:\x00\r\n") {
		return false
	}
	dest := path.Clean(path.Join(path.Dir(p), target))
	return strings.HasPrefix(dest, appName+"/")
}
func parseManifest(data []byte) (manifest, error) {
	var m manifest
	if len(data) > 4*1024*1024 {
		return m, errors.New("manifest too large")
	}
	if err := strictJSON(data, &m); err != nil {
		return m, err
	}
	if m.Version != 1 || len(m.Files) == 0 {
		return m, errors.New("invalid manifest")
	}
	seen := map[string]bool{}
	for _, e := range m.Files {
		if !safeName(e.Path) || seen[strings.ToLower(e.Path)] {
			return m, errors.New("unsafe or duplicate path")
		}
		seen[strings.ToLower(e.Path)] = true
		switch e.Kind {
		case "dir":
			if e.SHA256 != "" || e.Target != "" || e.Executable {
				return m, errors.New("invalid directory")
			}
		case "file":
			b, err := hex.DecodeString(e.SHA256)
			if err != nil || len(b) != 32 || e.Target != "" {
				return m, errors.New("invalid file")
			}
		case "link":
			if !safeLink(e.Path, e.Target) || e.SHA256 != "" || e.Executable {
				return m, errors.New("unsafe link")
			}
		default:
			return m, errors.New("invalid kind")
		}
	}
	return m, nil
}
func digestFile(p string) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > 512*1024*1024 {
		return "", errors.New("unsafe file size/type")
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), e
}
func makeManifest(root string) (manifest, error) {
	m := manifest{Version: 1}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if p == root {
			return nil
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" {
			return nil
		}
		x := entry{Path: rel}
		switch {
		case d.Type()&os.ModeSymlink != 0:
			x.Kind = "link"
			x.Target, e = os.Readlink(p)
		case d.IsDir():
			x.Kind = "dir"
		case d.Type().IsRegular():
			x.Kind = "file"
			x.SHA256, e = digestFile(p)
			s, se := d.Info()
			if se != nil {
				return se
			}
			x.Executable = s.Mode().Perm()&0111 != 0
		default:
			return errors.New("unsupported file type")
		}
		if e != nil {
			return e
		}
		m.Files = append(m.Files, x)
		return nil
	})
	if err != nil {
		return m, err
	}
	data, _ := json.Marshal(m)
	return parseManifest(data)
}
func verifyTree(root string, m manifest, complete bool) error {
	actual, e := makeManifest(root)
	if e != nil {
		return e
	}
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(m)
	if !bytes.Equal(a, b) {
		return errors.New("payload manifest mismatch")
	}
	found := map[string]entry{}
	for _, f := range m.Files {
		found[f.Path] = f
		if f.Kind == "link" {
			resolved, e := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(f.Path)))
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(filepath.Join(root, appName), resolved)
			if e != nil || !safeName(filepath.ToSlash(rel)) {
				return errors.New("link escapes app")
			}
		}
	}
	if complete {
		for _, n := range []string{"regen-access-service", "regen-access-installer", "regen-access", "sing-box", "Telecom-GoMITM-Root.cer", "policy.json", appName + "/Contents/Info.plist"} {
			if found[n].Kind != "file" {
				return fmt.Errorf("missing %s", n)
			}
		}
		if found["sing-box"].SHA256 != coreDigest || found["Telecom-GoMITM-Root.cer"].SHA256 != caDigest {
			return errors.New("pinned payload digest mismatch")
		}
		p, e := os.ReadFile(filepath.Join(root, "policy.json"))
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(p)) != fixedPolicy {
			return errors.New("policy is not approved fixed policy")
		}
		for _, f := range m.Files {
			if f.Path != appName && !strings.HasPrefix(f.Path, appName+"/") && f.Path != "regen-access-service" && f.Path != "regen-access-installer" && f.Path != "regen-access" && f.Path != "sing-box" && f.Path != "Telecom-GoMITM-Root.cer" && f.Path != "policy.json" {
				return errors.New("unexpected payload target")
			}
		}
	}
	return nil
}

type account struct {
	Name string
	UID  int
	Home string
}

func validateAccount(a account) error {
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,63}$`).MatchString(a.Name) || a.UID < 501 || a.UID > 2147483647 || !strings.HasPrefix(a.Home, "/Users/") || !safeName(strings.TrimPrefix(a.Home, "/")) {
		return errors.New("owner must be an existing ordinary local account with a /Users home")
	}
	return nil
}

type lifecycle interface {
	status() (string, error)
	step(string) error
}

func classifyLaunchQuery(output []byte, code int, err error) (bool, error) {
	if err == nil && code == 0 {
		return true, nil
	}
	// Exact C-locale output and exit status observed on the target Mac. Any
	// changed, truncated or failed query stays uncertain instead of skipping stop.
	missing := "Bad request.\nCould not find service \"" + label + "\" in domain for system"
	if code == 113 && err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) && strings.TrimSpace(string(output)) == missing {
		return false, nil
	}
	if err == nil {
		err = fmt.Errorf("launchctl exited %d", code)
	}
	return false, fmt.Errorf("launchd registration is uncertain: %w", err)
}

func replace(f lifecycle) error {
	s, e := f.status()
	if e != nil {
		return e
	}
	if s != "idle" && s != "absent" {
		return errors.New("upgrade refused: service connected or recovery uncertain")
	}
	for _, v := range []string{"stop", "restore", "stage", "activate"} {
		if e = f.step(v); e != nil {
			if v == "stage" {
				return errors.Join(e, f.step("start-old"))
			}
			return e
		}
	}
	if e = f.step("start"); e == nil {
		return nil
	}
	original := e
	for _, v := range []string{"stop", "restore", "rollback", "start-old"} {
		if e = f.step(v); e != nil {
			return errors.Join(original, fmt.Errorf("rollback %s: %w; backups retained", v, e))
		}
	}
	return fmt.Errorf("new service failed; previous installation restored: %w", original)
}
func ownedRemovalTarget(p string) bool { return p == installRoot || p == plistPath }

// Presence in the System keychain is checked by the native caller first. The
// receipt and pinned DER digest remain required before either cleanup operation.
func finishOwnedCARemoval(r receipt, digest string, removeTrust func() ([]byte, int, error), deleteCertificate func() error) error {
	if !shouldRemoveCA(r) {
		return nil
	}
	if digest != caDigest {
		return errors.New("CA copy integrity failure; trust retained")
	}
	output, code, err := removeTrust()
	missing := "SecTrustSettingsRemoveTrustSettings: The specified item could not be found in the keychain."
	confirmedMissing := code == 1 && err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) && strings.TrimSpace(string(output)) == missing
	if err != nil && !confirmedMissing {
		return err
	}
	if err == nil && code != 0 {
		return fmt.Errorf("trust removal exited %d without a confirmed result", code)
	}
	return deleteCertificate()
}
