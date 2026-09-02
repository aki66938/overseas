//go:build windows

package coreverify

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type FileIdentity struct {
	VolumeSerialNumber uint32
	FileIndex          uint64
	Size               int64
	LastWriteTime      int64
	ChangeTime         int64
	FileAttributes     uint32
}

type Evidence struct {
	Identity               FileIdentity
	SHA256                 string
	AuthenticodeStatus     string
	AuthenticodeSubject    string
	AuthenticodeThumbprint string
}

type identityReader func(string) (FileIdentity, error)
type evidenceVerifier func(string, string, []string) (Evidence, error)

type cachedEvidence struct {
	path     string
	evidence Evidence
}

type CachedVerifier struct {
	mu              sync.Mutex
	expectedSHA256  string
	signerAllowlist []string
	identity        identityReader
	full            evidenceVerifier
	cached          *cachedEvidence
}

func NewCachedVerifier(expectedSHA256 string, signerAllowlist []string) (*CachedVerifier, error) {
	return newCachedVerifier(expectedSHA256, signerAllowlist, readFileIdentity, VerifyEvidence)
}

func newCachedVerifier(expectedSHA256 string, signerAllowlist []string, identity identityReader, full evidenceVerifier) (*CachedVerifier, error) {
	normalizedHash, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return nil, err
	}
	if identity == nil || full == nil {
		return nil, errors.New("verification dependencies are required")
	}
	return &CachedVerifier{
		expectedSHA256: normalizedHash, signerAllowlist: canonicalSignerAllowlist(signerAllowlist),
		identity: identity, full: full,
	}, nil
}

func (v *CachedVerifier) Verify(path string) error {
	if v == nil {
		return errors.New("cached verifier is nil")
	}
	canonicalPath := strings.ToLower(filepath.Clean(path))
	v.mu.Lock()
	defer v.mu.Unlock()
	identity, err := v.identity(path)
	if err != nil {
		return err
	}
	if v.cached != nil && v.cached.path == canonicalPath && v.cached.evidence.Identity == identity {
		return nil
	}
	evidence, err := v.full(path, v.expectedSHA256, append([]string(nil), v.signerAllowlist...))
	if err != nil {
		return err
	}
	if evidence.Identity != identity {
		return errors.New("executable identity changed during verification")
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(evidence.SHA256)), []byte(v.expectedSHA256)) != 1 {
		return errors.New("verification evidence SHA-256 does not match policy")
	}
	if err := validateSignature(signatureMetadata{
		Status: evidence.AuthenticodeStatus, Subject: evidence.AuthenticodeSubject,
		Thumbprint: evidence.AuthenticodeThumbprint,
	}, v.signerAllowlist); err != nil {
		return fmt.Errorf("verification evidence signature: %w", err)
	}
	v.cached = &cachedEvidence{path: canonicalPath, evidence: evidence}
	return nil
}

func canonicalSignerAllowlist(values []string) []string {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		trimmed := strings.ToUpper(strings.TrimSpace(value))
		if trimmed != "" {
			set[trimmed] = true
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
