//go:build windows

package coreverify

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	adminsSID             = "S-1-5-32-544"
	systemSID             = "S-1-5-18"
	usersSID              = "S-1-5-32-545"
	authenticatedUsersSID = "S-1-5-11"
	everyoneSID           = "S-1-1-0"
)

type securityMetadata struct {
	OwnerSID         string   `json:"OwnerSID"`
	UnsafeWriteSIDs  []string `json:"UnsafeWriteSIDs"`
	UnsafeWriteNames []string `json:"UnsafeWriteNames"`
}

type signatureMetadata struct {
	Status     string `json:"Status"`
	Subject    string `json:"Subject"`
	Thumbprint string `json:"Thumbprint"`
}

var (
	lstatPath           = os.Lstat
	inspectSecurity     = inspectSecurityWithPowerShell
	inspectAuthenticode = inspectAuthenticodeWithPowerShell
)

// Verify opens the executable without following reparse points, checks the
// pinned hash, rejects unsafe ownership/ACLs, and enforces the expected
// Authenticode state for the pinned sing-box binary.
func Verify(path string, expectedSHA256 string, signerAllowlist []string) error {
	normalizedExpected, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return err
	}

	file, err := openRegularFileNoReparse(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := ensurePortableExecutable(file); err != nil {
		return err
	}

	actualHash, err := hashOpenFile(file)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(actualHash), []byte(normalizedExpected)) != 1 {
		return fmt.Errorf("sha256 mismatch: got %s", actualHash)
	}

	metadata, err := inspectSecurity(path)
	if err != nil {
		return fmt.Errorf("inspect file security: %w", err)
	}
	ownerSID := strings.ToUpper(strings.TrimSpace(metadata.OwnerSID))
	if ownerSID != adminsSID && ownerSID != systemSID {
		return fmt.Errorf("owner SID %q is not Administrators or SYSTEM", metadata.OwnerSID)
	}
	if len(metadata.UnsafeWriteSIDs) > 0 {
		names := metadata.UnsafeWriteNames
		if len(names) == 0 {
			names = metadata.UnsafeWriteSIDs
		}
		return fmt.Errorf("file is writable by standard users: %s", strings.Join(names, ", "))
	}

	signature, err := inspectAuthenticode(path)
	if err != nil {
		return fmt.Errorf("inspect Authenticode signature: %w", err)
	}
	if err := validateSignature(signature, signerAllowlist); err != nil {
		return err
	}

	return nil
}

func openRegularFileNoReparse(path string) (*os.File, error) {
	info, err := lstatPath(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a reparse point", path)
	}

	pathUTF16, err := syscall.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("encode path: %w", err)
	}
	handle, err := syscall.CreateFile(
		pathUTF16,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		syscall.CloseHandle(handle)
		return nil, fmt.Errorf("wrap handle for %s", path)
	}

	var handleInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect handle for %s: %w", path, err)
	}
	if handleInfo.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		file.Close()
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if handleInfo.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		file.Close()
		return nil, fmt.Errorf("%s is a reparse point", path)
	}

	return file, nil
}

func ensurePortableExecutable(file *os.File) error {
	header := make([]byte, 64)
	if _, err := io.ReadFull(file, header); err != nil {
		return fmt.Errorf("read executable header: %w", err)
	}
	if header[0] != 'M' || header[1] != 'Z' {
		return fmt.Errorf("%s is not a native Windows executable", file.Name())
	}

	peOffset := int64(binary.LittleEndian.Uint32(header[0x3c:0x40]))
	signature := make([]byte, 4)
	if _, err := file.ReadAt(signature, peOffset); err != nil {
		return fmt.Errorf("read PE signature: %w", err)
	}
	if string(signature) != "PE\x00\x00" {
		return fmt.Errorf("%s is not a PE executable", file.Name())
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind executable: %w", err)
	}
	return nil
}

func hashOpenFile(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind for hash: %w", err)
	}

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hash executable: %w", err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func normalizeSHA256(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) != 64 {
		return "", fmt.Errorf("expected SHA-256 must be 64 hex characters")
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("expected SHA-256 must be lowercase hex: %w", err)
	}
	return normalized, nil
}

func validateSignature(signature signatureMetadata, signerAllowlist []string) error {
	status := strings.TrimSpace(signature.Status)
	if len(signerAllowlist) == 0 {
		if strings.EqualFold(status, "NotSigned") {
			return nil
		}
		return fmt.Errorf("Authenticode status %q is not allowed for an unsigned pinned binary", status)
	}

	if !strings.EqualFold(status, "Valid") {
		return fmt.Errorf("Authenticode status %q is not valid", status)
	}

	for _, allowed := range signerAllowlist {
		normalizedAllowed := strings.TrimSpace(allowed)
		if normalizedAllowed == "" {
			continue
		}
		if strings.EqualFold(signature.Thumbprint, normalizedAllowed) || strings.EqualFold(signature.Subject, normalizedAllowed) {
			return nil
		}
	}

	return fmt.Errorf("Authenticode signer %q / %q is not in the allowlist", signature.Subject, signature.Thumbprint)
}

func inspectSecurityWithPowerShell(path string) (securityMetadata, error) {
	return runPowerShellJSON[securityMetadata](path, securityInspectionScript())
}

func securityInspectionScript() string {
	return strings.Join([]string{
		"$acl = Get-Acl -LiteralPath $env:COREVERIFY_TARGET_PATH",
		"$ownerSid = ([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value",
		"$targetSids = @('S-1-5-32-545','S-1-5-11','S-1-1-0')",
		"$unsafeNames = @()",
		"$unsafeSids = @()",
		"foreach ($rule in @($acl.Access)) {",
		"  $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value",
		"  if (-not ($targetSids -contains $sid)) { continue }",
		"  if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }",
		"  $rights = [System.Security.AccessControl.FileSystemRights]$rule.FileSystemRights",
		"  $unsafe = $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::WriteData) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::CreateFiles) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::AppendData) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::CreateDirectories) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::WriteAttributes) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::Delete) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::ChangePermissions) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::TakeOwnership) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::Modify) -or $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::FullControl)",
		"  if ($unsafe) {",
		"    $unsafeNames += [string]$rule.IdentityReference.Value",
		"    $unsafeSids += $sid",
		"  }",
		"}",
		"[pscustomobject]@{",
		"  OwnerSID = $ownerSid",
		"  UnsafeWriteSIDs = @($unsafeSids | Sort-Object -Unique)",
		"  UnsafeWriteNames = @($unsafeNames | Sort-Object -Unique)",
		"} | ConvertTo-Json -Compress -Depth 5",
	}, "\n")
}

func inspectAuthenticodeWithPowerShell(path string) (signatureMetadata, error) {
	return runPowerShellJSON[signatureMetadata](path, authenticodeInspectionScript())
}

func authenticodeInspectionScript() string {
	return strings.Join([]string{
		"$ProgressPreference = 'SilentlyContinue'",
		`Import-Module 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1' -ErrorAction Stop`,
		"$signature = Get-AuthenticodeSignature -LiteralPath $env:COREVERIFY_TARGET_PATH",
		"[pscustomobject]@{",
		"  Status = [string]$signature.Status",
		"  Subject = [string]$signature.SignerCertificate.Subject",
		"  Thumbprint = [string]$signature.SignerCertificate.Thumbprint",
		"} | ConvertTo-Json -Compress -Depth 3",
	}, "\n")
}

func runPowerShellJSON[T any](path string, script string) (T, error) {
	var output T

	command := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", script)
	command.Env = append(os.Environ(), "COREVERIFY_TARGET_PATH="+path)
	data, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("powershell failed: %w: %s", err, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return output, fmt.Errorf("decode powershell JSON: %w", err)
	}
	return output, nil
}
