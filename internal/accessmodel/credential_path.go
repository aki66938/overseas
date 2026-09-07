// Copyright 2010 The Go Authors. All rights reserved.
// Derived from Go 1.27.0 internal/filepathlite/path_windows.go.
// Use of this source code is governed by the BSD-style license reproduced
// in third_party/go/LICENSE.

package accessmodel

// DPAPI references describe Windows storage even when a policy is validated,
// hashed or rendered on another host. This lexical check preserves Windows
// filepath.IsAbs semantics without rewriting policy bytes or opening a file.
// It is not a filename validity, containment, or storage availability check.

func credentialPathSeparator(c uint8) bool {
	return c == '\\' || c == '/'
}

func credentialPathUpper(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

// windowsCredentialPathIsAbs reports whether the path is absolute.
func windowsCredentialPathIsAbs(path string) (b bool) {
	l := credentialVolumeNameLen(path)
	if l == 0 {
		return false
	}
	// If the volume name starts with a double slash, this is an absolute path.
	if credentialPathSeparator(path[0]) && credentialPathSeparator(path[1]) {
		return true
	}
	path = path[l:]
	if path == "" {
		return false
	}
	return credentialPathSeparator(path[0])
}

// credentialVolumeNameLen returns length of the leading volume name on Windows.
//
// See:
// https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
// https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
func credentialVolumeNameLen(path string) int {
	switch {
	case len(path) >= 2 && path[1] == ':':
		// Path starts with a drive letter.
		//
		// Not all Windows functions necessarily enforce the requirement that
		// drive letters be in the set A-Z, and we don't try to here.
		//
		// We don't handle the case of a path starting with a non-ASCII character,
		// in which case the "drive letter" might be multiple bytes long.
		return 2

	case len(path) == 0 || !credentialPathSeparator(path[0]):
		// Path does not have a volume component.
		return 0

	case credentialPathHasPrefixFold(path, `\\.`) ||
		credentialPathHasPrefixFold(path, `\\?`) || credentialPathHasPrefixFold(path, `\??`):
		// Path starts with a device prefix: \\.\ for Local Device paths,
		// or \\?\ or \??\ for Root Local Device paths.
		switch {
		case len(path) == 3:
			return 3 // exactly \\., \\?, or \??
		case credentialPathHasPrefixFold(path[4:], `UNC`):
			// We're going to treat the UNC host and share as part of the volume
			// prefix for historical reasons, but this isn't really principled;
			// Windows's own GetFullPathName will happily remove the first
			// component of the path in this space, converting
			// \\.\unc\a\b\..\c into \\.\unc\a\c.
			return validCredentialVolumeNameLen(path, credentialUNCLen(path, len(`\\.\UNC\`)))
		}
		//
		// We treat the next component after the device prefix as
		// part of the volume name, which means Clean(`\\?\c:\`)
		// won't remove the trailing \. (See #64028.)
		_, rest, ok := cutCredentialPath(path[4:])
		if !ok {
			return validCredentialVolumeNameLen(path, len(path))
		}
		return validCredentialVolumeNameLen(path, len(path)-len(rest)-1)

	case len(path) >= 2 && credentialPathSeparator(path[1]):
		// Path starts with \\, and is a UNC path.
		return validCredentialVolumeNameLen(path, credentialUNCLen(path, 2))
	}
	return 0
}

// validCredentialVolumeNameLen returns n if path[:n] is a valid Windows volume name.
// If the volume name contains a ".." path component, it returns 0.
func validCredentialVolumeNameLen(path string, n int) int {
	for p := path[:n]; p != ""; {
		var part string
		part, p, _ = cutCredentialPath(p)
		if part == ".." {
			return 0
		}
	}
	return n
}

// credentialPathHasPrefixFold tests whether the path s begins with prefix,
// ignoring case and treating all path separators as equivalent.
// If s is longer than prefix, then s[len(prefix)] must be a path separator.
func credentialPathHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if credentialPathSeparator(prefix[i]) {
			if !credentialPathSeparator(s[i]) {
				return false
			}
		} else if credentialPathUpper(prefix[i]) != credentialPathUpper(s[i]) {
			return false
		}
	}
	if len(s) > len(prefix) && !credentialPathSeparator(s[len(prefix)]) {
		return false
	}
	return true
}

// credentialUNCLen returns the length of the volume prefix of a UNC path.
// prefixLen is the prefix prior to the start of the UNC host;
// for example, for "//host/share", the prefixLen is len("//")==2.
func credentialUNCLen(path string, prefixLen int) int {
	count := 0
	for i := prefixLen; i < len(path); i++ {
		if credentialPathSeparator(path[i]) {
			count++
			if count == 2 {
				return i
			}
		}
	}
	return len(path)
}

// cutCredentialPath slices path around the first path separator.
func cutCredentialPath(path string) (before, after string, found bool) {
	for i := range path {
		if credentialPathSeparator(path[i]) {
			return path[:i], path[i+1:], true
		}
	}
	return path, "", false
}
