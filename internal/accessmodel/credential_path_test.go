package accessmodel

import "testing"

var credentialPathCases = []struct {
	path string
	want bool
}{
	{`C:\ProgramData\RegenBio\credential.bin`, true},
	{`c:/ProgramData/RegenBio/credential.bin`, true},
	{`C:\`, true},
	{`\\server\share\credential.bin`, true},
	{`//server/share/credential.bin`, true},
	{`\\?\C:\ProgramData\credential.bin`, true},
	{`\\?\UNC\server\share\credential.bin`, true},
	{`\\.\C:\credential.bin`, true},
	{`\??\C:\credential.bin`, true},
	{``, false},
	{`credential.bin`, false},
	{`..\credential.bin`, false},
	{`C:credential.bin`, false},
	{`C:`, false},
	{`\credential.bin`, false},
	{`/var/lib/regen/credential.bin`, false},
	{`\\..\share\credential.bin`, false},
	{`\\server\..\credential.bin`, false},
	{`\\?\UNC\server\..\credential.bin`, false},
	{`\??\C:`, false},
}

func TestCredentialPathUsesWindowsStorageSemantics(t *testing.T) {
	for _, test := range credentialPathCases {
		t.Run(test.path, func(t *testing.T) {
			if got := windowsCredentialPathIsAbs(test.path); got != test.want {
				t.Fatalf("Windows storage absolute(%q) = %v, want %v", test.path, got, test.want)
			}
			policy := Policy{SchemaVersion: 1, Mode: "poc", BlockUDP: true, BlockQUIC: true,
				Nodes: []Node{{ID: "vm101", Address: "172.20.9.15", Port: 18443}}, CorporateCIDRs: []string{"172.20.8.0/22"},
				Credential: CredentialRef{Kind: "dpapi-file", Path: test.path}}
			if err := Validate(policy); (err == nil) != test.want {
				t.Fatalf("Validate Windows credential %q: %v", test.path, err)
			}
			if policy.Credential.Path != test.path {
				t.Fatal("validation rewrote credential path")
			}
		})
	}
}
