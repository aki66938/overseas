package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "policy" {
		fmt.Println(fixedPolicy)
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "manifest" {
		m, e := makeManifest(os.Args[2])
		if e == nil {
			var b []byte
			b, e = json.MarshalIndent(m, "", "  ")
			if e == nil {
				fmt.Println(string(b))
				return
			}
		}
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if e := runPlatform(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "RegenBio PoC:", e)
		os.Exit(1)
	}
}

type receipt struct {
	Version  int    `json:"version"`
	OwnerUID int    `json:"owner_uid"`
	CAAdded  bool   `json:"ca_added"`
	CASHA256 string `json:"ca_sha256"`
}

func shouldRemoveCA(r receipt) bool { return r.CAAdded && r.CASHA256 == caDigest }
func launchPlist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.regenbio.access.poc</string>
<key>ProgramArguments</key><array><string>/Library/Application Support/RegenBioAccess/regen-access-service</string></array>
<key>UserName</key><string>root</string><key>GroupName</key><string>wheel</string>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>AbandonProcessGroup</key><false/><key>ExitTimeOut</key><integer>100</integer>
<key>ThrottleInterval</key><integer>10</integer><key>Umask</key><integer>63</integer>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
<key>WorkingDirectory</key><string>/Library/Application Support/RegenBioAccess</string>
</dict></plist>
`
}
