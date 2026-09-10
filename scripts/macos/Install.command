#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
cd "$(dirname "$0")"
package=$(pwd -P)
printf '%s\n' 'RegenBio Access macOS internal PoC (Apple Silicon)' \
 'This installs a root background service and the bundled GUI, core and fixed node policy.' \
 'Traffic CA: Telecom GoMITM Root. This permits the configured corporate gateway to inspect HTTPS traffic.' \
 'This is NOT the application-signing certificate. TLS verification remains enabled.' \
 'SHA256: 0D344A6F39FD4252C96F0E5606E2F4E7205CB2E59C44603C542AA8C132A711F8' \
 'Exact preexisting CA trust is preserved. A newly installed CA is recorded for removal on uninstall.' \
 'Enter the existing LOCAL DAILY username (not the SSH maintenance account).'
read -r -p 'Daily username: ' owner
read -r -p 'Type TRUST to approve this traffic CA and installation: ' approval
[[ $approval == TRUST ]] || { echo 'Cancelled.'; exit 1; }
/usr/bin/sudo -- "$package/payload/regen-access-installer" install --payload "$package/payload" --owner "$owner" --accept-ca 0d344a6f39fd4252c96f0e5606e2f4e7205cb2e59c44603c542aa8c132a711f8
printf '%s\n' 'Installation complete. As the selected daily user, open:' '/Library/Application Support/RegenBioAccess/RegenBio Access.app'
read -r -p 'Press Return to close. ' ignored
