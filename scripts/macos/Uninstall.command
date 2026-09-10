#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
printf '%s\n' 'This disconnects RegenBio Access, verifies recovery, and removes its active installation.' \
 'Backups and runtime locks are retained. Exact preexisting traffic CA trust is preserved.'
read -r -p 'Type UNINSTALL to continue: ' approval
[[ $approval == UNINSTALL ]] || { echo 'Cancelled.'; exit 1; }
/usr/bin/sudo -- '/Library/Application Support/RegenBioAccess/regen-access-installer' uninstall
read -r -p 'Press Return to close. ' ignored
