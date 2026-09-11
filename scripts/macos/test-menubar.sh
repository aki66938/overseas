#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
runner="$repo/apps/regen_access/macos/Runner"
tests="$repo/apps/regen_access/macos/Tests"
[[ $(uname -s) == Darwin ]] || { echo 'Native macOS required.' >&2; exit 2; }
[[ $# == 0 || ( $# == 1 && $1 == --interactive ) ]] || exit 2
if [[ $# == 1 && $(id -u) != $(stat -f %u /dev/console) ]]; then
  echo 'Interactive tests must run in the logged-in graphical user session.' >&2
  exit 2
fi
work=$(mktemp -d /private/tmp/regenbio-menubar-tests.XXXXXXXX)
echo "Test artifacts retained: $work"
xcrun swiftc -parse-as-library -Onone "$runner/MenuBarHost.swift" "$tests/MenuBarHostTests.swift" -o "$work/host-tests"
xcrun swiftc -parse-as-library -Onone "$runner/SafeExitState.swift" "$tests/SafeExitStateTests.swift" -o "$work/exit-tests"
"$work/host-tests" "$@"
"$work/exit-tests"
[[ $(/usr/libexec/PlistBuddy -c 'Print :LSUIElement' "$runner/Info.plist") == true ]]
if grep -q '<window ' "$runner/Base.lproj/MainMenu.xib"; then
  echo 'Unexpected standalone nib window.' >&2
  exit 1
fi
echo 'Menu bar host, exit guard and metadata checks passed.'
