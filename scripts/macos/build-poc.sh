#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
if [[ $# != 3 ]]; then
  echo 'Usage: GO=/absolute/go build-poc.sh /absolute/Release.app /absolute/sing-box /absolute/output.dmg' >&2
  exit 2
fi
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { echo 'Build on Apple Silicon macOS.' >&2; exit 1; }
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
app=$1
core=$2
output=$3
go=${GO:-$(command -v go || true)}
[[ -n $go ]] || { echo 'Set GO to the installed native Go executable.' >&2; exit 2; }
source_commit=${SOURCE_COMMIT:-$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)}
[[ $source_commit =~ ^[0-9a-fA-F]{40}$ ]] || { echo 'Set SOURCE_COMMIT to the real full source commit when building from an archive.' >&2; exit 2; }
[[ $app == /* && $core == /* && $output == /* && $go == /* ]] || { echo 'Absolute paths required.' >&2; exit 2; }
[[ ! -e $output && ! -L $output ]] || { echo 'Output already exists; choose a new filename.' >&2; exit 1; }
[[ $(shasum -a 256 "$core" | awk '{print $1}') == 5b75c1dec19488675f725adc7a6e3a7301a553117af835dc47669b1fa918976b ]] || { echo 'Wrong sing-box 1.13.19 arm64 digest.' >&2; exit 1; }
codesign --verify --deep --strict "$app"
work=$(mktemp -d /private/tmp/regenbio-poc-build.XXXXXXXX)
echo "Build staging retained for inspection: $work"
mkdir "$work/image" "$work/image/payload"
payload="$work/image/payload"
ditto "$app" "$payload/RegenBio Access.app"
cp "$core" "$payload/sing-box"
cp "$repo/deploy/client/Telecom-GoMITM-Root.cer" "$payload/Telecom-GoMITM-Root.cer"
cd "$repo"
"$go" build -trimpath -o "$payload/regen-access-service" ./cmd/regen-access-service
"$go" build -trimpath -o "$payload/regen-access" ./cmd/regen-access
"$go" build -trimpath -o "$payload/regen-access-installer" ./scripts/macos/installer
for binary in regen-access-service regen-access regen-access-installer; do
  codesign --force --sign - "$payload/$binary"
  codesign --verify --strict "$payload/$binary"
done
chmod 755 "$payload/sing-box" "$payload/regen-access-service" "$payload/regen-access" "$payload/regen-access-installer"
"$payload/regen-access-installer" policy > "$payload/policy.json"
"$payload/regen-access-installer" manifest "$payload" > "$payload/manifest.json"
cp "$repo/scripts/macos/Install.command" "$work/image/Install.command"
cp "$repo/scripts/macos/Uninstall.command" "$work/image/Uninstall.command"
cp "$repo/deploy/macos/README.md" "$work/image/README.md"
chmod 755 "$work/image/Install.command" "$work/image/Uninstall.command"
printf '%s\n' "$source_commit" > "$work/image/SOURCE-COMMIT.txt"
hdiutil create -volname 'RegenBio Access PoC' -srcfolder "$work/image" -format UDZO "$output"
shasum -a 256 "$output"
echo 'DMG ready. No live installation or network changes performed.'
