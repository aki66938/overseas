GO ?= go
WIX ?= wix
WIX_UTIL_EXT ?= WixToolset.Util.wixext/4.0.6
WIX_FIREWALL_EXT ?= WixToolset.Firewall.wixext/4.0.6
CLIENT_PAYLOAD_DIR ?= build/msi
CLIENT_MSI ?= dist/OverseasAccessSetup.msi

.PHONY: test build
.PHONY: msi inspect-msi prepare-client-payload build-client-binaries
.PHONY: generate-client-resources build-client verify-client-manifest build-server-service package-server-service test-server-install test-client-install

test:
	$(GO) test ./...
	pwsh -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester tests/powershell -Output Detailed } else { Invoke-Pester -Script tests/powershell -Verbose }"

build:
	$(MAKE) build-client-binaries
	$(GO) build -trimpath -o bin/poc-probe.exe ./cmd/poc-probe

build-client-binaries: generate-client-resources
	pwsh -NoProfile -Command "$$env:GOOS='windows'; $$env:GOARCH='amd64'; & '$(GO)' build -trimpath -o bin/overseas-agent.exe ./cmd/overseas-agent; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }; & '$(GO)' build -trimpath -ldflags '-H windowsgui' -o bin/overseas-client.exe ./cmd/overseas-client; exit $$LASTEXITCODE"

generate-client-resources:
	$(GO) generate ./cmd/overseas-client

build-client: generate-client-resources
	$(GO) build -trimpath -ldflags "-H windowsgui" -o bin/overseas-client.exe ./cmd/overseas-client

verify-client-manifest:
	pwsh -NoProfile -File scripts/windows/verify-overseas-client-manifest.ps1 -Path bin/overseas-client.exe

build-server-service:
	$(GO) build -trimpath -o bin/overseas-server-service.exe ./cmd/overseas-server-service

package-server-service: build-server-service
	pwsh -NoProfile -File scripts/windows/package-server-service.ps1 -BundlePath bin/sing-box -ServicePath bin/overseas-server-service.exe

test-server-install:
	powershell.exe -NoProfile -Command "$$result = Invoke-Pester -Script tests/powershell/ServerInstall.Tests.ps1 -PassThru; if ($$result.FailedCount -ne 0) { exit 1 }"
	pwsh -NoProfile -Command "$$result = Invoke-Pester -Script tests/powershell/ServerInstall.Tests.ps1 -PassThru; if ($$result.FailedCount -ne 0) { exit 1 }"

test-client-install:
	powershell.exe -NoProfile -Command "$$result = Invoke-Pester -Script tests/powershell/ClientInstall.Tests.ps1 -PassThru; if ($$result.('Failed'+'Count') -ne 0) { exit 1 }"
	pwsh -NoProfile -Command "$$result = Invoke-Pester -Script tests/powershell/ClientInstall.Tests.ps1 -PassThru; if ($$result.('Failed'+'Count') -ne 0) { exit 1 }"

prepare-client-payload: build-client-binaries
	pwsh -NoProfile -Command "$$repo=(Resolve-Path '.').Path; $$target=[IO.Path]::GetFullPath('$(CLIENT_PAYLOAD_DIR)'); if (-not $$target.StartsWith($$repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe client payload target.' }; if (Test-Path -LiteralPath $$target) { Remove-Item -LiteralPath $$target -Recurse -Force }; New-Item -ItemType Directory -Path $$target -Force | Out-Null; $$coreArchive='artifacts/sing-box-1.13.19-windows-amd64.zip'; if ((Get-FileHash -LiteralPath $$coreArchive -Algorithm SHA256).Hash -ne 'E011A4DEF2F5E2B143ED54ADB2B1A20A6BE407806AB4442F3667F1DD817A2C8D') { throw 'Pinned sing-box archive hash mismatch.' }; $$tunArchive='artifacts/wintun-0.14.1.zip'; if ((Get-FileHash -LiteralPath $$tunArchive -Algorithm SHA256).Hash -ne '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51') { throw 'Pinned Wintun archive hash mismatch.' }; $$scratch=Join-Path $$target '.extract'; Expand-Archive -LiteralPath $$coreArchive -DestinationPath (Join-Path $$scratch 'core'); Expand-Archive -LiteralPath $$tunArchive -DestinationPath (Join-Path $$scratch 'tun'); Copy-Item -LiteralPath bin/overseas-agent.exe,bin/overseas-client.exe,deploy/client/agent.yaml,deploy/client/agent.yaml.p7s,deploy/client/install-client.ps1,sing-box.manifest.json -Destination $$target; Copy-Item -LiteralPath (Join-Path $$scratch 'core/sing-box-1.13.19-windows-amd64/sing-box.exe'),(Join-Path $$scratch 'core/sing-box-1.13.19-windows-amd64/libcronet.dll'),(Join-Path $$scratch 'core/sing-box-1.13.19-windows-amd64/LICENSE') -Destination $$target; Copy-Item -LiteralPath (Join-Path $$scratch 'tun/wintun/bin/amd64/wintun.dll') -Destination $$target; $$signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $$target 'wintun.dll'); if ($$signature.Status -ne 'Valid') { throw 'Wintun Authenticode verification failed.' }; Remove-Item -LiteralPath $$scratch -Recurse -Force"

msi: prepare-client-payload
	pwsh -NoProfile -Command "New-Item -ItemType Directory -Path (Split-Path -Parent '$(CLIENT_MSI)') -Force | Out-Null; & '$(WIX)' build deploy/client/Product.wxs deploy/client/Files.wxs -bindpath '$(CLIENT_PAYLOAD_DIR)' -arch x64 -ext '$(WIX_UTIL_EXT)' -ext '$(WIX_FIREWALL_EXT)' -intermediateFolder build/wixobj -pdbtype none -out '$(CLIENT_MSI)'; exit $$LASTEXITCODE"

inspect-msi: msi
	pwsh -NoProfile -Command "$$repo=(Resolve-Path '.').Path; $$extract=[IO.Path]::GetFullPath('build/msi-inspect'); if (-not $$extract.StartsWith($$repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe MSI inspection target.' }; if (Test-Path -LiteralPath $$extract) { Remove-Item -LiteralPath $$extract -Recurse -Force }; New-Item -ItemType Directory -Path $$extract -Force | Out-Null; & '$(WIX)' msi decompile -x (Join-Path $$extract 'files') -o (Join-Path $$extract 'decompiled.wxs') '$(CLIENT_MSI)'; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }; $$forbidden='BEGIN (RSA |EC )?PRIVATE KEY|\.pfx|\.pem|CleartextCredential'; if (Select-String -Path (Join-Path $$extract 'decompiled.wxs') -Pattern $$forbidden -CaseSensitive:$$false -Quiet) { throw 'Forbidden secret material found in MSI inspection.' }; $$payloadIds=@((Get-ChildItem -LiteralPath (Join-Path $$extract 'files/File') -File).Name | Sort-Object); $$expected=@('AgentExe','AgentPolicy','AgentPolicySignature','ClientExe','CoreManifest','CronetRuntime','InstallerHarnessFile','SingBoxExe','ThirdPartyLicense','TunDriver'); $$expected=@($$expected | Sort-Object); if (Compare-Object $$expected $$payloadIds) { throw 'MSI payload allowlist mismatch.' }; Get-FileHash -LiteralPath '$(CLIENT_MSI)' -Algorithm SHA256"
