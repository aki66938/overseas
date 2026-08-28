GO ?= go
WIX ?= wix
WIX_UTIL_EXT ?= WixToolset.Util.wixext/4.0.6
WIX_FIREWALL_EXT ?= WixToolset.Firewall.wixext/4.0.6
CLIENT_PAYLOAD_DIR ?= build/msi
CLIENT_MSI ?= dist/OverseasAccessSetup.msi
DTF ?= WixToolset.Dtf.WindowsInstaller.dll
SIGNTOOL ?= signtool.exe
SIGNING_CERT_THUMBPRINT ?=

.PHONY: test build
.PHONY: msi release-msi inspect-msi prepare-client-payload build-client-binaries
.PHONY: generate-client-resources build-client verify-client-manifest build-server-service package-server-service test-server-install test-client-install

test:
	$(GO) test ./...
	pwsh -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester tests/powershell -Output Detailed } else { Invoke-Pester -Script tests/powershell -Verbose }"

build:
	$(MAKE) build-client-binaries
	$(GO) build -trimpath -o bin/poc-probe.exe ./cmd/poc-probe

build-client-binaries: generate-client-resources
	pwsh -NoProfile -Command "$$env:GOOS='windows'; $$env:GOARCH='amd64'; & '$(GO)' build -trimpath -o bin/overseas-agent.exe ./cmd/overseas-agent; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }; & '$(GO)' build -trimpath -ldflags '-H windowsgui' -o bin/overseas-client.exe ./cmd/overseas-client; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }; & '$(GO)' build -trimpath -o bin/credential-provisioner.exe ./cmd/credential-provisioner; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }; & '$(GO)' build -trimpath -o bin/installer-verifier.exe ./cmd/installer-verifier; exit $$LASTEXITCODE"

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
	pwsh -NoProfile -File scripts/windows/build-client-artifacts.ps1 -Mode Inspect -OutputDirectory '$(CLIENT_PAYLOAD_DIR)'

msi: prepare-client-payload
	pwsh -NoProfile -Command "New-Item -ItemType Directory -Path (Split-Path -Parent '$(CLIENT_MSI)') -Force | Out-Null; & '$(WIX)' build deploy/client/Product.wxs deploy/client/Files.wxs -bindpath '$(CLIENT_PAYLOAD_DIR)' -arch x64 -ext '$(WIX_UTIL_EXT)' -ext '$(WIX_FIREWALL_EXT)' -intermediateFolder build/wixobj -pdbtype none -out '$(CLIENT_MSI)'; exit $$LASTEXITCODE"

inspect-msi: msi
	pwsh -NoProfile -File scripts/windows/inspect-client-msi.ps1 -MsiPath '$(CLIENT_MSI)' -StagingPath '$(CLIENT_PAYLOAD_DIR)' -WixPath '$(WIX)' -DtfPath '$(DTF)'

release-msi: build-client-binaries
	pwsh -NoProfile -Command "if ('$(SIGNING_CERT_THUMBPRINT)' -notmatch '^[A-Fa-f0-9]{40}$$') { throw 'SIGNING_CERT_THUMBPRINT is required for release-msi.' }"
	pwsh -NoProfile -File scripts/windows/build-client-artifacts.ps1 -Mode Release -OutputDirectory '$(CLIENT_PAYLOAD_DIR)' -SigningCertificateThumbprint '$(SIGNING_CERT_THUMBPRINT)' -SignToolPath '$(SIGNTOOL)'
	pwsh -NoProfile -Command "New-Item -ItemType Directory -Path (Split-Path -Parent '$(CLIENT_MSI)') -Force | Out-Null; & '$(WIX)' build deploy/client/Product.wxs deploy/client/Files.wxs -d CorporateSigningThumbprint='$(SIGNING_CERT_THUMBPRINT)' -d PackageTrustMode='RELEASE_SIGNED' -bindpath '$(CLIENT_PAYLOAD_DIR)' -arch x64 -ext '$(WIX_UTIL_EXT)' -ext '$(WIX_FIREWALL_EXT)' -intermediateFolder build/wixobj-release -pdbtype none -out '$(CLIENT_MSI)'; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }; & '$(SIGNTOOL)' sign /fd SHA256 /sha1 '$(SIGNING_CERT_THUMBPRINT)' '$(CLIENT_MSI)'; exit $$LASTEXITCODE"
	pwsh -NoProfile -File scripts/windows/inspect-client-msi.ps1 -MsiPath '$(CLIENT_MSI)' -StagingPath '$(CLIENT_PAYLOAD_DIR)' -WixPath '$(WIX)' -DtfPath '$(DTF)'
