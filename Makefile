LOCKED_CLIENT_TOOL := scripts/windows/invoke-locked-client-tool.ps1
CLIENT_PAYLOAD_DIR ?= build/msi
CLIENT_MSI ?= dist/OverseasAccessSetup.msi
CLIENT_RELEASE_MSI ?= dist/OverseasAccessSetup-RELEASE_SIGNED.msi
SIGNTOOL ?= signtool.exe
SIGNING_CERT_THUMBPRINT ?=

.PHONY: test build
.PHONY: test-integration-preflight test-integration-live build-integration-fixtures
.PHONY: msi release-msi inspect-msi prepare-client-payload build-client-binaries
.PHONY: generate-client-resources build-client verify-client-manifest build-server-service package-server-service test-server-install test-client-install

test:
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -ToolArguments @('test','./...'); exit $$LASTEXITCODE"
	pwsh -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester tests/powershell -Output Detailed } else { Invoke-Pester -Script tests/powershell -Verbose }"

test-integration-preflight:
	pwsh -NoProfile -Command "Remove-Item Env:OVERSEAS_ACCESS_INTEGRATION -ErrorAction SilentlyContinue; & '$(LOCKED_CLIENT_TOOL)' -Tool Go -ToolArguments @('test','-count=1','./tests/integration'); exit $$LASTEXITCODE"

test-integration-live:
	pwsh -NoProfile -Command "if ($$env:OVERSEAS_ACCESS_INTEGRATION -ne '1') { throw 'Set OVERSEAS_ACCESS_INTEGRATION=1 explicitly before invoking the live target.' }; & '$(LOCKED_CLIENT_TOOL)' -Tool Go -ToolArguments @('test','-count=1','-v','./tests/integration'); exit $$LASTEXITCODE"

build-integration-fixtures:
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -GoOS windows -GoArch amd64 -ToolArguments @('build','-trimpath','-o','bin/overseas-access-integration-driver.exe','./tests/integration/fixturedriver'); exit $$LASTEXITCODE"
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -GoOS windows -GoArch amd64 -ToolArguments @('build','-trimpath','-o','bin/fixture-sentinel.exe','./tests/integration/fixtureserver'); exit $$LASTEXITCODE"
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -GoOS windows -GoArch amd64 -ToolArguments @('build','-trimpath','-o','bin/fixture-action.exe','./tests/integration/fixtureaction'); exit $$LASTEXITCODE"

build:
	$(MAKE) build-client-binaries
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -ToolArguments @('build','-trimpath','-o','bin/poc-probe.exe','./cmd/poc-probe'); exit $$LASTEXITCODE"

build-client-binaries: generate-client-resources
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -GoOS windows -GoArch amd64 -ToolArguments @('build','-trimpath','-o','bin/overseas-agent.exe','./cmd/overseas-agent'); exit $$LASTEXITCODE"
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -GoOS windows -GoArch amd64 -ToolArguments @('build','-trimpath','-ldflags','-H windowsgui','-o','bin/overseas-client.exe','./cmd/overseas-client'); exit $$LASTEXITCODE"
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -GoOS windows -GoArch amd64 -ToolArguments @('build','-trimpath','-o','bin/credential-provisioner.exe','./cmd/credential-provisioner'); exit $$LASTEXITCODE"
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -GoOS windows -GoArch amd64 -ToolArguments @('build','-trimpath','-o','bin/installer-verifier.exe','./cmd/installer-verifier'); exit $$LASTEXITCODE"

generate-client-resources:
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -ToolArguments @('generate','./cmd/overseas-client'); exit $$LASTEXITCODE"

build-client: generate-client-resources
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -ToolArguments @('build','-trimpath','-ldflags','-H windowsgui','-o','bin/overseas-client.exe','./cmd/overseas-client'); exit $$LASTEXITCODE"

verify-client-manifest:
	pwsh -NoProfile -File scripts/windows/verify-overseas-client-manifest.ps1 -Path bin/overseas-client.exe

build-server-service:
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Go -ToolArguments @('build','-trimpath','-o','bin/overseas-server-service.exe','./cmd/overseas-server-service'); exit $$LASTEXITCODE"

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
	pwsh -NoProfile -Command "New-Item -ItemType Directory -Path (Split-Path -Parent '$(CLIENT_MSI)') -Force | Out-Null"
	pwsh -NoProfile -Command "& '$(LOCKED_CLIENT_TOOL)' -Tool Wix -ToolArguments @('build','deploy/client/Product.wxs','deploy/client/Files.wxs','-bindpath','$(CLIENT_PAYLOAD_DIR)','-arch','x64','-intermediateFolder','build/wixobj','-pdbtype','none','-out','$(CLIENT_MSI)'); exit $$LASTEXITCODE"

inspect-msi: msi
	pwsh -NoProfile -File scripts/windows/inspect-client-msi.ps1 -MsiPath '$(CLIENT_MSI)' -StagingPath '$(CLIENT_PAYLOAD_DIR)'

release-msi:
	pwsh -NoProfile -Command "if ('$(SIGNING_CERT_THUMBPRINT)' -notmatch '^[A-Fa-f0-9]{40}$$') { throw 'SIGNING_CERT_THUMBPRINT is required for release-msi.' }"
	pwsh -NoProfile -File scripts/windows/publish-client-release.ps1 -SigningCertificateThumbprint '$(SIGNING_CERT_THUMBPRINT)' -SignToolPath '$(SIGNTOOL)' -FinalMsiPath '$(CLIENT_RELEASE_MSI)'
