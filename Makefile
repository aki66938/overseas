GO ?= go

.PHONY: test build
.PHONY: generate-client-resources build-client verify-client-manifest build-server-service package-server-service test-server-install

test:
	$(GO) test ./...
	pwsh -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester tests/powershell -Output Detailed } else { Invoke-Pester -Script tests/powershell -Verbose }"

build:
	$(GO) build -trimpath -o bin/poc-probe.exe ./cmd/poc-probe

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
