GO ?= go

.PHONY: test build generate-client-resources build-client verify-client-manifest

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
