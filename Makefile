GO ?= go

.PHONY: test build

test:
	$(GO) test ./...
	pwsh -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester tests/powershell -Output Detailed } else { Invoke-Pester -Script tests/powershell -Verbose }"

build:
	$(GO) build -trimpath -o bin/poc-probe.exe ./cmd/poc-probe
