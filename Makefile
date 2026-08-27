.PHONY: test build

test:
	go test ./...
	pwsh -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester tests/powershell -Output Detailed } else { Invoke-Pester -Script tests/powershell -Verbose }"

build:
	go build -trimpath -o bin/poc-probe.exe ./cmd/poc-probe
