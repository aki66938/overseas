$scriptPath = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\scripts\windows\assert-no-leak.ps1')
)

function Get-NoLeakFailureMessage {
    param([scriptblock] $Action)
    try {
        & $Action
        return $null
    }
    catch {
        return $_.Exception.Message
    }
}

function New-FakeNativeProcess {
    param(
        [int] $ExitCode = 0,
		[bool[]] $WaitResults = @($true),
		[int] $WaitThrowAt = 0,
		[scriptblock] $OnWait = {},
		[bool] $KillThrows = $false
    )
    $process = New-Object PSObject
    $process | Add-Member NoteProperty ExitCode $ExitCode
    $process | Add-Member NoteProperty WaitAction $OnWait
	$process | Add-Member NoteProperty WaitResults @($WaitResults)
	$process | Add-Member NoteProperty WaitThrowAt $WaitThrowAt
	$process | Add-Member NoteProperty WaitCalls 0
	$process | Add-Member NoteProperty KillCalls 0
	$process | Add-Member NoteProperty Exited $false
	$process | Add-Member NoteProperty KillShouldThrow $KillThrows
	$process | Add-Member ScriptProperty HasExited { return [bool] $this.Exited }
    $process | Add-Member ScriptMethod WaitForExit {
        param([int] $Milliseconds)
		$this.WaitCalls++
		$global:NoLeakEvents += "wait:$($this.WaitCalls)"
        & $this.WaitAction
		if ($this.WaitThrowAt -gt 0 -and $this.WaitCalls -eq $this.WaitThrowAt) {
			throw 'injected WaitForExit polling failure'
		}
		if ($this.Exited) {
			return $true
		}
		$index = [Math]::Min($this.WaitCalls - 1, $this.WaitResults.Count - 1)
		$result = [bool] $this.WaitResults[$index]
		if ($result) {
			$this.Exited = $true
		}
		return $result
    }
	$process | Add-Member ScriptMethod Kill {
		$this.KillCalls++
		$global:NoLeakEvents += 'kill'
		if ($this.KillShouldThrow) {
			throw 'injected child kill failure'
		}
		$this.Exited = $true
	}
    return $process
}

function New-TestRoute {
    param([string] $Prefix, [string] $NextHop = '0.0.0.0', [string] $State = 'Alive')
    return [pscustomobject] @{
        DestinationPrefix = $Prefix
        NextHop = $NextHop
        State = $State
    }
}

function Write-FakeNativeExecutable {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $bytes = New-Object byte[] 128
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    [BitConverter]::GetBytes([int] 64).CopyTo($bytes, 0x3c)
    $bytes[64] = 0x50
    $bytes[65] = 0x45
    $bytes[66] = 0
    $bytes[67] = 0
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

Describe 'Windows PoC no-leak orchestration' {
    BeforeEach {
        $global:NoLeakStateRead = 0
        $global:NoLeakAdapterStatuses = @('Down', 'Down', 'Down', 'Up')
        $global:NoLeakRouteSets = @(@(), @(), @(), @((New-TestRoute '0.0.0.0/0' '198.51.100.1')))
        $global:NoLeakProbeExitCode = 0
        $global:NoLeakProbeWaitAction = {}
		$global:NoLeakProbeWaitResults = @($true)
		$global:NoLeakProbeWaitThrowAt = 0
		$global:NoLeakProbeKillThrows = $false
		$global:NoLeakProbeProcess = $null
        $global:NoLeakStartThrows = $false
		$global:NoLeakRouteThrowsAt = -1
        $global:NoLeakPromptCount = 0
		$global:NoLeakEvents = @()
		$global:NoLeakLockObserved = @()

        $configPath = Join-Path $TestDrive 'poc.yaml'
        $outputPath = Join-Path $TestDrive 'probe-telecom-down.json'
        $monitorPath = Join-Path $TestDrive 'probe-telecom-down-monitor.json'
        $probePath = Join-Path $TestDrive 'poc-probe.exe'
        foreach ($path in @($configPath, $outputPath, $monitorPath, $probePath, (Join-Path $TestDrive 'poc-probe.cmd'))) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Remove-Item -LiteralPath $path -Force
            }
        }
        Set-Content -LiteralPath $configPath -Value 'strict config is described by the trusted native binary'
        Write-FakeNativeExecutable -Path $probePath
		$expectedHash = (Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash
        $runId = 'run-pester-no-leak'

        Mock Read-Host {
            $global:NoLeakPromptCount++
			$global:NoLeakEvents += "prompt:$global:NoLeakPromptCount"
            return ''
        }
        Mock Get-NetAdapter {
            $index = [Math]::Min($global:NoLeakStateRead, $global:NoLeakAdapterStatuses.Count - 1)
            return [pscustomobject] @{ Name = 'Telecom-Client'; ifIndex = 11; Status = $global:NoLeakAdapterStatuses[$index] }
        }
        Mock Get-NetRoute {
            $index = [Math]::Min($global:NoLeakStateRead, $global:NoLeakRouteSets.Count - 1)
			if ($global:NoLeakStateRead -eq $global:NoLeakRouteThrowsAt) {
				$global:NoLeakStateRead++
				throw 'injected telecom route polling failure'
			}
            $routes = $global:NoLeakRouteSets[$index]
            $global:NoLeakStateRead++
            return $routes
        }
        Mock Start-Process {
			$writeBlocked = $false
			$writeStream = $null
			try {
				$writeStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
			}
			catch {
				$writeBlocked = $true
			}
			finally {
				if ($null -ne $writeStream) { $writeStream.Dispose() }
			}
			$global:NoLeakLockObserved += $writeBlocked
            if (@($ArgumentList) -contains 'describe-config') {
                $metadata = [ordered] @{
                    telecom_interface = 'Telecom-Client'
                    telecom_route_prefixes = @('0.0.0.0/0')
                    config_digest = ('b' * 64)
                } | ConvertTo-Json -Compress
                Set-Content -LiteralPath $RedirectStandardOutput -Value $metadata
                Set-Content -LiteralPath $RedirectStandardError -Value ''
                return (New-FakeNativeProcess -ExitCode 0)
            }
            if ($global:NoLeakStartThrows) {
                throw 'injected native process start failure'
            }
            $arguments = @($ArgumentList)
            $outputIndex = [Array]::IndexOf($arguments, '--out')
            if ($outputIndex -ge 0 -and $global:NoLeakProbeExitCode -eq 0) {
                Set-Content -LiteralPath $arguments[$outputIndex + 1] -Value '{"schema_version":1}'
            }
			$global:NoLeakProbeProcess = New-FakeNativeProcess -ExitCode $global:NoLeakProbeExitCode -WaitResults $global:NoLeakProbeWaitResults -WaitThrowAt $global:NoLeakProbeWaitThrowAt -OnWait $global:NoLeakProbeWaitAction -KillThrows $global:NoLeakProbeKillThrows
			return $global:NoLeakProbeProcess
        }
    }

    It 'has valid PowerShell syntax and no client automation or secret handling' {
        $tokens = $null
        $errors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $errors.Count | Should Be 0

        $source = Get-Content -LiteralPath $scriptPath -Raw -Encoding UTF8
        $source | Should Match '(?i)Get-FileHash'
        $source | Should Match '(?i)Start-Process'
        $source | Should Match '(?i)WaitForExit'
        $source | Should Not Match '(?i)rasdial|Set-NetAdapter|Disable-NetAdapter|Enable-NetAdapter'
        $source | Should Not Match '(?i)\bpin\b|Get-Credential|password|credential'
    }

    It 'refuses existing create-new evidence before prompting or starting native code' {
        Set-Content -LiteralPath $outputPath -Value 'preserve-me'

        $message = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
        }

        $message | Should Match 'already exists'
        (Get-Content -LiteralPath $outputPath -Raw -Encoding UTF8).Trim() | Should Be 'preserve-me'
        Assert-MockCalled Read-Host -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-Process -Times 0 -Exactly -Scope It
    }

    It 'rejects script wrappers, renamed text, and a mismatched caller-supplied native hash' {
        $wrapperPath = Join-Path $TestDrive 'poc-probe.cmd'
        Set-Content -LiteralPath $wrapperPath -Value '@exit /b 0'

        $wrapperMessage = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $wrapperPath -PocProbeSha256 $expectedHash
        }
        $wrapperMessage | Should Match 'poc-probe.exe'

        Set-Content -LiteralPath $probePath -Value 'Write-Output renamed-script'
        $renamedMessage = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
        }
        $renamedMessage | Should Match 'native Windows executable'

        Write-FakeNativeExecutable -Path $probePath

        $hashMessage = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 ('C' * 64)
        }
        $hashMessage | Should Match 'SHA256'
        Assert-MockCalled Read-Host -Times 0 -Exactly -Scope It
        Assert-MockCalled Start-Process -Times 0 -Exactly -Scope It
    }

    It 'checks only the configured telecom default or external prefixes and accepts unrelated routes' {
        $global:NoLeakAdapterStatuses = @('Up', 'Up', 'Up', 'Up')
        $global:NoLeakRouteSets = @(
            @((New-TestRoute '10.0.0.0/8')),
            @((New-TestRoute '10.0.0.0/8')),
            @((New-TestRoute '10.0.0.0/8')),
            @((New-TestRoute '10.0.0.0/8'), (New-TestRoute '0.0.0.0/0' '198.51.100.1'))
        )

        & $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash

        (Test-Path -LiteralPath $outputPath -PathType Leaf) | Should Be $true
        (Test-Path -LiteralPath $monitorPath -PathType Leaf) | Should Be $true
        $monitor = Get-Content -LiteralPath $monitorPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $monitor.reconnect_detected | Should Be $false
        @($monitor.telecom_route_prefixes).Count | Should Be 1
        @($monitor.telecom_route_prefixes)[0] | Should Be '0.0.0.0/0'
        Assert-MockCalled Get-NetRoute -Times 4 -Exactly -Scope It -ParameterFilter { $InterfaceIndex -eq 11 -and $AddressFamily -eq 'IPv4' -and $PolicyStore -eq 'ActiveStore' }
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter { @($ArgumentList) -contains 'probe' -and @($ArgumentList) -contains '--run-id' }
    }

	It 'holds one deny-write executable lock across both native launches and releases it afterward' {
		& $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash

		@($global:NoLeakLockObserved).Count | Should Be 2
		@($global:NoLeakLockObserved | Where-Object { -not $_ }).Count | Should Be 0
		$releasedStream = [System.IO.File]::Open($probePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
		$releasedStream.Dispose()
	}

	It 'continues monitoring across repeated incomplete waits until the child exits' {
		$global:NoLeakProbeWaitResults = @($false, $false, $true)
		$global:NoLeakAdapterStatuses = @('Down', 'Down', 'Down', 'Down', 'Down', 'Up')
		$global:NoLeakRouteSets = @(
			@(), @(), @(), @(), @(), @((New-TestRoute '0.0.0.0/0' '198.51.100.1'))
		)

		& $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash

		$global:NoLeakProbeProcess.WaitCalls | Should Be 3
		$global:NoLeakProbeProcess.KillCalls | Should Be 0
		$monitor = Get-Content -LiteralPath $monitorPath -Raw -Encoding UTF8 | ConvertFrom-Json
		$monitor.sample_count | Should Be 4
		$monitor.reconnect_detected | Should Be $false
	}

	It 'detects an intermediate automatic reconnect after an incomplete wait and reaps the child before prompting' {
		$global:NoLeakProbeWaitResults = @($false, $false)
		$global:NoLeakAdapterStatuses = @('Down', 'Down', 'Up', 'Up')
		$global:NoLeakRouteSets = @(
			@(), @(), @((New-TestRoute '0.0.0.0/0' '198.51.100.1')), @((New-TestRoute '0.0.0.0/0' '198.51.100.1'))
		)

		$message = Get-NoLeakFailureMessage {
			& $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
		}

		$message | Should Match 'automatically reconnected'
		$global:NoLeakProbeProcess.KillCalls | Should Be 1
		$killIndex = [Array]::IndexOf($global:NoLeakEvents, 'kill')
		$reconnectPromptIndex = [Array]::IndexOf($global:NoLeakEvents, 'prompt:2')
		($killIndex -ge 0 -and $killIndex -lt $reconnectPromptIndex) | Should Be $true
	}

	It 'kills and waits for a live child before reconnect when telecom polling throws' {
		$global:NoLeakProbeWaitResults = @($false, $false)
		$global:NoLeakRouteThrowsAt = 2
		$global:NoLeakAdapterStatuses = @('Down', 'Down', 'Down', 'Up')
		$global:NoLeakRouteSets = @(@(), @(), @(), @((New-TestRoute '0.0.0.0/0' '198.51.100.1')))

		$message = Get-NoLeakFailureMessage {
			& $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
		}

		$message | Should Match 'injected telecom route polling failure'
		$global:NoLeakProbeProcess.KillCalls | Should Be 1
		$global:NoLeakProbeProcess.WaitCalls | Should Be 2
		$killIndex = [Array]::IndexOf($global:NoLeakEvents, 'kill')
		$cleanupWaitIndex = [Array]::LastIndexOf($global:NoLeakEvents, 'wait:2')
		$reconnectPromptIndex = [Array]::IndexOf($global:NoLeakEvents, 'prompt:2')
		($killIndex -lt $cleanupWaitIndex -and $cleanupWaitIndex -lt $reconnectPromptIndex) | Should Be $true
	}

	It 'kills and waits for a live child before reconnect when WaitForExit polling throws' {
		$global:NoLeakProbeWaitThrowAt = 1
		$global:NoLeakAdapterStatuses = @('Down', 'Down', 'Up')
		$global:NoLeakRouteSets = @(@(), @(), @((New-TestRoute '0.0.0.0/0' '198.51.100.1')))

		$message = Get-NoLeakFailureMessage {
			& $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
		}

		$message | Should Match 'injected WaitForExit polling failure'
		$global:NoLeakProbeProcess.KillCalls | Should Be 1
		$global:NoLeakProbeProcess.WaitCalls | Should Be 2
		$global:NoLeakPromptCount | Should Be 2
	}

	It 'still prompts reconnect and releases the lock when cleanup WaitForExit throws' {
		$global:NoLeakProbeWaitResults = @($false, $false)
		$global:NoLeakProbeWaitThrowAt = 2
		$global:NoLeakRouteThrowsAt = 2
		$global:NoLeakAdapterStatuses = @('Down', 'Down', 'Down', 'Up')
		$global:NoLeakRouteSets = @(@(), @(), @(), @((New-TestRoute '0.0.0.0/0' '198.51.100.1')))

		$message = Get-NoLeakFailureMessage {
			& $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
		}

		$message | Should Match 'child cleanup failed'
		$message | Should Match 'WaitForExit polling failure'
		$global:NoLeakProbeProcess.KillCalls | Should Be 1
		$global:NoLeakPromptCount | Should Be 2
		$cleanupWaitIndex = [Array]::IndexOf($global:NoLeakEvents, 'wait:2')
		$reconnectPromptIndex = [Array]::IndexOf($global:NoLeakEvents, 'prompt:2')
		($cleanupWaitIndex -ge 0 -and $cleanupWaitIndex -lt $reconnectPromptIndex) | Should Be $true
		$releasedStream = [System.IO.File]::Open($probePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
		$releasedStream.Dispose()
	}

    It 'handles a native probe failure and still gives the reconnect reminder' {
        $global:NoLeakProbeExitCode = 7

        $message = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
        }

        $message | Should Match 'exit code 7'
        $global:NoLeakPromptCount | Should Be 2
        (Test-Path -LiteralPath $monitorPath -PathType Leaf) | Should Be $true
    }

    It 'closes the process-exit race and records automatic reconnect evidence' {
        $global:NoLeakAdapterStatuses = @('Down', 'Down', 'Up', 'Up')
        $global:NoLeakRouteSets = @(
            @(),
            @(),
            @((New-TestRoute '0.0.0.0/0' '198.51.100.1')),
            @((New-TestRoute '0.0.0.0/0' '198.51.100.1'))
        )

        $message = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
        }

        $message | Should Match 'automatically reconnected'
        $global:NoLeakPromptCount | Should Be 2
        $monitor = Get-Content -LiteralPath $monitorPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $monitor.reconnect_detected | Should Be $true
        $monitor.reconnect_interface_up | Should Be $true
        @($monitor.reconnect_routes).Count | Should Be 1
        @($monitor.reconnect_routes)[0].destination_prefix | Should Be '0.0.0.0/0'
    }

    It 'keeps the reconnect reminder in finally for process-start failure and reports reconnect failure' {
        $global:NoLeakStartThrows = $true
        $global:NoLeakAdapterStatuses = @('Down', 'Down')
        $global:NoLeakRouteSets = @(@(), @())

        $message = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -RunId $runId -OutputPath $outputPath -MonitorOutputPath $monitorPath -PocProbePath $probePath -PocProbeSha256 $expectedHash
        }

        $message | Should Match 'not restored'
        $global:NoLeakPromptCount | Should Be 2
        Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter { @($ArgumentList) -contains 'probe' }
    }
}
