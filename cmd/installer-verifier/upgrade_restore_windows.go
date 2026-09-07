//go:build windows

package main

// This embedded pre-file-replacement guard shares the harness function bodies.
// A contract test rejects drift; it never loads the old installed script.
const upgradeRestoreScript = `$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ServiceName = 'RegenBioOverseasAccessAgent'
$DataRoot = 'C:\ProgramData\RegenBio\OverseasAccess'
$TunAlias = 'RegenBioOverseasAccess'
$RuntimeFirewallGroup = 'RegenBioOverseasAccess.Managed'
function Assert-RestorationResponse {
    param([Parameter(Mandatory = $true)] $Response, [Parameter(Mandatory = $true)][string] $RequestId)
    $properties = @($Response.PSObject.Properties.Name)
    if ($properties -notcontains 'id' -or [string]$Response.id -cne $RequestId -or
        ($properties -contains 'error_code' -and -not [string]::IsNullOrEmpty([string]$Response.error_code))) {
        throw 'The agent restoration response has an invalid request ID or error.'
    }
    if ($properties -contains 'version') {
        if ($Response.version -ne 1 -or $properties -notcontains 'status' -or $null -eq $Response.status) {
            throw 'The agent restoration protocol version or status is invalid.'
        }
        $statusProperties = @($Response.status.PSObject.Properties.Name)
        if ($statusProperties -notcontains 'state' -or [string]$Response.status.state -cne 'idle' -or
            ($statusProperties -contains 'error_code' -and -not [string]::IsNullOrEmpty([string]$Response.status.error_code))) {
            throw 'The agent reported that restoration could not be proven.'
        }
    }
    elseif ($properties -notcontains 'state' -or [string]$Response.state -cnotin @('disconnected', 'prepared')) {
        throw 'The agent reported that restoration could not be proven.'
    }
    # These acknowledgements are necessary, not sufficient: callers still run
    # Assert-NetworkRestored against adapters, routes, DNS, firewall and journal.
}

function Read-BoundedPipeFrame {
    param([Parameter(Mandatory = $true)][IO.Stream] $Stream, [int] $TimeoutMilliseconds = 95000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    $buffer = New-Object byte[] 1024
    $frame = New-Object IO.MemoryStream
    try {
        while ($true) {
            $remaining = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if ($remaining -le 0) { throw 'Agent restoration response timed out.' }
            $read = $Stream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $read.Wait($remaining)) { throw 'Agent restoration response timed out.' }
            $count = $read.Result
            if ($count -eq 0) { throw 'Agent restoration response ended without a newline.' }
            for ($index = 0; $index -lt $count; $index++) {
                if ($buffer[$index] -eq 10) {
                    $utf8 = New-Object Text.UTF8Encoding($false, $true)
                    return $utf8.GetString($frame.ToArray()).TrimEnd([char]13)
                }
                if ($frame.Length -ge 65536) { throw 'Agent restoration response exceeds the frame limit.' }
                $frame.WriteByte($buffer[$index])
            }
        }
    }
    finally { $frame.Dispose() }
}

function Request-ControlledDisconnect {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { return }
    if ($service.Status -ne 'Running') {
        # During a major upgrade the new payload is installed but must remain
        # stopped until the cached old MSI finishes its runtime cleanup.
        Assert-NetworkRestored
        return
    }
    $pipe = New-Object IO.Pipes.NamedPipeClientStream('.', 'RegenBioOverseasAccess', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect(5000)
        $writer = New-Object IO.StreamWriter($pipe, (New-Object Text.UTF8Encoding($false)), 1024, $true)
        $writer.AutoFlush = $true
        $requestId = [guid]::NewGuid().ToString('N')
        $writer.WriteLine(([ordered] @{ id = $requestId; action = 'disconnect' } | ConvertTo-Json -Compress))
        # Legacy request supports the installed 0.1.7 service as well as the
        # new service; versioned responses are validated separately if present.
        $response = Read-BoundedPipeFrame -Stream $pipe | ConvertFrom-Json
        Assert-RestorationResponse -Response $response -RequestId $requestId
    }
    catch {
        throw "Refusing to remove the client because controlled restoration could not be proven: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $pipe) { $pipe.Dispose() }
    }
}

function Assert-TunAbsent {
    if (@(Get-NetAdapter -InterfaceAlias $TunAlias -IncludeHidden -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'The owned TUN adapter remains.'
    }
}

function Assert-OwnedRoutesAbsent {
    if (@(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq $TunAlias }).Count -ne 0) {
        throw 'Routes owned by the TUN adapter remain.'
    }
}

function Assert-DnsRestored {
    if (@(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { @($_.ServerAddresses) -contains '172.19.0.2' }).Count -ne 0) {
        throw 'The temporary TUN DNS server remains configured.'
    }
}

function Assert-NetworkRestored {
    Assert-TunAbsent
    Assert-OwnedRoutesAbsent
    Assert-DnsRestored
    $groupRules = @(Get-NetFirewallRule -Group $RuntimeFirewallGroup -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    $enabledRules = @($groupRules | Where-Object { [string]$_.Enabled -eq 'True' })
    if ($enabledRules.Count -ne 0) {
        throw 'Agent restoration could not be proven because runtime firewall rules remain.'
    }
    if (Test-Path -LiteralPath (Join-Path $DataRoot 'network-state.json')) {
        throw 'Agent restoration could not be proven because its state journal remains.'
    }
}

Request-ControlledDisconnect
Assert-NetworkRestored
`

func (windowsTrustVerifier) prepareUpgrade() error {
	return runPowerShell(upgradeRestoreScript)
}
