//go:build windows

package agent

import (
	"context"
	"errors"
	"sort"
)

func (m *WindowsNetworkManager) preparedFirewallInput(state WindowsPreparedState, includeEmergency bool) windowsNetworkInput {
	rules := canonicalPreparedRules(state.Rules)
	if !includeEmergency {
		filtered := rules[:0]
		for _, rule := range rules {
			if !rule.Emergency {
				filtered = append(filtered, rule)
			}
		}
		rules = filtered
	}
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, rule.Name)
	}
	sort.Strings(names)
	blocked := state.BlockedRemoteAddresses
	if len(blocked) == 0 {
		blocked = m.blockedPrefixes
	}
	dnsBlocked := state.DNSBlockedRemoteAddresses
	if len(dnsBlocked) == 0 {
		dnsBlocked = m.dnsBlockedPrefixes
	}
	return windowsNetworkInput{
		FirewallRuleNames: names, FirewallGroup: windowsFirewallGroup,
		BlockedRemoteAddresses:    append([]string(nil), blocked...),
		DNSBlockedRemoteAddresses: append([]string(nil), dnsBlocked...),
		PreparedRules:             rules, PreparedGeneration: state.Generation,
		RuleDefinitionVersion: state.RuleDefinitionVersion,
	}
}

func (m *WindowsNetworkManager) prepareFirewallPool(ctx context.Context, state WindowsPreparedState, previous ...WindowsPreparedState) error {
	input := m.preparedFirewallInput(state, true)
	if len(previous) > 1 {
		return errors.New("at most one previous prepared firewall generation is allowed")
	}
	if len(previous) == 1 {
		input.PreviousPreparedRules = canonicalPreparedRules(previous[0].Rules)
		input.PreviousPreparedGeneration = previous[0].Generation
		input.PreviousRuleDefinitionVersion = previous[0].RuleDefinitionVersion
		input.PreviousBlockedRemoteAddresses = append([]string(nil), previous[0].BlockedRemoteAddresses...)
		input.PreviousDNSBlockedRemoteAddresses = append([]string(nil), previous[0].DNSBlockedRemoteAddresses...)
	}
	if _, err := m.run(ctx, networkOperationFirewallPrepare, input); err != nil {
		emergencyContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), windowsEmergencyTimeout)
		defer cancel()
		if len(previous) == 1 {
			if previousEmergencyErr := m.installPreparedEmergencyProtection(emergencyContext, previous[0]); previousEmergencyErr == nil {
				return err
			}
		}
		return errors.Join(err, m.installPreparedEmergencyProtection(emergencyContext, state))
	}
	return nil
}

func (m *WindowsNetworkManager) installPreparedEmergencyProtection(ctx context.Context, state WindowsPreparedState) error {
	_, err := m.run(ctx, networkOperationEmergency, m.preparedFirewallInput(state, true))
	return err
}

// armPreparedFirewall enables the pool and proves the active store in a
// single PowerShell transaction.
func (m *WindowsNetworkManager) armPreparedFirewall(ctx context.Context, state WindowsPreparedState) error {
	// includeEmergency: the script arms only the normal rules but ends by
	// proving the emergency rule is present and still disabled.
	_, err := m.run(ctx, networkOperationFirewallArm, m.preparedFirewallInput(state, true))
	return err
}

func (m *WindowsNetworkManager) disablePreparedFirewall(ctx context.Context, state WindowsPreparedState) error {
	_, err := m.run(ctx, networkOperationFirewallDisable, m.preparedFirewallInput(state, true))
	return err
}

func (m *WindowsNetworkManager) auditPreparedFirewall(ctx context.Context, state WindowsPreparedState, connected bool) error {
	state.Rules = canonicalPreparedRules(state.Rules)
	for index := range state.Rules {
		state.Rules[index].ExpectedEnabled = connected && !state.Rules[index].Emergency
	}
	_, err := m.run(ctx, networkOperationFirewallAudit, m.preparedFirewallInput(state, true))
	return err
}

// Prepared firewall operations: firewall_prepare, firewall_enable,
// firewall_verify, firewall_disable, firewall_audit.
const preparedFirewallPowerShellHelpers = `function Normalize-PreparedToken($value) {
  $text = ([string]$value).Trim().ToLowerInvariant()
  if ($text -match '^(?<address>\d{1,3}(?:\.\d{1,3}){3})/(?<mask>\d{1,3}(?:\.\d{1,3}){3})$') {
    $address = [string]$Matches.address
    $maskOctets = @(([string]$Matches.mask).Split('.') | ForEach-Object { [int]$_ })
    $prefixLength = 0; $seenZero = $false
    foreach ($octet in $maskOctets) {
      if ($octet -lt 0 -or $octet -gt 255) { return $text }
      for ($bit = 7; $bit -ge 0; $bit--) {
        if (($octet -band (1 -shl $bit)) -ne 0) { if ($seenZero) { return $text }; $prefixLength++ } else { $seenZero = $true }
      }
    }
    if ($prefixLength -eq 32) { return $address }
    return ($address + '/' + [string]$prefixLength)
  }
  if ($text -match '^(?<address>\d{1,3}(?:\.\d{1,3}){3})/32$') { return [string]$Matches.address }
  if ($text -match '^(?<address>[^/]*:[^/]*)/128$') { return [string]$Matches.address }
  return $text
}
function Assert-PreparedSet([string]$label, $actual, $expected, [bool]$addresses) {
  if ($addresses) {
    $left = @($actual | ForEach-Object { Normalize-PreparedToken $_ } | Sort-Object -Unique)
    $right = @($expected | ForEach-Object { Normalize-PreparedToken $_ } | Sort-Object -Unique)
  } else {
    $left = @($actual | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $right = @($expected | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
  }
  if ($left.Count -ne $right.Count -or [string]::Join('|',$left) -ne [string]::Join('|',$right)) { throw ('prepared_firewall: ' + $label + ' mismatch.') }
}
function Get-PreparedDescriptionFor($expected, [uint64]$generation, [int]$version) {
  return ('RegenBioOwned;v=' + [string]$version + ';g=' + [string]$generation + ';sha=' + [string]$expected.RemoteAddressesSHA + ';emergency=' + ([bool]$expected.Emergency).ToString().ToLowerInvariant())
}
function Get-PreparedDescription($expected) {
  return (Get-PreparedDescriptionFor $expected ([uint64]$i.PreparedGeneration) ([int]$i.RuleDefinitionVersion))
}
function Get-PreparedRemoteFor($expected, $blocked, $dnsBlocked) {
  if ([bool]$expected.Emergency -or [string]$expected.Protocol -eq 'Any') { return @($blocked) }
  return @($dnsBlocked)
}
function Get-PreparedRemote($expected) {
  return @(Get-PreparedRemoteFor $expected @($i.BlockedRemoteAddresses | Where-Object { $null -ne $_ }) @($i.DNSBlockedRemoteAddresses | Where-Object { $null -ne $_ }))
}
function Get-PreparedAliases($expected) {
  if (-not [string]::IsNullOrWhiteSpace([string]$expected.InterfaceAlias)) { return @([string]$expected.InterfaceAlias) }
  return @($expected.InterfaceAliases | Where-Object { $null -ne $_ })
}
function Assert-PreparedRuleFor($expected, [string]$policyStore, [string]$enabled, [uint64]$generation, [int]$version, $blocked, $dnsBlocked) {
  $rules = @(Get-NetFirewallRule -PolicyStore $policyStore -Name ([string]$expected.Name) -ErrorAction SilentlyContinue)
  if ($rules.Count -ne 1) { throw ('prepared_firewall: expected exactly one rule named ' + [string]$expected.Name + '.') }
  $rule = $rules[0]
  if ([string]$rule.Group -ne [string]$i.FirewallGroup -or [string]$rule.Direction -ne 'Outbound' -or [string]$rule.Action -ne 'Block' -or [string]$rule.Enabled -ne $enabled -or [string]$rule.Description -ne (Get-PreparedDescriptionFor $expected $generation $version)) { throw ('prepared_firewall: metadata mismatch for ' + [string]$expected.Name + '.') }
  $port = @($rule | Get-NetFirewallPortFilter)
  if ($port.Count -ne 1 -or [string]$port[0].Protocol -ne [string]$expected.Protocol) { throw ('prepared_firewall: protocol mismatch for ' + [string]$expected.Name + '.') }
  $expectedPorts = @($expected.RemotePorts | Where-Object { $null -ne $_ })
  if ($expectedPorts.Count -eq 0) { $expectedPorts = @('Any') }
  Assert-PreparedSet (([string]$expected.Name) + ' remote ports') @($port[0].RemotePort) $expectedPorts $false
  $address = @($rule | Get-NetFirewallAddressFilter)
  if ($address.Count -ne 1) { throw ('prepared_firewall: address filter is ambiguous for ' + [string]$expected.Name + '.') }
  Assert-PreparedSet (([string]$expected.Name) + ' remote addresses') @($address[0].RemoteAddress) @(Get-PreparedRemoteFor $expected $blocked $dnsBlocked) $true
  $interface = @($rule | Get-NetFirewallInterfaceFilter)
  if ($interface.Count -ne 1) { throw ('prepared_firewall: interface filter is ambiguous for ' + [string]$expected.Name + '.') }
  Assert-PreparedSet (([string]$expected.Name) + ' interface aliases') @($interface[0].InterfaceAlias) @(Get-PreparedAliases $expected) $false
}
function Assert-PreparedRule($expected, [string]$policyStore, [string]$enabled) {
  Assert-PreparedRuleFor $expected $policyStore $enabled ([uint64]$i.PreparedGeneration) ([int]$i.RuleDefinitionVersion) @($i.BlockedRemoteAddresses | Where-Object { $null -ne $_ }) @($i.DNSBlockedRemoteAddresses | Where-Object { $null -ne $_ })
}`

const preparedFirewallPreparePowerShell = preparedFirewallPowerShellHelpers + `
if ([int]$i.RuleDefinitionVersion -ne 2 -or [uint64]$i.PreparedGeneration -eq 0) { throw 'prepared_firewall: invalid definition version or generation.' }
$expectedRules = @($i.PreparedRules | Where-Object { $null -ne $_ })
if ($expectedRules.Count -lt 4) { throw 'prepared_firewall: rule plan is incomplete.' }
$expectedNames = @($expectedRules | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
if ($expectedNames.Count -ne $expectedRules.Count) { throw 'prepared_firewall: duplicate desired rule name.' }
$previousRules = @($i.PreviousPreparedRules | Where-Object { $null -ne $_ })
$previousNames = @($previousRules | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
if ($previousRules.Count -ne 0 -and ($previousNames.Count -ne $previousRules.Count -or [uint64]$i.PreviousPreparedGeneration -eq 0 -or [int]$i.PreviousRuleDefinitionVersion -le 0)) { throw 'prepared_firewall: previous ledger is invalid.' }
$allowedNames = @($expectedNames + $previousNames | Sort-Object -Unique)
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$i.FirewallGroup) -ErrorAction SilentlyContinue)
$unknown = @($rules | Where-Object { $allowedNames -notcontains [string]$_.Name })
if ($unknown.Count -ne 0) { throw 'prepared_firewall: unknown product-group rule exists.' }
# Topology drift tolerance: a ledger rule whose definition no longer matches
# (renamed or vanished adapter aliases, changed prefix sets) is materialized
# and removed so the rebuild recreates it for the current topology. Only
# enabled or ambiguous rules are hostile and fail closed.
$previousValid = @()
$previousDrifted = @()
foreach ($previous in $previousRules) {
  $name = [string]$previous.Name
  $owned = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
  if ($owned.Count -ne 1) { throw ('prepared_firewall: previous rule is ambiguous: ' + $name) }
  if ([string]$owned[0].Group -ne [string]$i.FirewallGroup) { throw ('prepared_firewall: previous rule is unowned: ' + $name) }
  if ([string]$owned[0].Enabled -eq 'True') { throw ('prepared_firewall: previous rule is enabled: ' + $name) }
  $drifted = $false
  try { Assert-PreparedRuleFor $previous 'PersistentStore' 'False' ([uint64]$i.PreviousPreparedGeneration) ([int]$i.PreviousRuleDefinitionVersion) @($i.PreviousBlockedRemoteAddresses | Where-Object { $null -ne $_ }) @($i.PreviousDNSBlockedRemoteAddresses | Where-Object { $null -ne $_ }) } catch { $drifted = $true }
  if ($drifted) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop; $previousDrifted += $previous } else { $previousValid += $previous }
}
$previousEmergency = @($previousValid | Where-Object { [bool]$_.Emergency })
if ($previousValid.Count -ne 0) {
  if ($previousEmergency.Count -ne 1) { throw 'prepared_firewall: previous emergency rule is ambiguous.' }
  Enable-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$previousEmergency[0].Name) -ErrorAction Stop
  Assert-PreparedRuleFor $previousEmergency[0] 'ActiveStore' 'True' ([uint64]$i.PreviousPreparedGeneration) ([int]$i.PreviousRuleDefinitionVersion) @($i.PreviousBlockedRemoteAddresses | Where-Object { $null -ne $_ }) @($i.PreviousDNSBlockedRemoteAddresses | Where-Object { $null -ne $_ })
  $previousNormalNames = @($previousValid | Where-Object { -not [bool]$_.Emergency } | ForEach-Object { [string]$_.Name })
  foreach ($name in $previousNormalNames) {
    $owned = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop)
    if ($owned.Count -ne 1) { throw ('prepared_firewall: previous rule became ambiguous: ' + $name) }
    Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
  }
}
foreach ($expected in @($expectedRules | Where-Object { -not [bool]$_.Emergency })) {
  $name = [string]$expected.Name
  $existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
  if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and [string]$existing[0].Group -ne [string]$i.FirewallGroup)) { throw ('prepared_firewall: rule-name collision for ' + $name + '.') }
  if ($existing.Count -eq 1) { Assert-PreparedRule $expected 'PersistentStore' 'False'; continue }
  $parameters = @{
    PolicyStore='PersistentStore'; Name=$name; DisplayName=$name; Group=[string]$i.FirewallGroup
    Description=(Get-PreparedDescription $expected); Direction='Outbound'; Action='Block'; Enabled='False'
    Protocol=[string]$expected.Protocol; RemoteAddress=@(Get-PreparedRemote $expected)
    InterfaceAlias=@(Get-PreparedAliases $expected); Profile='Any'
  }
  $ports = @($expected.RemotePorts | Where-Object { $null -ne $_ })
  if ($ports.Count -ne 0) { $parameters.RemotePort = $ports }
  New-NetFirewallRule @parameters | Out-Null
  Assert-PreparedRule $expected 'PersistentStore' 'False'
}
$expectedEmergency = @($expectedRules | Where-Object { [bool]$_.Emergency })
if ($expectedEmergency.Count -ne 1) { throw 'prepared_firewall: desired emergency rule is ambiguous.' }
if ($previousValid.Count -ne 0) {
  $oldEmergencyName = [string]$previousEmergency[0].Name
  $ownedEmergency = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $oldEmergencyName -ErrorAction SilentlyContinue)
  if ($ownedEmergency.Count -gt 1) { throw 'prepared_firewall: previous emergency rule became ambiguous.' }
  if ($ownedEmergency.Count -eq 1) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $oldEmergencyName -ErrorAction Stop }
}
$expected = $expectedEmergency[0]
$name = [string]$expected.Name
$existingEmergency = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
if ($existingEmergency.Count -gt 1 -or ($existingEmergency.Count -eq 1 -and [string]$existingEmergency[0].Group -ne [string]$i.FirewallGroup)) { throw ('prepared_firewall: emergency rule-name collision for ' + $name + '.') }
if ($existingEmergency.Count -eq 0) {
  New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group ([string]$i.FirewallGroup) -Description (Get-PreparedDescription $expected) -Direction Outbound -Action Block -Enabled False -Protocol Any -RemoteAddress @(Get-PreparedRemote $expected) -InterfaceAlias @(Get-PreparedAliases $expected) -Profile Any | Out-Null
}
Assert-PreparedRule $expected 'PersistentStore' 'False'
[pscustomobject]@{RuleCount=[int]$expectedRules.Count;DisabledCount=[int]$expectedRules.Count}|ConvertTo-Json -Compress`

const preparedFirewallEnablePowerShell = preparedFirewallPowerShellHelpers + `
$normal = @($i.PreparedRules | Where-Object { -not [bool]$_.Emergency })
if ($normal.Count -eq 0) { throw 'prepared_firewall: normal rule set is empty.' }
foreach ($expected in $normal) { Assert-PreparedRule $expected 'PersistentStore' 'False' }
foreach ($name in @($i.FirewallRuleNames)) {
  $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction SilentlyContinue)
  if ($rule.Count -ne 1 -or [string]$rule[0].Group -ne [string]$i.FirewallGroup) { throw ('prepared_firewall: cannot enable unowned rule ' + [string]$name + '.') }
  Enable-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction Stop
}
foreach ($expected in $normal) { Assert-PreparedRule $expected 'ActiveStore' 'True' }
[pscustomobject]@{EnabledCount=[int]$normal.Count}|ConvertTo-Json -Compress`

// preparedFirewallArmPowerShell enables the pool and verifies the active
// store inside ONE PowerShell session: bulk reads replace per-rule CIM
// round trips (the dominant cost on AV-hooked machines).
const preparedFirewallArmPowerShell = preparedFirewallPowerShellHelpers + `
$normal = @($i.PreparedRules | Where-Object { -not [bool]$_.Emergency })
if ($normal.Count -eq 0) { throw 'prepared_firewall: normal rule set is empty.' }
$names = @($normal | ForEach-Object { [string]$_.Name })
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $names -ErrorAction Stop)
if ($rules.Count -ne $normal.Count) { throw 'prepared_firewall: a normal rule is missing from the persistent store.' }
foreach ($rule in $rules) {
  if ([string]$rule.Group -ne [string]$i.FirewallGroup) { throw ('prepared_firewall: unowned rule ' + [string]$rule.Name + '.') }
  if ([string]$rule.Enabled -ne 'False') { throw ('prepared_firewall: rule ' + [string]$rule.Name + ' is not disabled.') }
}
$expectedByName = @{}
foreach ($expected in $normal) { $expectedByName[[string]$expected.Name] = $expected }
foreach ($rule in $rules) {
  $expected = $expectedByName[[string]$rule.Name]
  if ([string]$rule.Description -ne (Get-PreparedDescription $expected)) { throw ('prepared_firewall: definition drift for ' + [string]$rule.Name + '.') }
}
Enable-NetFirewallRule -PolicyStore PersistentStore -Name $names -ErrorAction Stop
$active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $names -ErrorAction Stop)
if ($active.Count -ne $normal.Count) { throw 'prepared_firewall: enabled rules are not visible in the active store.' }
$activeByName = @{}
foreach ($rule in $active) { $activeByName[[string]$rule.Name] = $rule }
foreach ($expected in $normal) {
  $name = [string]$expected.Name
  $rule = $activeByName[$name]
  if ($null -eq $rule) { throw ('prepared_firewall: ' + $name + ' is not active.') }
  if ([string]$rule.Enabled -ne 'True' -or [string]$rule.Action -ne 'Block' -or [string]$rule.Direction -ne 'Outbound' -or [string]$rule.Group -ne [string]$i.FirewallGroup) { throw ('prepared_firewall: ' + $name + ' metadata mismatch.') }
}
# Pair filters with rules BY NAME: pipelined filter output order is not
# guaranteed to match the piped rule order.
$paired = @($rules | ForEach-Object {
  $r = $_
  $af = @($r | Get-NetFirewallAddressFilter)
  $itf = @($r | Get-NetFirewallInterfaceFilter)
  [pscustomobject]@{ Name = [string]$r.Name; Remote = @($af[0].RemoteAddress); Aliases = @($itf[0].InterfaceAlias) }
})
$addressByName = @{}
$aliasByName = @{}
foreach ($entry in $paired) { $addressByName[$entry.Name] = $entry.Remote; $aliasByName[$entry.Name] = $entry.Aliases }
foreach ($expected in $normal) {
  $name = [string]$expected.Name
  $actualAddresses = @($addressByName[$name] | ForEach-Object { Normalize-PreparedToken $_ } | Sort-Object)
  $expectedAddresses = @(Get-PreparedRemote $expected | ForEach-Object { Normalize-PreparedToken $_ } | Sort-Object)
  if ([string]::Join('|', $actualAddresses) -ne [string]::Join('|', $expectedAddresses)) { throw ('prepared_firewall: ' + $name + ' remote prefixes mismatch.') }
  $actualAliases = @($aliasByName[$name] | Sort-Object)
  $expectedAliases = @(Get-PreparedAliases $expected | Sort-Object)
  if ([string]::Join('|', $actualAliases) -ne [string]::Join('|', $expectedAliases)) { throw ('prepared_firewall: ' + $name + ' interface aliases mismatch.') }
}
$emergency = @($i.PreparedRules | Where-Object { [bool]$_.Emergency })
if ($emergency.Count -ne 1) { throw 'prepared_firewall: emergency rule is ambiguous.' }
$emergencyRule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$emergency[0].Name) -ErrorAction SilentlyContinue)
if ($emergencyRule.Count -ne 1 -or [string]$emergencyRule[0].Enabled -ne 'False') { throw 'prepared_firewall: emergency rule must stay disabled.' }
[pscustomobject]@{EnabledCount=[int]$normal.Count}|ConvertTo-Json -Compress`

const preparedFirewallVerifyPowerShell = preparedFirewallPowerShellHelpers + `
$normal = @($i.PreparedRules | Where-Object { -not [bool]$_.Emergency })
foreach ($expected in $normal) { Assert-PreparedRule $expected 'ActiveStore' 'True' }
$emergency = @($i.PreparedRules | Where-Object { [bool]$_.Emergency })
if ($emergency.Count -ne 1) { throw 'prepared_firewall: emergency rule is ambiguous.' }
Assert-PreparedRule $emergency[0] 'PersistentStore' 'False'
[pscustomobject]@{VerifiedCount=[int]$normal.Count}|ConvertTo-Json -Compress`

const preparedFirewallDisablePowerShell = `
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$i.FirewallGroup) -ErrorAction SilentlyContinue)
$ownedNames = @($i.PreparedRules | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
$unknown = @($rules | Where-Object { $ownedNames -notcontains [string]$_.Name })
if ($unknown.Count -ne 0) { throw 'prepared_firewall: refusing to disable unknown product-group rule.' }
foreach ($name in @($i.FirewallRuleNames)) {
  $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction SilentlyContinue)
  if ($rule.Count -eq 0) { continue }
  if ($rule.Count -ne 1 -or [string]$rule[0].Group -ne [string]$i.FirewallGroup) { throw ('prepared_firewall: cannot disable unowned rule ' + [string]$name + '.') }
  Disable-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction Stop
}
$enabled = @($ownedNames | ForEach-Object { @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $_ -ErrorAction SilentlyContinue) } | Where-Object { [string]$_.Enabled -eq 'True' })
if ($enabled.Count -ne 0) { throw 'prepared_firewall: an owned rule remains enabled.' }
[pscustomobject]@{DisabledCount=[int]$ownedNames.Count}|ConvertTo-Json -Compress`

const preparedFirewallAuditPowerShell = preparedFirewallPowerShellHelpers + `
$expectedRules = @($i.PreparedRules | Where-Object { $null -ne $_ })
$expectedNames = @($expectedRules | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$i.FirewallGroup) -ErrorAction SilentlyContinue)
if ($rules.Count -ne $expectedRules.Count -or @($rules | Where-Object { $expectedNames -notcontains [string]$_.Name }).Count -ne 0) { throw 'prepared_firewall: group membership drifted.' }
foreach ($expected in $expectedRules) {
  $enabled = if ([bool]$expected.ExpectedEnabled) { 'True' } else { 'False' }
  $store = if ([bool]$expected.ExpectedEnabled) { 'ActiveStore' } else { 'PersistentStore' }
  Assert-PreparedRule $expected $store $enabled
}
[pscustomobject]@{AuditedCount=[int]$expectedRules.Count}|ConvertTo-Json -Compress`
