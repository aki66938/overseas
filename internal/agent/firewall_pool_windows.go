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
	return windowsNetworkInput{
		FirewallRuleNames: names, FirewallGroup: windowsFirewallGroup,
		BlockedRemoteAddresses:    append([]string(nil), m.blockedPrefixes...),
		DNSBlockedRemoteAddresses: append([]string(nil), m.dnsBlockedPrefixes...),
		PreparedRules:             rules, PreparedGeneration: state.Generation,
		RuleDefinitionVersion: state.RuleDefinitionVersion,
	}
}

func (m *WindowsNetworkManager) prepareFirewallPool(ctx context.Context, state WindowsPreparedState) error {
	input := m.preparedFirewallInput(state, true)
	if _, err := m.run(ctx, networkOperationFirewallPrepare, input); err != nil {
		emergencyContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), windowsEmergencyTimeout)
		defer cancel()
		return errors.Join(err, m.installPreparedEmergencyProtection(emergencyContext, state))
	}
	return nil
}

func (m *WindowsNetworkManager) installPreparedEmergencyProtection(ctx context.Context, state WindowsPreparedState) error {
	_, err := m.run(ctx, networkOperationEmergency, m.preparedFirewallInput(state, true))
	return err
}

func (m *WindowsNetworkManager) enablePreparedFirewall(ctx context.Context, state WindowsPreparedState) error {
	_, err := m.run(ctx, networkOperationFirewallEnable, m.preparedFirewallInput(state, false))
	return err
}

func (m *WindowsNetworkManager) verifyPreparedFirewall(ctx context.Context, state WindowsPreparedState) error {
	_, err := m.run(ctx, networkOperationFirewallVerify, m.preparedFirewallInput(state, true))
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
function Get-PreparedDescription($expected) {
  return ('RegenBioOwned;v=' + [string]$i.RuleDefinitionVersion + ';g=' + [string]$i.PreparedGeneration + ';sha=' + [string]$expected.RemoteAddressesSHA + ';emergency=' + ([bool]$expected.Emergency).ToString().ToLowerInvariant())
}
function Get-PreparedRemote($expected) {
  if ([bool]$expected.Emergency -or [string]$expected.Protocol -eq 'Any') { return @($i.BlockedRemoteAddresses) }
  return @($i.DNSBlockedRemoteAddresses)
}
function Get-PreparedAliases($expected) {
  if (-not [string]::IsNullOrWhiteSpace([string]$expected.InterfaceAlias)) { return @([string]$expected.InterfaceAlias) }
  return @($expected.InterfaceAliases)
}
function Assert-PreparedRule($expected, [string]$policyStore, [string]$enabled) {
  $rules = @(Get-NetFirewallRule -PolicyStore $policyStore -Name ([string]$expected.Name) -ErrorAction SilentlyContinue)
  if ($rules.Count -ne 1) { throw ('prepared_firewall: expected exactly one rule named ' + [string]$expected.Name + '.') }
  $rule = $rules[0]
  if ([string]$rule.Group -ne [string]$i.FirewallGroup -or [string]$rule.Direction -ne 'Outbound' -or [string]$rule.Action -ne 'Block' -or [string]$rule.Enabled -ne $enabled -or [string]$rule.Description -ne (Get-PreparedDescription $expected)) { throw ('prepared_firewall: metadata mismatch for ' + [string]$expected.Name + '.') }
  $port = @($rule | Get-NetFirewallPortFilter)
  if ($port.Count -ne 1 -or [string]$port[0].Protocol -ne [string]$expected.Protocol) { throw ('prepared_firewall: protocol mismatch for ' + [string]$expected.Name + '.') }
  $expectedPorts = @($expected.RemotePorts)
  if ($expectedPorts.Count -eq 0) { $expectedPorts = @('Any') }
  Assert-PreparedSet (([string]$expected.Name) + ' remote ports') @($port[0].RemotePort) $expectedPorts $false
  $address = @($rule | Get-NetFirewallAddressFilter)
  if ($address.Count -ne 1) { throw ('prepared_firewall: address filter is ambiguous for ' + [string]$expected.Name + '.') }
  Assert-PreparedSet (([string]$expected.Name) + ' remote addresses') @($address[0].RemoteAddress) @(Get-PreparedRemote $expected) $true
  $interface = @($rule | Get-NetFirewallInterfaceFilter)
  if ($interface.Count -ne 1) { throw ('prepared_firewall: interface filter is ambiguous for ' + [string]$expected.Name + '.') }
  Assert-PreparedSet (([string]$expected.Name) + ' interface aliases') @($interface[0].InterfaceAlias) @(Get-PreparedAliases $expected) $false
}`

const preparedFirewallPreparePowerShell = preparedFirewallPowerShellHelpers + `
if ([int]$i.RuleDefinitionVersion -ne 2 -or [uint64]$i.PreparedGeneration -eq 0) { throw 'prepared_firewall: invalid definition version or generation.' }
$expectedRules = @($i.PreparedRules)
if ($expectedRules.Count -lt 4) { throw 'prepared_firewall: rule plan is incomplete.' }
$expectedNames = @($expectedRules | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
if ($expectedNames.Count -ne $expectedRules.Count) { throw 'prepared_firewall: duplicate desired rule name.' }
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$i.FirewallGroup) -ErrorAction SilentlyContinue)
$unknown = @($rules | Where-Object { $expectedNames -notcontains [string]$_.Name })
if ($unknown.Count -ne 0) { throw 'prepared_firewall: unknown product-group rule exists.' }
foreach ($expected in $expectedRules) {
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
  $ports = @($expected.RemotePorts)
  if ($ports.Count -ne 0) { $parameters.RemotePort = $ports }
  New-NetFirewallRule @parameters | Out-Null
  Assert-PreparedRule $expected 'PersistentStore' 'False'
}
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
$expectedRules = @($i.PreparedRules)
$expectedNames = @($expectedRules | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$i.FirewallGroup) -ErrorAction SilentlyContinue)
if ($rules.Count -ne $expectedRules.Count -or @($rules | Where-Object { $expectedNames -notcontains [string]$_.Name }).Count -ne 0) { throw 'prepared_firewall: group membership drifted.' }
foreach ($expected in $expectedRules) {
  $enabled = if ([bool]$expected.ExpectedEnabled) { 'True' } else { 'False' }
  $store = if ([bool]$expected.ExpectedEnabled) { 'ActiveStore' } else { 'PersistentStore' }
  Assert-PreparedRule $expected $store $enabled
}
[pscustomobject]@{AuditedCount=[int]$expectedRules.Count}|ConvertTo-Json -Compress`
