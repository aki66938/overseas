package inventory

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

const windowsInventoryScript = `$interfaces = @(Get-NetIPInterface -ErrorAction Stop | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ConnectionState,Forwarding,NlMtu)
$routes = @(Get-NetRoute -ErrorAction Stop | Select-Object InterfaceAlias,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,State)
$nat = @(Get-NetNat -ErrorAction Stop | Select-Object Name,InternalIPInterfaceAddressPrefix,ExternalIPInterfaceAddressPrefix,Active)
$firewall = @(Get-NetFirewallRule -ErrorAction Stop | ForEach-Object {
    $rule = $_
    $address = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $interface = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
    $port = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $application = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $service = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
    [pscustomobject]@{
        Name = $rule.Name; DisplayName = $rule.DisplayName; Description = $rule.Description; Group = $rule.Group
        Enabled = $rule.Enabled.ToString(); Profile = $rule.Profile.ToString(); Direction = $rule.Direction.ToString(); Action = $rule.Action.ToString()
        PolicyStoreSource = $rule.PolicyStoreSource; PolicyStoreSourceType = $rule.PolicyStoreSourceType.ToString()
        InterfaceAlias = @($interface | ForEach-Object { @($_.InterfaceAlias) } | Sort-Object -Unique)
        LocalAddress = @($address | ForEach-Object { @($_.LocalAddress) } | Sort-Object -Unique)
        RemoteAddress = @($address | ForEach-Object { @($_.RemoteAddress) } | Sort-Object -Unique)
        Protocol = @($port | ForEach-Object { $_.Protocol.ToString() } | Sort-Object -Unique)
        LocalPort = @($port | ForEach-Object { @($_.LocalPort) } | Sort-Object -Unique)
        RemotePort = @($port | ForEach-Object { @($_.RemotePort) } | Sort-Object -Unique)
        Program = @($application | ForEach-Object { @($_.Program) } | Sort-Object -Unique)
        Service = @($service | ForEach-Object { @($_.Service) } | Sort-Object -Unique)
    }
})
[pscustomobject]@{ interfaces = $interfaces; routes = $routes; nat = $nat; firewall_rules = $firewall } | ConvertTo-Json -Depth 8 -Compress`

// Snapshot reads Windows network inventory without changing network state.
// The PowerShell program is fixed: operator-supplied aliases are never passed
// to PowerShell or interpolated into its command text.
func Snapshot(ctx context.Context) (State, error) {
	command := exec.CommandContext(ctx, "pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", windowsInventoryScript)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		if stderr.Len() > 0 {
			return State{}, fmt.Errorf("run Windows inventory: %w: %s", err, stderr.String())
		}
		return State{}, fmt.Errorf("run Windows inventory: %w", err)
	}

	state, err := parseJSON(bytes.NewReader(output))
	if err != nil {
		return State{}, err
	}
	return state, nil
}
