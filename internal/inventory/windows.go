package inventory

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

const windowsInventoryScript = `$interfaces = Get-NetIPInterface | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ConnectionState,Forwarding,NlMtu
$routes = Get-NetRoute | Select-Object InterfaceAlias,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,State
[pscustomobject]@{ interfaces = $interfaces; routes = $routes } | ConvertTo-Json -Depth 5 -Compress`

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
