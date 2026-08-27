// Package verdict evaluates the complete forwarding PoC evidence set without
// consulting process state or making additional network requests.
package verdict

import (
	"fmt"
	"sort"
	"strings"

	"corp.example/overseas-access-gateway/internal/inventory"
)

const (
	StatusPass         = "PASS"
	StatusFail         = "FAIL"
	StatusInconclusive = "INCONCLUSIVE"
)

// Evidence is the complete, explicit input to Evaluate. Pointer fields make a
// missing artifact distinguishable from an artifact containing an empty list.
type Evidence struct {
	InventoryBefore *inventory.State
	TelecomUp       *ProbeEvidence
	TelecomDown     *ProbeEvidence
	InventoryAfter  *inventory.State
}

// ProbeEvidence contains normalized approved-target network outcomes from one
// telecom state. Success represents an observed successful HTTPS probe, never
// a telecom-client process status.
type ProbeEvidence struct {
	Results []ProbeResult
}

// ProbeResult is the verdict-relevant subset of approved-target evidence.
type ProbeResult struct {
	TargetName string `json:"target_name"`
	Success    bool   `json:"success"`
}

// Report is the deterministic, machine-readable gate decision.
type Report struct {
	Status  string `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Evaluate applies fail-closed acceptance rules to captured network evidence.
// A leak takes precedence over other conclusive failures because it is the
// immediate safety stop condition.
func Evaluate(e Evidence) Report {
	if e.TelecomDown != nil {
		if leakedTargets := successfulTargets(e.TelecomDown.Results); len(leakedTargets) > 0 {
			return report(StatusFail, "FAIL_LEAK", fmt.Sprintf("approved target %q remained reachable while telecom was down", leakedTargets[0]))
		}
	}
	if e.InventoryBefore == nil || e.TelecomUp == nil || e.TelecomDown == nil || e.InventoryAfter == nil {
		return report(StatusInconclusive, "INCONCLUSIVE_MISSING_EVIDENCE", "all four evidence artifacts are required")
	}

	upTargets, validUp := targetOutcomes(e.TelecomUp.Results)
	downTargets, validDown := targetOutcomes(e.TelecomDown.Results)
	if !validUp || !validDown || !sameTargets(upTargets, downTargets) {
		return report(StatusInconclusive, "INCONCLUSIVE_INVALID_EVIDENCE", "probe evidence must contain the same non-empty, unique approved targets")
	}

	if !sameRoutes(e.InventoryBefore.Routes, e.InventoryAfter.Routes) {
		return report(StatusFail, "FAIL_STATE_DRIFT", "route inventory changed after rollback")
	}

	if failedTargets := failedTargets(upTargets); len(failedTargets) > 0 {
		return report(StatusFail, "FAIL_NO_FORWARD", fmt.Sprintf("approved target %q was not reachable while telecom was up", failedTargets[0]))
	}

	return report(StatusPass, "PASS", "approved-target forwarding worked, failed closed, and routes were restored")
}

func successfulTargets(results []ProbeResult) []string {
	targets := make([]string, 0, len(results))
	for _, result := range results {
		name := strings.TrimSpace(result.TargetName)
		if name != "" && result.Success {
			targets = append(targets, name)
		}
	}
	sort.Strings(targets)
	return targets
}

func failedTargets(outcomes map[string]bool) []string {
	targets := make([]string, 0, len(outcomes))
	for target, succeeded := range outcomes {
		if !succeeded {
			targets = append(targets, target)
		}
	}
	sort.Strings(targets)
	return targets
}

func report(status, code, message string) Report {
	return Report{Status: status, Code: code, Message: message}
}

func targetOutcomes(results []ProbeResult) (map[string]bool, bool) {
	if len(results) == 0 {
		return nil, false
	}
	outcomes := make(map[string]bool, len(results))
	for _, result := range results {
		name := strings.TrimSpace(result.TargetName)
		if name == "" {
			return nil, false
		}
		if _, exists := outcomes[name]; exists {
			return nil, false
		}
		outcomes[name] = result.Success
	}
	return outcomes, true
}

func sameTargets(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for target := range left {
		if _, exists := right[target]; !exists {
			return false
		}
	}
	return true
}

func sameRoutes(before, after []inventory.Route) bool {
	left := append([]inventory.Route(nil), before...)
	right := append([]inventory.Route(nil), after...)
	if len(left) != len(right) {
		return false
	}
	sort.Slice(left, func(i, j int) bool { return routeKey(left[i]) < routeKey(left[j]) })
	sort.Slice(right, func(i, j int) bool { return routeKey(right[i]) < routeKey(right[j]) })
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func routeKey(route inventory.Route) string {
	return fmt.Sprintf("%s\x00%010d\x00%s\x00%s\x00%010d\x00%s",
		route.Alias,
		route.Index,
		route.DestinationPrefix,
		route.NextHop,
		route.Metric,
		route.State,
	)
}
