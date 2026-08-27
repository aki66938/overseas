package verdict

import (
	"testing"

	"corp.example/overseas-access-gateway/internal/inventory"
)

func TestEvaluatePassesOnlyWithUpSuccessDownFailureAndRestoredRoutes(t *testing.T) {
	report := Evaluate(passingEvidence())
	if report.Status != "PASS" || report.Code != "PASS" {
		t.Fatalf("got %#v", report)
	}
}

func TestEvaluateDetectsFallbackLeak(t *testing.T) {
	evidence := passingEvidence()
	evidence.TelecomDown.Results[0].Success = true

	report := Evaluate(evidence)
	if report.Status != "FAIL" || report.Code != "FAIL_LEAK" {
		t.Fatalf("got %#v", report)
	}
}

func TestEvaluateLeakEvidenceTakesPriorityOverMissingNonLeakEvidence(t *testing.T) {
	evidence := passingEvidence()
	evidence.TelecomDown.Results[0].Success = true
	evidence.InventoryAfter = nil

	report := Evaluate(evidence)
	if report.Status != "FAIL" || report.Code != "FAIL_LEAK" {
		t.Fatalf("got %#v", report)
	}
}

func TestEvaluateReportIsDeterministicForMultipleFailingTargets(t *testing.T) {
	evidence := passingEvidence()
	evidence.TelecomUp.Results = []ProbeResult{
		{TargetName: "z-approved", Success: false},
		{TargetName: "a-approved", Success: false},
	}
	evidence.TelecomDown.Results = []ProbeResult{
		{TargetName: "z-approved", Success: false},
		{TargetName: "a-approved", Success: false},
	}

	for i := 0; i < 100; i++ {
		report := Evaluate(evidence)
		if report.Message != `approved target "a-approved" was not reachable while telecom was up` {
			t.Fatalf("iteration %d got %#v", i, report)
		}
	}
}

func TestEvaluateTreatsEachMissingEvidenceSetAsInconclusive(t *testing.T) {
	tests := []struct {
		name   string
		remove func(*Evidence)
	}{
		{name: "inventory before", remove: func(e *Evidence) { e.InventoryBefore = nil }},
		{name: "telecom up", remove: func(e *Evidence) { e.TelecomUp = nil }},
		{name: "telecom down", remove: func(e *Evidence) { e.TelecomDown = nil }},
		{name: "inventory after", remove: func(e *Evidence) { e.InventoryAfter = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := passingEvidence()
			test.remove(&evidence)

			report := Evaluate(evidence)
			if report.Status != "INCONCLUSIVE" || report.Code != "INCONCLUSIVE_MISSING_EVIDENCE" {
				t.Fatalf("got %#v", report)
			}
		})
	}
}

func TestEvaluateRejectsChangedUnrelatedRoutes(t *testing.T) {
	evidence := passingEvidence()
	evidence.InventoryAfter.Routes = append(evidence.InventoryAfter.Routes, inventory.Route{
		Alias:             "Ethernet",
		Index:             7,
		DestinationPrefix: "203.0.113.0/24",
		NextHop:           "172.20.10.1",
		Metric:            40,
		State:             "Alive",
	})

	report := Evaluate(evidence)
	if report.Status != "FAIL" || report.Code != "FAIL_STATE_DRIFT" {
		t.Fatalf("got %#v", report)
	}
}

func TestEvaluateIgnoresRouteOrdering(t *testing.T) {
	evidence := passingEvidence()
	evidence.InventoryAfter.Routes[0], evidence.InventoryAfter.Routes[1] =
		evidence.InventoryAfter.Routes[1], evidence.InventoryAfter.Routes[0]

	report := Evaluate(evidence)
	if report.Status != "PASS" || report.Code != "PASS" {
		t.Fatalf("got %#v", report)
	}
}

func TestEvaluateFailsWhenApprovedTargetDoesNotWorkWhileTelecomIsUp(t *testing.T) {
	evidence := passingEvidence()
	evidence.TelecomUp.Results[0].Success = false

	report := Evaluate(evidence)
	if report.Status != "FAIL" || report.Code != "FAIL_NO_FORWARD" {
		t.Fatalf("got %#v", report)
	}
}

func TestEvaluateRejectsMismatchedOrDuplicateTargetEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{
			name: "mismatched target",
			mutate: func(e *Evidence) {
				e.TelecomDown.Results[0].TargetName = "different-approved-target"
			},
		},
		{
			name: "duplicate target",
			mutate: func(e *Evidence) {
				e.TelecomDown.Results = append(e.TelecomDown.Results, e.TelecomDown.Results[0])
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := passingEvidence()
			test.mutate(&evidence)

			report := Evaluate(evidence)
			if report.Status != "INCONCLUSIVE" || report.Code != "INCONCLUSIVE_INVALID_EVIDENCE" {
				t.Fatalf("got %#v", report)
			}
		})
	}
}

func passingEvidence() Evidence {
	routes := []inventory.Route{
		{
			Alias:             "Ethernet",
			Index:             7,
			DestinationPrefix: "0.0.0.0/0",
			NextHop:           "172.20.10.1",
			Metric:            25,
			State:             "Alive",
		},
		{
			Alias:             "Ethernet",
			Index:             7,
			DestinationPrefix: "10.0.0.0/8",
			NextHop:           "0.0.0.0",
			Metric:            10,
			State:             "Alive",
		},
	}
	before := &inventory.State{Routes: append([]inventory.Route(nil), routes...)}
	after := &inventory.State{Routes: append([]inventory.Route(nil), routes...)}
	return Evidence{
		InventoryBefore: before,
		TelecomUp: &ProbeEvidence{Results: []ProbeResult{
			{TargetName: "operator-approved-test", Success: true},
		}},
		TelecomDown: &ProbeEvidence{Results: []ProbeResult{
			{TargetName: "operator-approved-test", Success: false},
		}},
		InventoryAfter: after,
	}
}
