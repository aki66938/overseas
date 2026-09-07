package lineprobe

import "testing"

func TestAggregateFailureHysteresisAndRecovery(t *testing.T) {
	var a Aggregate
	results := []Result{{ID: "a", Reachable: false}, {ID: "b", Reachable: false}, {ID: "c", Reachable: false}, {ID: "d", Reachable: true, HTTPStatus: 403}, {ID: "e", Reachable: true, HTTPStatus: 429}}
	for i := 0; i < 2; i++ {
		if got := a.Update(results); got == "failed" {
			t.Fatal("premature failure")
		}
	}
	if got := a.Update(results); got != "failed" {
		t.Fatal(got)
	}
	for i := 0; i < 3; i++ {
		results[i].Reachable = true
		results[i].HTTPStatus = 200
	}
	if got := a.Update(results); got != "good" {
		t.Fatal(got)
	}
	for i := 0; i < 3; i++ {
		results[i].HTTPStatus = 503
	}
	if got := a.Update(results); got == "failed" {
		t.Fatal("recovery did not reset failures")
	}
}

func TestAggregateThresholdAndMinorityFailure(t *testing.T) {
	for _, tc := range []struct {
		ms   int64
		want string
	}{{999, "good"}, {1000, "slow"}, {5000, "slow"}} {
		var a Aggregate
		results := []Result{{ID: "a", Reachable: true, HTTPStatus: 200, LatencyMS: tc.ms}, {ID: "b", Reachable: true, HTTPStatus: 200, LatencyMS: tc.ms}, {ID: "c", Reachable: true, HTTPStatus: 200, LatencyMS: tc.ms}, {ID: "d"}, {ID: "e"}}
		for i := 0; i < 4; i++ {
			if got := a.Update(results); got != tc.want {
				t.Fatalf("%d: %s", tc.ms, got)
			}
		}
	}
}

func TestAggregateRetainsPreviousQualityUntilSustainedMajorityFailure(t *testing.T) {
	var a Aggregate
	results := []Result{{ID: "google", Reachable: true, HTTPStatus: 200}}
	if a.Update(results) != "good" {
		t.Fatal("not healthy")
	}
	results[0].Reachable = false
	for i := 0; i < 2; i++ {
		if got := a.Update(results); got != "good" {
			t.Fatalf("premature degradation: %s", got)
		}
	}
	if got := a.Update(results); got != "failed" {
		t.Fatal(got)
	}
}
