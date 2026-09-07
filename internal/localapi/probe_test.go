package localapi

import (
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"encoding/json"
	"testing"
	"time"
)

func TestProbeResponseBoundedAndGenerationChecked(t *testing.T) {
	response := Response{Version: Version, ID: "probe", Status: Status{State: StateConnected, Quality: QualityGood, Generation: 4}, ProbeGeneration: 4, ProbeResults: []lineprobe.Result{{ID: "google", Reachable: true, HTTPStatus: 403, CheckedAt: time.Now()}}}
	data, _ := json.Marshal(response)
	if _, err := DecodeResponse(data, "probe"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Response){
		func(r *Response) { r.ProbeGeneration = 3 },
		func(r *Response) { r.ProbeResults[0].ID = "https://secret.invalid" },
		func(r *Response) { r.ProbeResults[0].LatencyMS = 5001 },
		func(r *Response) { r.ProbeResults[0].ErrorCode = "private raw detail" },
		func(r *Response) { r.ProbeResults = append(r.ProbeResults, r.ProbeResults[0]) },
	} {
		copy := response
		copy.ProbeResults = append([]lineprobe.Result(nil), response.ProbeResults...)
		mutate(&copy)
		data, _ := json.Marshal(copy)
		if _, err := DecodeResponse(data, "probe"); err == nil {
			t.Fatalf("accepted %+v", copy)
		}
	}
}

func TestProbeConsecutiveFailuresOptionalAndBounded(t *testing.T) {
	response := Response{Version: 1, ID: "counts", Status: Status{State: StateConnected, Quality: QualityUnknown, Generation: 1}, ProbeGeneration: 1, ProbeResults: []lineprobe.Result{{ID: "google", ErrorCode: "timeout", CheckedAt: time.Now()}}}
	data, _ := json.Marshal(response)
	old, err := DecodeResponse(data, "counts")
	if err != nil || old.ProbeResults[0].ConsecutiveFailures != nil {
		t.Fatalf("absent must remain unknown: %+v %v", old, err)
	}
	for _, count := range []int{-1, 0, 1, 2, 3, 4} {
		response.ProbeResults[0].ConsecutiveFailures = &count
		data, _ = json.Marshal(response)
		got, err := DecodeResponse(data, "counts")
		if count < 0 || count > 3 {
			if err == nil {
				t.Fatalf("accepted invalid %d", count)
			}
			continue
		}
		if err != nil || got.ProbeResults[0].ConsecutiveFailures == nil || *got.ProbeResults[0].ConsecutiveFailures != count {
			t.Fatalf("%d: %+v %v", count, got, err)
		}
	}
}

func TestHistoricalProbeResponseRequiresExplicitFlagAndOlderGeneration(t *testing.T) {
	response := Response{Version: 1, ID: "history", Status: Status{State: StateIdle, Quality: QualityUnknown, Generation: 4}, ProbeGeneration: 3, ProbeHistorical: true, ProbeResults: []lineprobe.Result{{ID: "google", Reachable: true, HTTPStatus: 200, CheckedAt: time.Now()}}}
	data, _ := json.Marshal(response)
	if _, err := DecodeResponse(data, "history"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Response){
		func(r *Response) { r.ProbeHistorical = false },
		func(r *Response) { r.ProbeGeneration = 5 },
		func(r *Response) { r.Status.State = StateConnected },
		func(r *Response) { r.ProbeResults = nil; r.ProbeGeneration = 0 },
	} {
		copy := response
		mutate(&copy)
		data, _ := json.Marshal(copy)
		if _, err := DecodeResponse(data, "history"); err == nil {
			t.Fatalf("accepted %+v", copy)
		}
	}
	response.ProbeGeneration = 4
	data, _ = json.Marshal(response)
	if _, err := DecodeResponse(data, "history"); err != nil {
		t.Fatalf("same-generation automatic restore history: %v", err)
	}
}
