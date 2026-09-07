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
