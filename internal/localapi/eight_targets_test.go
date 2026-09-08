package localapi

import (
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"testing"
	"time"
)

func TestEightProbeResultsRoundTrip(t *testing.T) {
	response := Response{Version: 1, ID: "eight", Status: Status{State: StateConnected, Quality: "good", Generation: 1}, ProbeGeneration: 1}
	for _, id := range []string{"google", "pinterest", "gemini", "chatgpt", "claude", "tiktok", "amazon", "facebook"} {
		response.ProbeResults = append(response.ProbeResults, lineprobe.Result{ID: id, Reachable: true, HTTPStatus: 200, CheckedAt: time.Now()})
	}
	frame, err := EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeResponse(frame, "eight")
	if err != nil || len(got.ProbeResults) != 8 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	response.ProbeResults = append(response.ProbeResults, response.ProbeResults[0])
	if _, err := EncodeResponse(response); err == nil {
		t.Fatal("duplicate ninth target accepted")
	}
	response.ProbeResults = response.ProbeResults[:8]
	response.ProbeResults[7].ID = "unknown"
	if _, err := EncodeResponse(response); err == nil {
		t.Fatal("unknown target accepted")
	}
}
