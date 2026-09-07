package agent

import (
	"encoding/json"
	"testing"
	"time"

	"corp.example/overseas-access-gateway/internal/lineprobe"
	"corp.example/overseas-access-gateway/internal/localapi"
)

func TestPortableLegacyPipeProgress(t *testing.T) {
	var response Response
	if err := json.Unmarshal([]byte(`{"id":"progress-1","state":"connecting","phase":"routes","step":2,"total_steps":5,"elapsed_ms":123}`), &response); err != nil {
		t.Fatal(err)
	}
	if response.Phase != "routes" || response.Step != 2 || response.TotalSteps != 5 || response.ElapsedMS != 123 {
		t.Fatalf("lost wire progress fields: %+v", response)
	}
	var request Request
	if err := json.Unmarshal([]byte(`{"id":"trace-1","action":"trace","after_sequence":8,"limit":32}`), &request); err != nil {
		t.Fatal(err)
	}
	if request.AfterSequence != 8 || request.Limit != 32 || request.Action != ActionTrace {
		t.Fatalf("lost wire request fields: %+v", request)
	}
}

func TestPortablePipeTimeouts(t *testing.T) {
	for action, want := range map[string]time.Duration{
		ActionConnect: 120 * time.Second, ActionDisconnect: 90 * time.Second,
		ActionStatus: 5 * time.Second, localapi.ActionProbe: lineprobe.RoundBudget + 5*time.Second,
	} {
		if got := PipeTimeoutForAction(action); got != want {
			t.Errorf("%s timeout %v, want %v", action, got, want)
		}
	}
}
