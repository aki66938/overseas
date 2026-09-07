package localapi

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestDecodeRequestV1IgnoresUnknownFields(t *testing.T) {
	request, err := DecodeRequest([]byte(`{"version":1,"id":"r-1","action":"status","future":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if request != (Request{Version: Version, ID: "r-1", Action: ActionStatus}) {
		t.Fatalf("request = %#v", request)
	}
}

func TestDecodeRequestRejectsInvalidContract(t *testing.T) {
	tests := []struct {
		name  string
		frame string
		err   error
	}{
		{"version", `{"version":2,"id":"r-1","action":"status"}`, ErrUnsupportedVersion},
		{"action", `{"version":1,"id":"r-1","action":"shell"}`, ErrUnsupportedAction},
		{"missing id", `{"version":1,"action":"status"}`, ErrInvalidRequest},
		{"invalid diagnostic duration", `{"version":1,"id":"r-1","action":"diagnostic-enable","duration_minutes":1}`, ErrInvalidRequest},
		{"arbitrary path", `{"version":1,"id":"r-1","action":"status","path":"C:\\evil"}`, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeRequest([]byte(test.frame))
			if test.err == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestDecodeRequestAcceptsFixedDiagnosticDurations(t *testing.T) {
	for _, duration := range []int{15, 30, 60} {
		frame := []byte(`{"version":1,"id":"diagnostic","action":"diagnostic-enable","duration_minutes":` + strconv.Itoa(duration) + `}`)
		request, err := DecodeRequest(frame)
		if err != nil {
			t.Fatalf("duration %d: %v", duration, err)
		}
		if request.DurationMinutes != duration {
			t.Fatalf("duration = %d", request.DurationMinutes)
		}
	}
}

func TestDecodeRequestRejectsOversizedInput(t *testing.T) {
	_, err := DecodeRequest([]byte(strings.Repeat("x", MaxFrameBytes+1)))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error = %v, want %v", err, ErrFrameTooLarge)
	}
}

func TestDecodeResponseRequiresMatchingIDAndContainsNoLogFields(t *testing.T) {
	frame := []byte(`{"version":1,"id":"different","status":{"state":"connected","quality":"good","generation":4},"message":"secret log"}`)
	if _, err := DecodeResponse(frame, "r-1"); !errors.Is(err, ErrMismatchedResponseID) {
		t.Fatalf("error = %v, want %v", err, ErrMismatchedResponseID)
	}
	frame = []byte(`{"version":1,"id":"r-1","status":{"state":"connected","quality":"good","generation":4},"message":"secret log"}`)
	response, err := DecodeResponse(frame, "r-1")
	if err != nil {
		t.Fatal(err)
	}
	if response.Status.State != StateConnected || response.Status.Generation != 4 {
		t.Fatalf("response = %#v", response)
	}
}

func TestProjectStatusKeepsConnectionAndQualitySeparate(t *testing.T) {
	status := ProjectStatus(ProjectionInput{State: "connected", Quality: QualitySlow, Generation: 7})
	if status.State != StateConnected || status.Quality != QualitySlow {
		t.Fatalf("status = %#v", status)
	}
	legacy := ProjectStatus(ProjectionInput{State: "prepared", Quality: QualityUnknown, Generation: 8})
	if legacy.State != StateIdle {
		t.Fatalf("prepared state projected as %q", legacy.State)
	}
}

func TestStatusCacheDoesNotOverwriteNewerGeneration(t *testing.T) {
	var cache StatusCache
	if !cache.Apply(Status{State: StateConnected, Quality: QualityGood, Generation: 9}) {
		t.Fatal("initial status rejected")
	}
	if cache.Apply(Status{State: StateIdle, Quality: QualityUnknown, Generation: 8}) {
		t.Fatal("stale status accepted")
	}
	if got, ok := cache.Load(); !ok || got.Generation != 9 || got.State != StateConnected {
		t.Fatalf("cached status = %#v, ok = %v", got, ok)
	}
}
