// Package localapi defines the platform-independent local IPC contract.
package localapi

import (
	"bytes"
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	Version       = 1
	MaxFrameBytes = 64 * 1024

	ActionStatus           = "status"
	ActionConnect          = "connect"
	ActionDisconnect       = "disconnect"
	ActionProbe            = "probe"
	ActionDiagnosticEnable = "diagnostic-enable"
)

var (
	ErrFrameTooLarge        = errors.New("local API frame exceeded size limit")
	ErrInvalidRequest       = errors.New("local API request is invalid")
	ErrUnsupportedVersion   = errors.New("local API version is unsupported")
	ErrUnsupportedAction    = errors.New("local API action is unsupported")
	ErrInvalidResponse      = errors.New("local API response is invalid")
	ErrMismatchedResponseID = errors.New("local API response ID does not match request")
)

type Request struct {
	Version         int    `json:"version"`
	ID              string `json:"id"`
	Action          string `json:"action"`
	DurationMinutes int    `json:"duration_minutes,omitempty"`
}

type Status struct {
	State       string `json:"state"`
	Quality     string `json:"quality"`
	ErrorCode   string `json:"error_code,omitempty"`
	ConnectedAt string `json:"connected_at,omitempty"`
	Generation  uint64 `json:"generation"`
}

// Response deliberately has no message, detail, log, path, command, or URL
// field. Detailed diagnostics travel through a separately authorized mode.
type Response struct {
	Version         int                `json:"version"`
	ID              string             `json:"id"`
	Status          Status             `json:"status"`
	ErrorCode       string             `json:"error_code,omitempty"`
	ProbeGeneration uint64             `json:"probe_generation,omitempty"`
	ProbeResults    []lineprobe.Result `json:"probe_results,omitempty"`
}

func DecodeRequest(frame []byte) (Request, error) {
	if len(frame) > MaxFrameBytes {
		return Request{}, ErrFrameTooLarge
	}
	var request Request
	if err := decodeOne(frame, &request); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if request.Version != Version {
		return Request{}, ErrUnsupportedVersion
	}
	if !validID(request.ID) {
		return Request{}, ErrInvalidRequest
	}
	switch request.Action {
	case ActionStatus, ActionConnect, ActionDisconnect, ActionProbe:
		if request.DurationMinutes != 0 {
			return Request{}, ErrInvalidRequest
		}
	case ActionDiagnosticEnable:
		if request.DurationMinutes != 15 && request.DurationMinutes != 30 && request.DurationMinutes != 60 {
			return Request{}, ErrInvalidRequest
		}
	default:
		return Request{}, ErrUnsupportedAction
	}
	return request, nil
}

func DecodeResponse(frame []byte, requestID string) (Response, error) {
	if len(frame) > MaxFrameBytes {
		return Response{}, ErrFrameTooLarge
	}
	var response Response
	if err := decodeOne(frame, &response); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if response.Version != Version || !validID(response.ID) || !ValidStatus(response.Status) || !validProbeResults(response) {
		return Response{}, ErrInvalidResponse
	}
	if response.ID != requestID {
		return Response{}, ErrMismatchedResponseID
	}
	return response, nil
}

func EncodeResponse(response Response) ([]byte, error) {
	if !validProbeResults(response) {
		return nil, ErrInvalidResponse
	}
	data, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	if len(data)+1 > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	return append(data, '\n'), nil
}

func validProbeResults(response Response) bool {
	if len(response.ProbeResults) == 0 {
		return response.ProbeGeneration == 0
	}
	if len(response.ProbeResults) > 5 || response.ProbeGeneration != response.Status.Generation || response.Status.State != StateConnected {
		return false
	}
	ids := make(map[string]bool)
	for _, target := range lineprobe.Targets() {
		ids[target.ID] = true
	}
	for _, r := range response.ProbeResults {
		if !ids[r.ID] || r.LatencyMS < 0 || r.LatencyMS > 5000 || r.HTTPStatus < 0 || r.HTTPStatus > 599 || r.CheckedAt.IsZero() {
			return false
		}
		delete(ids, r.ID)
		switch r.ErrorCode {
		case "", "timeout", "canceled", "tls_error", "network_error", "http_server_error", "invalid_target":
		default:
			return false
		}
	}
	return true
}

func decodeOne(frame []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validID(id string) bool {
	return id != "" && len(id) <= 128 && strings.IndexFunc(id, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

// StatusCache applies asynchronously received status without allowing an old
// controller generation to overwrite a newer one.
type StatusCache struct {
	mu      sync.RWMutex
	status  Status
	present bool
}

func (c *StatusCache) Apply(status Status) bool {
	if c == nil || !ValidStatus(status) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.present && status.Generation < c.status.Generation {
		return false
	}
	c.status, c.present = status, true
	return true
}

func (c *StatusCache) Load() (Status, bool) {
	if c == nil {
		return Status{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status, c.present
}
