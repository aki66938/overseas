package agent

import (
	"context"
	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/lineprobe"
	"corp.example/overseas-access-gateway/internal/localapi"
	"time"
)

type diagnosticEnabler interface {
	Enable(time.Time, time.Duration) error
}
type pipeV1SnapshotProvider interface{ LocalStatusSnapshot() LocalStatusSnapshot }

// LocalHandler shares API v1 behavior. The transport supplies administrator
// authority from the actual connection, never from request fields or local CLI checks.
type LocalHandler struct {
	controller     PipeController
	lineProbe      *lineprobe.Scheduler
	diagnosticMode diagnosticEnabler
}

func NewLocalHandler(controller PipeController, probe *lineprobe.Scheduler, diagnostic diagnosticEnabler) *LocalHandler {
	return &LocalHandler{controller: controller, lineProbe: probe, diagnosticMode: diagnostic}
}

func (s *LocalHandler) Dispatch(ctx context.Context, request localapi.Request, administrator bool) localapi.Response {
	responseError := ""
	switch request.Action {
	case localapi.ActionConnect:
		s.controller.Connect(ctx)
	case localapi.ActionDisconnect:
		s.controller.Disconnect(ctx)
	case localapi.ActionStatus:
	case localapi.ActionProbe:
		if s.lineProbe == nil || v1SnapshotFor(s.controller).Status.State != accessmodel.StateConnected {
			responseError = "probe_unavailable"
		} else {
			s.lineProbe.Manual(ctx)
		}
	case localapi.ActionDiagnosticEnable:
		if !administrator {
			responseError = "permission_denied"
		} else if s.diagnosticMode == nil || s.diagnosticMode.Enable(time.Now(), time.Duration(request.DurationMinutes)*time.Minute) != nil {
			responseError = "diagnostic_unavailable"
		}
	}
	snapshot := v1SnapshotFor(s.controller)
	connectedAt := ""
	if !snapshot.ConnectedAt.IsZero() {
		connectedAt = snapshot.ConnectedAt.UTC().Format(time.RFC3339)
	}
	response := localapi.Response{Version: localapi.Version, ID: request.ID, ErrorCode: responseError, Status: localapi.ProjectStatus(localapi.ProjectionInput{State: string(snapshot.Status.State), Quality: snapshot.Quality, ErrorCode: snapshot.Status.ErrorCode, Generation: snapshot.Generation, ConnectedAt: connectedAt})}
	if s.lineProbe != nil && snapshot.Status.State != accessmodel.StateConnecting {
		probes := s.lineProbe.Snapshot()
		connected := snapshot.Status.State == accessmodel.StateConnected
		if len(probes.Results) > 0 && probes.Generation <= snapshot.Generation && (!connected || probes.Generation == snapshot.Generation) {
			response.ProbeGeneration = probes.Generation
			response.ProbeResults = probes.Results
			response.ProbeHistorical = !connected
		}
	}
	if request.Action == localapi.ActionProbe && len(response.ProbeResults) == 0 {
		response.ErrorCode = "probe_unavailable"
	}
	return response
}

func v1SnapshotFor(controller PipeController) LocalStatusSnapshot {
	if provider, ok := controller.(pipeV1SnapshotProvider); ok {
		return provider.LocalStatusSnapshot()
	}
	diagnostics := controller.Diagnostics()
	return LocalStatusSnapshot{Status: Status{State: diagnostics.State, ErrorCode: diagnostics.ErrorCode}, Generation: diagnostics.Generation, Quality: LineQualityUnknown}
}
