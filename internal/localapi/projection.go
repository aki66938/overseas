package localapi

const (
	StateIdle        = "idle"
	StatePreparing   = "preparing"
	StateConnecting  = "connecting"
	StateConnected   = "connected"
	StateRestoring   = "restoring"
	StateNeedsAction = "needs_action"

	QualityUnknown = "unknown"
	QualityGood    = "good"
	QualitySlow    = "slow"
	QualityFailed  = "failed"
)

// ProjectionInput is intentionally independent of agent.Status. Platform
// adapters copy the controller fields into it, keeping localapi cycle-free.
type ProjectionInput struct {
	State       string
	Quality     string
	ErrorCode   string
	ConnectedAt string
	Generation  uint64
}

func ProjectStatus(input ProjectionInput) Status {
	state := input.State
	switch state {
	case "prepared", "disconnected":
		state = StateIdle
	case "failed_safe", "failed":
		state = StateNeedsAction
	}
	quality := input.Quality
	if quality == "" {
		quality = QualityUnknown
	}
	return Status{State: state, Quality: quality, ErrorCode: input.ErrorCode, ConnectedAt: input.ConnectedAt, Generation: input.Generation}
}

func ValidStatus(status Status) bool {
	switch status.State {
	case StateIdle, StatePreparing, StateConnecting, StateConnected, StateRestoring, StateNeedsAction:
	default:
		return false
	}
	switch status.Quality {
	case QualityUnknown, QualityGood, QualitySlow, QualityFailed:
		return true
	default:
		return false
	}
}
