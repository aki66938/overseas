// Package traceevent defines the bounded, sanitized diagnostic stream shared
// by the privileged agent and its local UI.
package traceevent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	SchemaVersion  = 1
	MaxDetailBytes = 4096

	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"

	ComponentController = "controller"
	ComponentNetwork    = "network"
	ComponentPowerShell = "powershell"
	ComponentCore       = "core"
	ComponentRecovery   = "recovery"
	ComponentService    = "service"
	ComponentLogging    = "logging"

	EventStarted   = "started"
	EventSucceeded = "succeeded"
	EventFailed    = "failed"
	EventState     = "state"

	StageRequestReceived     = "request_received"
	StagePolicyValidation    = "policy_validation"
	StageBinaryVerification  = "binary_verification"
	StageCredentialLoad      = "credential_load"
	StageNetworkCapture      = "network_capture"
	StageAdapterScan         = "adapter_scan"
	StageFirewallPublish     = "firewall_publish"
	StageActiveStoreVerify   = "active_store_verify"
	StageEmergencyProtection = "emergency_protection"
	StageConfigRender        = "config_render"
	StageCoreStart           = "core_start"
	StageCoreReady           = "core_ready"
	StageTUNReady            = "tun_ready"
	StageRouteActivation     = "route_activation"
	StageConnected           = "connected"
	StageCoreStop            = "core_stop"
	StageNetworkRestore      = "network_restore"
	StageResidueVerify       = "residue_verify"
	StageServiceRecovery     = "service_recovery"
	StageLoggingDegraded     = "logging_degraded"
)

var (
	approvedLevels     = stringSet(LevelInfo, LevelWarning, LevelError)
	approvedEvents     = stringSet(EventStarted, EventSucceeded, EventFailed, EventState)
	approvedComponents = stringSet(
		ComponentController,
		ComponentNetwork,
		ComponentPowerShell,
		ComponentCore,
		ComponentRecovery,
		ComponentService,
		ComponentLogging,
	)
	approvedStages = stringSet(
		StageRequestReceived,
		StagePolicyValidation,
		StageBinaryVerification,
		StageCredentialLoad,
		StageNetworkCapture,
		StageAdapterScan,
		StageFirewallPublish,
		StageActiveStoreVerify,
		StageEmergencyProtection,
		StageConfigRender,
		StageCoreStart,
		StageCoreReady,
		StageTUNReady,
		StageRouteActivation,
		StageConnected,
		StageCoreStop,
		StageNetworkRestore,
		StageResidueVerify,
		StageServiceRecovery,
		StageLoggingDegraded,
	)
)

type Residue struct {
	ManagedRules  int    `json:"managed_rules"`
	ProductRoutes int    `json:"product_routes"`
	ProductTUNs   int    `json:"product_tuns"`
	CoreProcesses int    `json:"core_processes"`
	Snapshot      bool   `json:"snapshot"`
	SnapshotPhase string `json:"snapshot_phase,omitempty"`
}

func (r Residue) IsZero() bool {
	return r.ManagedRules == 0 && r.ProductRoutes == 0 && r.ProductTUNs == 0 && r.CoreProcesses == 0 && !r.Snapshot
}

type Event struct {
	SchemaVersion   int       `json:"schema_version"`
	Sequence        uint64    `json:"sequence"`
	TimestampUTC    time.Time `json:"timestamp_utc"`
	Generation      uint64    `json:"generation"`
	Level           string    `json:"level"`
	Component       string    `json:"component"`
	Stage           string    `json:"stage"`
	Event           string    `json:"event"`
	ElapsedMS       *int64    `json:"elapsed_ms,omitempty"`
	Message         string    `json:"message"`
	Detail          string    `json:"detail,omitempty"`
	DetailTruncated bool      `json:"detail_truncated,omitempty"`
	Residue         *Residue  `json:"residue,omitempty"`
}

type Batch struct {
	Events         []Event `json:"events"`
	NextSequence   uint64  `json:"next_sequence"`
	HasMore        bool    `json:"has_more"`
	OldestSequence uint64  `json:"oldest_sequence"`
}

type Sink interface {
	Record(Event)
}

type Source interface {
	Batch(after uint64, limit int) Batch
}

func ApprovedComponents() []string {
	return []string{
		ComponentController,
		ComponentNetwork,
		ComponentPowerShell,
		ComponentCore,
		ComponentRecovery,
		ComponentService,
		ComponentLogging,
	}
}

func ApprovedStages() []string {
	return []string{
		StageRequestReceived,
		StagePolicyValidation,
		StageBinaryVerification,
		StageCredentialLoad,
		StageNetworkCapture,
		StageAdapterScan,
		StageFirewallPublish,
		StageActiveStoreVerify,
		StageEmergencyProtection,
		StageConfigRender,
		StageCoreStart,
		StageCoreReady,
		StageTUNReady,
		StageRouteActivation,
		StageConnected,
		StageCoreStop,
		StageNetworkRestore,
		StageResidueVerify,
		StageServiceRecovery,
		StageLoggingDegraded,
	}
}

func Validate(event Event) error {
	if event.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported trace schema %d", event.SchemaVersion)
	}
	if event.Sequence == 0 {
		return errors.New("trace sequence is required")
	}
	if event.TimestampUTC.IsZero() || event.TimestampUTC.Location() != time.UTC {
		return errors.New("trace timestamp must be UTC")
	}
	if !approvedLevels[event.Level] {
		return errors.New("trace level is not approved")
	}
	if !approvedComponents[event.Component] {
		return errors.New("trace component is not approved")
	}
	if !approvedStages[event.Stage] {
		return errors.New("trace stage is not approved")
	}
	if !approvedEvents[event.Event] {
		return errors.New("trace event is not approved")
	}
	if strings.TrimSpace(event.Message) == "" {
		return errors.New("trace message is required")
	}
	if len([]byte(event.Detail)) > MaxDetailBytes {
		return errors.New("trace detail exceeds limit")
	}
	if event.ElapsedMS != nil && *event.ElapsedMS < 0 {
		return errors.New("trace elapsed time is negative")
	}
	if event.Event == EventStarted && event.ElapsedMS != nil {
		return errors.New("started trace cannot have elapsed time")
	}
	if event.Event == EventStarted && event.Residue != nil {
		return errors.New("started trace cannot have residue")
	}
	if event.Residue != nil {
		if event.Residue.ManagedRules < 0 || event.Residue.ProductRoutes < 0 || event.Residue.ProductTUNs < 0 || event.Residue.CoreProcesses < 0 {
			return errors.New("trace residue count is negative")
		}
	}
	return nil
}

type generationContextKey struct{}

func WithGeneration(ctx context.Context, generation uint64) context.Context {
	return context.WithValue(ctx, generationContextKey{}, generation)
}

func GenerationFromContext(ctx context.Context) uint64 {
	generation, _ := ctx.Value(generationContextKey{}).(uint64)
	return generation
}

func stringSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}
