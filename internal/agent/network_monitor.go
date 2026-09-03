//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Runtime monitor cadence: lightweight native fingerprints every 30 seconds
// and a read-only deep firewall audit every 5 minutes. Neither runs before
// the controller reports connected.
const (
	networkMonitorFingerprintInterval = 30 * time.Second
	networkMonitorAuditInterval       = 5 * time.Minute
)

type monitorTicker interface {
	Tick() <-chan time.Time
	Stop()
}

type monitorClock interface {
	NewTicker(time.Duration) monitorTicker
}

type realMonitorTicker struct{ ticker *time.Ticker }

func (t realMonitorTicker) Tick() <-chan time.Time { return t.ticker.C }
func (t realMonitorTicker) Stop()                  { t.ticker.Stop() }

type realMonitorClock struct{}

func (realMonitorClock) NewTicker(duration time.Duration) monitorTicker {
	return realMonitorTicker{ticker: time.NewTicker(duration)}
}

type networkMonitorConfig struct {
	FingerprintInterval time.Duration
	AuditInterval       time.Duration
}

func withWindowsMonitorClock(clock monitorClock) WindowsNetworkOption {
	return func(manager *WindowsNetworkManager) { manager.monitorClock = clock }
}

func withWindowsMonitorConfig(config networkMonitorConfig) WindowsNetworkOption {
	return func(manager *WindowsNetworkManager) { manager.monitorConfig = config }
}

// preparedNetwork reports the prepared generation currently held in memory.
func (m *WindowsNetworkManager) preparedNetwork() PreparedNetwork {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.prepared == nil {
		return PreparedNetwork{}
	}
	return preparedNetworkFromState(*m.prepared)
}

// StartMonitor runs the post-connect runtime monitor for one prepared
// generation. Fingerprints are compared through native APIs only; the deep
// audit is read-only PowerShell. Any confirmed drift enables the pool's own
// emergency rule before exactly one buffered terminal error is delivered.
func (m *WindowsNetworkManager) StartMonitor(ctx context.Context, prepared PreparedNetwork) (<-chan error, error) {
	if err := validatePreparedNetwork(prepared); err != nil {
		return nil, err
	}
	state, ok := m.preparedStateForSnapshot(WindowsNetworkSnapshot{PreparedGeneration: prepared.Generation})
	if !ok || preparedNetworkFromState(state) != prepared {
		return nil, errors.New("prepared generation is not available for monitoring")
	}
	config := m.monitorConfig
	if config.FingerprintInterval <= 0 {
		config.FingerprintInterval = networkMonitorFingerprintInterval
	}
	if config.AuditInterval <= 0 {
		config.AuditInterval = networkMonitorAuditInterval
	}
	clock := m.monitorClock
	if clock == nil {
		clock = realMonitorClock{}
	}
	failures := make(chan error, 1)
	m.mu.Lock()
	m.monitorFlights++
	m.mu.Unlock()
	go func() {
		defer func() {
			m.mu.Lock()
			m.monitorFlights--
			m.mu.Unlock()
		}()
		m.runMonitor(ctx, state, config, clock, failures)
	}()
	return failures, nil
}

func (m *WindowsNetworkManager) runMonitor(ctx context.Context, state WindowsPreparedState, config networkMonitorConfig, clock monitorClock, failures chan<- error) {
	fingerprints := clock.NewTicker(config.FingerprintInterval)
	defer fingerprints.Stop()
	audits := clock.NewTicker(config.AuditInterval)
	defer audits.Stop()
	// The comparison baseline is the CONNECTED state (TUN up, DNS overrides,
	// owned routes in place), captured when monitoring starts. Comparing
	// against the prepared fingerprint would flag the connection's own
	// network changes as topology drift and kill every session at the first
	// tick.
	baselineFingerprint, err := m.native.Fingerprint(ctx, m.nodeAddresses)
	if err != nil {
		// A failed read at startup is retried on the next tick; only a
		// confirmed drift against a known baseline reports failure.
		baselineFingerprint = ""
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-fingerprints.Tick():
			if ctx.Err() != nil {
				return
			}
			fingerprint, err := m.native.Fingerprint(ctx, m.nodeAddresses)
			if err != nil {
				// A single failed native read is retried on the next tick;
				// it must not tear down a healthy connection.
				continue
			}
			if baselineFingerprint != "" && fingerprint != baselineFingerprint {
				m.armMonitorEmergency(ctx, state)
				deliverMonitorFailure(failures, fmt.Errorf("%w: runtime fingerprint differs from the connected baseline", errNetworkChanged))
				return
			}
			if baselineFingerprint == "" {
				baselineFingerprint = fingerprint
			}
		case <-audits.Tick():
			if ctx.Err() != nil {
				return
			}
			if err := m.auditPreparedFirewall(ctx, state, true); err != nil {
				if ctx.Err() != nil {
					return
				}
				m.armMonitorEmergency(ctx, state)
				deliverMonitorFailure(failures, fmt.Errorf("%w: %v", errFirewallAudit, err))
				return
			}
		}
	}
}

func (m *WindowsNetworkManager) armMonitorEmergency(ctx context.Context, state WindowsPreparedState) {
	emergencyContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), windowsEmergencyTimeout)
	defer cancel()
	_ = m.installPreparedEmergencyProtection(emergencyContext, state)
}

func deliverMonitorFailure(failures chan<- error, err error) {
	failures <- err
	close(failures)
}
