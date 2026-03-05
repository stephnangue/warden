package core

import "time"

// ClusterConfig holds tunable parameters for HA clustering behavior.
// All fields have sensible defaults via DefaultClusterConfig().
type ClusterConfig struct {
	// GoroutineShutdownTimeout is how long to wait for background goroutines
	// (key upgrade checker, leader refresh, leader cleanup) to exit during
	// step-down before giving up.
	GoroutineShutdownTimeout time.Duration

	// LockAcquisitionTimeout is the maximum time to wait when acquiring the
	// HA lock. Zero means wait indefinitely (the default).
	LockAcquisitionTimeout time.Duration

	// LeaderCleanupInterval is how often the active node removes stale
	// leader advertisements from barrier storage.
	LeaderCleanupInterval time.Duration

	// StepDownStateLockTimeout is how long to wait to acquire the state lock
	// during step-down before forcing teardown without the lock.
	StepDownStateLockTimeout time.Duration

	// LeaderLookupTimeout is the deadline for barrier reads when looking up
	// the leader advertisement in Leader()/LeaderLocked().
	LeaderLookupTimeout time.Duration

	// ClockSkewGrace is the backwards offset applied to the cluster
	// certificate's NotBefore time to tolerate clock drift between nodes.
	ClockSkewGrace time.Duration

	// ClusterListenerReadTimeout is the HTTP read timeout for the cluster
	// listener that handles forwarded requests from standby nodes.
	ClusterListenerReadTimeout time.Duration

	// ClusterListenerWriteTimeout is the HTTP write timeout for the cluster
	// listener.
	ClusterListenerWriteTimeout time.Duration

	// ForwardingTimeout is the maximum time for a forwarded request from a
	// standby node to the active node before timing out.
	ForwardingTimeout time.Duration
}

// DefaultClusterConfig returns a ClusterConfig with production-ready defaults.
func DefaultClusterConfig() ClusterConfig {
	return ClusterConfig{
		GoroutineShutdownTimeout:    30 * time.Second,
		LockAcquisitionTimeout:      0, // indefinite
		LeaderCleanupInterval:       1 * time.Hour,
		StepDownStateLockTimeout:    30 * time.Second,
		LeaderLookupTimeout:         10 * time.Second,
		ClockSkewGrace:              60 * time.Second,
		ClusterListenerReadTimeout:  30 * time.Second,
		ClusterListenerWriteTimeout: 60 * time.Second,
		ForwardingTimeout:           60 * time.Second,
	}
}
