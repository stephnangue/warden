// Copyright (c) Warden Authors
// SPDX-License-Identifier: MPL-2.0

package core

// revocationJob implements fairshare.Job for expiration revocation
// Uses OpenBao's fairshare.JobManager which provides:
// - Round-robin fair-share distribution across multiple queues
// - 90% worker saturation limit per queue to prevent starvation
// - Configurable worker pool with internal dispatcher
// - Thread-safe with RWMutex protection
// - Queue management with automatic pruning of empty queues
type revocationJob struct {
	manager *ExpirationManager
	entry   *ExpirationEntry
	key     string
	pending *pendingInfo
}

// Execute implements fairshare.Job.Execute
// Called by the fairshare worker pool to perform the revocation
func (j *revocationJob) Execute() error {
	return j.manager.revokeEntry(j.entry)
}

// OnFailure implements fairshare.Job.OnFailure
// Called when Execute returns an error
func (j *revocationJob) OnFailure(err error) {
	j.manager.handleRevocationFailure(j.key, j.entry, j.pending, err)
}
