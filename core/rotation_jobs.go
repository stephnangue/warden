// Copyright (c) Warden Authors
// SPDX-License-Identifier: MPL-2.0

package core

// rotationJob implements fairshare.Job for credential rotation
// Uses OpenBao's fairshare.JobManager which provides:
// - Round-robin fair-share distribution across multiple queues
// - 90% worker saturation limit per queue to prevent starvation
// - Configurable worker pool with internal dispatcher
// - Thread-safe with RWMutex protection
// - Queue management with automatic pruning of empty queues
type rotationJob struct {
	manager *RotationManager
	entry   *RotationEntry
	key     string
	pending *pendingRotation
}

// Execute implements fairshare.Job.Execute
// Called by the fairshare worker pool to perform the rotation.
// On success, schedules the next rotation since fairshare.Job has no OnSuccess callback.
func (j *rotationJob) Execute() error {
	err := j.manager.rotateSource(j.entry)
	if err == nil {
		j.manager.handleRotationSuccess(j.key, j.entry, j.pending)
	}
	return err
}

// OnFailure implements fairshare.Job.OnFailure
// Called when Execute returns an error
func (j *rotationJob) OnFailure(err error) {
	j.manager.handleRotationFailure(j.key, j.entry, j.pending, err)
}
