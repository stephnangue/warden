package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/stephnangue/warden/logger"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
)

// oidcPublisherRotationPath is the storage key (within the issuer barrier view) of the
// publisher-credential rotation state. It holds only a schedule anchor — no secret and
// no staged credential — because rotation is single-stage (see RotatablePublisher).
const oidcPublisherRotationPath = "publisher-rotation"

// publisherRotationState anchors the rotation schedule so restarts and failovers do not
// re-mint a credential on every unseal (which would burn the provider's per-account key
// quota). The next rotation is due at LastRotatedAt + period. It also records the last
// rotation's outcome so operators can see rotation health via the read API without
// tailing logs.
type publisherRotationState struct {
	LastRotatedAt time.Time `json:"last_rotated_at"`
	// LastError / LastErrorAt record the most recent failed cycle; cleared on success. A
	// failure does not advance LastRotatedAt (the schedule stays anchored on last success).
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitempty"`
}

func loadPublisherRotationState(ctx context.Context, storage sdklogical.Storage) (*publisherRotationState, error) {
	entry, err := storage.Get(ctx, oidcPublisherRotationPath)
	if err != nil {
		return nil, fmt.Errorf("oidc publisher rotation: read state: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var s publisherRotationState
	if err := json.Unmarshal(entry.Value, &s); err != nil {
		return nil, fmt.Errorf("oidc publisher rotation: unmarshal state: %w", err)
	}
	return &s, nil
}

func savePublisherRotationState(ctx context.Context, storage sdklogical.Storage, s *publisherRotationState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("oidc publisher rotation: marshal state: %w", err)
	}
	return storage.Put(ctx, &sdklogical.StorageEntry{Key: oidcPublisherRotationPath, Value: data})
}

func clearPublisherRotationState(ctx context.Context, storage sdklogical.Storage) error {
	return storage.Delete(ctx, oidcPublisherRotationPath)
}

// publisherRotationActive reports whether the publisher-credential rotation loop is
// running on this node (true only on the active node with a rotatable, configured
// publisher). Used by the read API to show whether rotation is actually in effect here.
func (c *Core) publisherRotationActive() bool {
	c.oidcMu.RLock()
	defer c.oidcMu.RUnlock()
	return c.oidcPubRotationCancel != nil
}

// startPublisherCredRotation launches the active node's publisher-credential rotation
// loop. It is a no-op on a standby, when the period is unset, or when the configured
// publisher cannot rotate. Always stops any prior loop first, so it is safe to call on
// every (re)setup.
func (c *Core) startPublisherCredRotation(standby bool, period time.Duration, publisher JWKSPublisher) {
	c.stopPublisherCredRotation()
	if standby {
		// The active node owns the shared schedule state; a standby must not touch it.
		return
	}
	storage := NewBarrierView(c.barrier, oidcIssuerStorePrefix)
	if period <= 0 {
		// Rotation is disabled by config (period unset, or a type switch cleared the
		// rotation_period, which is owned only by rotatable types). Drop any stale schedule
		// anchor so a later re-enable starts a fresh period instead of firing immediately
		// off an old timestamp.
		if err := clearPublisherRotationState(c.activeContext, storage); err != nil {
			c.logger.Warn("oidc issuer: publisher-credential rotation: clearing schedule anchor failed", logger.Err(err))
		}
		return
	}
	rp, ok := publisher.(RotatablePublisher)
	if publisher == nil || !ok || !rp.SupportsRotation() {
		// period > 0 but the publisher is not rotatable. rotation_period is only accepted for
		// rotatable types, so this means the publisher failed to build (e.g. a corrupted
		// stored key degraded setup to endpoint-only) or holds a non-rotatable credential
		// (an s3 non-AKIA key reachable only via a direct storage edit). Do NOT clear the
		// anchor: preserve the schedule so a repaired config resumes on its original cadence.
		c.logger.Warn("oidc issuer: publisher-credential rotation configured but the publisher is not rotatable; not rotating (publisher build failed or credential not rotatable)")
		return
	}

	firstTick, err := c.publisherRotationFirstTick(c.activeContext, storage, period)
	if err != nil {
		// A state read/seed failure must not brick unseal; schedule a full period out
		// and let a later cycle re-seed the anchor.
		c.logger.Warn("oidc issuer: publisher-credential rotation: state read failed; scheduling a full period out", logger.Err(err))
		firstTick = period
	}

	ctx, cancel := context.WithCancel(c.activeContext)
	done := make(chan struct{})
	c.oidcMu.Lock()
	c.oidcPubRotationCancel = cancel
	c.oidcPubRotationDone = done
	c.oidcMu.Unlock()
	go c.publisherCredRotationLoop(ctx, done, period, firstTick, rp)
	c.logger.Info("oidc issuer: publisher-credential rotation enabled", logger.String("period", period.String()))
}

// publisherRotationFirstTick returns the delay until the first rotation. On a first-ever
// start (no persisted state) it seeds LastRotatedAt=now and schedules a full period out,
// so a restart within a period never re-mints. Otherwise it anchors on the persisted
// LastRotatedAt (stable across restarts and failover).
func (c *Core) publisherRotationFirstTick(ctx context.Context, storage sdklogical.Storage, period time.Duration) (time.Duration, error) {
	st, err := loadPublisherRotationState(ctx, storage)
	if err != nil {
		return 0, err
	}
	if st == nil {
		if err := savePublisherRotationState(ctx, storage, &publisherRotationState{LastRotatedAt: time.Now()}); err != nil {
			return 0, err
		}
		return period, nil
	}
	return time.Until(st.LastRotatedAt.Add(period)), nil
}

// stopPublisherCredRotation cancels the loop and joins it, so a demoted/sealing node
// never keeps rotating (or racing a rebuild in setupOIDCIssuer).
func (c *Core) stopPublisherCredRotation() {
	c.oidcMu.Lock()
	cancel := c.oidcPubRotationCancel
	done := c.oidcPubRotationDone
	c.oidcPubRotationCancel = nil
	c.oidcPubRotationDone = nil
	c.oidcMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (c *Core) publisherCredRotationLoop(ctx context.Context, done chan struct{}, period, firstTick time.Duration, rp RotatablePublisher) {
	defer close(done)
	if firstTick < 0 {
		firstTick = 0
	}
	timer := time.NewTimer(firstTick)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			rotErr := c.rotatePublisherCredential(ctx, rp)
			// Record the outcome (skip if the loop is tearing down — ctx cancellation is
			// not a rotation failure worth persisting, and the state write would fail).
			if ctx.Err() == nil {
				c.recordPublisherRotationOutcome(ctx, rotErr)
			}
			if rotErr != nil {
				c.logger.Warn("oidc issuer: publisher-credential rotation failed", logger.Err(rotErr))
			}
			timer.Reset(jitterDuration(period, 0.05))
		}
	}
}

// rotatePublisherCredential runs one single-stage verify-before-swap cycle: mint+verify a
// new credential (old untouched), persist it, swap the live publisher in place, then
// delete the old credential best-effort. A failure before the swap leaves the old
// credential live, so publishing never breaks; the cycle retries next tick.
func (c *Core) rotatePublisherCredential(ctx context.Context, rp RotatablePublisher) error {
	// 1. Create + verify the new credential (abortable via ctx so stop() joins fast).
	newFields, prevFields, cleanup, err := rp.PrepareRotation(ctx)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}

	// 2. Persist the new credential into the publisher config (durable before swap).
	// Aborts (and rolls back) if the stored config no longer holds the values this cycle
	// chained from — e.g. an operator swapped the credential or changed the publisher type
	// concurrently. Overwriting there would silently discard the operator's change (a
	// compromise remediation!) and re-instate a key minted from the old chain.
	if err := c.persistRotatedPublisherFields(ctx, newFields, prevFields); err != nil {
		// The new credential was created + verified but never persisted or committed;
		// delete it (best-effort) so a persist failure does not leak a live key toward
		// the provider quota. Skip when ctx was cancelled (node sealing) — the loop is
		// tearing down and a leftover key is a tolerated orphan.
		if ctx.Err() == nil {
			if rbErr := rp.RollbackRotation(ctx, newFields); rbErr != nil {
				c.logger.Warn("oidc issuer: publisher-credential rotation: rollback of unpersisted key failed (orphan left)", logger.Err(rbErr))
			}
		}
		return fmt.Errorf("persist: %w", err)
	}

	// 3. Swap the live in-memory credential to the just-persisted one.
	if err := rp.CommitRotation(newFields); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	// 4. Delete the superseded credential (best-effort; a leftover is a harmless orphan).
	if err := rp.CleanupRotation(ctx, cleanup); err != nil {
		c.logger.Warn("oidc issuer: publisher-credential rotation: deleting old credential failed (orphan left)", logger.Err(err))
	}

	c.logger.Info("oidc issuer: rotated publisher credential")
	return nil
}

// recordPublisherRotationOutcome persists the result of a rotation cycle. On success it
// advances the schedule anchor and clears any recorded error; on failure it records the
// error (and its time) while leaving LastRotatedAt anchored on the last success, so a
// failing cycle neither resets the schedule nor hides the reason from the read API.
func (c *Core) recordPublisherRotationOutcome(ctx context.Context, rotErr error) {
	storage := NewBarrierView(c.barrier, oidcIssuerStorePrefix)
	st, err := loadPublisherRotationState(ctx, storage)
	if err != nil || st == nil {
		st = &publisherRotationState{}
	}
	now := time.Now()
	if rotErr == nil {
		st.LastRotatedAt = now
		st.LastError = ""
		st.LastErrorAt = time.Time{}
	} else {
		st.LastError = rotErr.Error()
		st.LastErrorAt = now
	}
	if err := savePublisherRotationState(ctx, storage, st); err != nil {
		c.logger.Warn("oidc issuer: publisher-credential rotation: persisting rotation state failed", logger.Err(err))
	}
}

// errRotationSuperseded means the stored config changed under a rotation cycle (the
// operator swapped the credential or the publisher type), so the persist was abandoned.
var errRotationSuperseded = errors.New("rotation superseded by a concurrent config change")

// persistRotatedPublisherFields overlays the rotated credential fields onto the stored
// issuer config and saves it, under oidcConfigMu so a concurrent operator config write
// cannot lost-update the credential. It first compare-and-swaps: every field in prevFields
// must still hold its pre-rotation value in the stored config; otherwise an operator
// changed the credential (or the publisher type) concurrently, so it returns
// errRotationSuperseded and persists nothing (the caller rolls back the new credential).
// The check is credential-format-agnostic — a new publisher type only needs its fields
// wired into publisherFieldValue/setPublisherField.
func (c *Core) persistRotatedPublisherFields(ctx context.Context, newFields, prevFields map[string]string) error {
	c.oidcConfigMu.Lock()
	defer c.oidcConfigMu.Unlock()

	storage := NewBarrierView(c.barrier, oidcIssuerStorePrefix)
	cfg, err := loadIssuerConfig(ctx, storage)
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("issuer config missing")
	}

	for k, want := range prevFields {
		cur, ok := publisherFieldValue(&cfg.Publisher, k)
		if !ok || cur != want {
			return errRotationSuperseded
		}
	}
	for k, v := range newFields {
		if err := setPublisherField(&cfg.Publisher, k, v); err != nil {
			return err
		}
	}
	return saveIssuerConfig(ctx, storage, cfg)
}

// publisherFieldValue / setPublisherField map a rotated-credential field key to its slot
// on publisherConfig, keeping persistRotatedPublisherFields free of any per-provider
// credential-format knowledge. Extend the switches when a new rotatable publisher lands.
func publisherFieldValue(pc *publisherConfig, key string) (string, bool) {
	switch key {
	case "credentials_json":
		return pc.CredentialsJSON, true
	case "access_key_id":
		return pc.AccessKeyID, true
	case "secret_access_key":
		return pc.SecretAccessKey, true
	case "client_secret":
		return pc.ClientSecret, true
	case "secret_id":
		return pc.SecretID, true
	default:
		return "", false
	}
}

func setPublisherField(pc *publisherConfig, key, val string) error {
	switch key {
	case "credentials_json":
		pc.CredentialsJSON = val
	case "access_key_id":
		pc.AccessKeyID = val
	case "secret_access_key":
		pc.SecretAccessKey = val
	case "client_secret":
		pc.ClientSecret = val
	case "secret_id":
		pc.SecretID = val
	default:
		return fmt.Errorf("unexpected rotated publisher field %q", key)
	}
	return nil
}
