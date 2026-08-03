package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/stephnangue/warden/logger"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
)

// oidcKeyRotationPath is the storage key (within the issuer barrier view) of the
// signing-key rotation status. It holds only a status/schedule anchor — the key material
// itself lives in the keyset doc — so an operator can see signing-key rotation health via
// the read API without tailing logs.
const oidcKeyRotationPath = "key-rotation"

// oidcKeyRotationState records signing-key rotation status for the read API. The rotation
// loop schedules off the next key's age (see oidcRotationFirstTick); this anchor is kept
// in lockstep with it — seeded from the same next-key createdAt and advanced on each
// successful cycle — purely so last_rotated_at / next_rotation and the last error can be
// surfaced without changing how scheduling works.
type oidcKeyRotationState struct {
	LastRotatedAt time.Time `json:"last_rotated_at"`
	// LastError / LastErrorAt record the most recent failed cycle; cleared on success. A
	// failure does not advance LastRotatedAt (the schedule stays anchored on last success).
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitempty"`
}

func loadOIDCKeyRotationState(ctx context.Context, storage sdklogical.Storage) (*oidcKeyRotationState, error) {
	entry, err := storage.Get(ctx, oidcKeyRotationPath)
	if err != nil {
		return nil, fmt.Errorf("oidc key rotation: read state: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var s oidcKeyRotationState
	if err := json.Unmarshal(entry.Value, &s); err != nil {
		return nil, fmt.Errorf("oidc key rotation: unmarshal state: %w", err)
	}
	return &s, nil
}

func saveOIDCKeyRotationState(ctx context.Context, storage sdklogical.Storage, s *oidcKeyRotationState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("oidc key rotation: marshal state: %w", err)
	}
	return storage.Put(ctx, &sdklogical.StorageEntry{Key: oidcKeyRotationPath, Value: data})
}

func clearOIDCKeyRotationState(ctx context.Context, storage sdklogical.Storage) error {
	return storage.Delete(ctx, oidcKeyRotationPath)
}

// oidcKeyRotationActive reports whether the signing-key rotation loop is running on this
// node (true only on the active node with a positive key_rotation_period). Used by the
// read API to show whether rotation is actually in effect here.
func (c *Core) oidcKeyRotationActive() bool {
	c.oidcMu.RLock()
	defer c.oidcMu.RUnlock()
	return c.oidcRotationCancel != nil
}

// seedOIDCKeyRotationState seeds the status anchor when none exists yet, anchoring
// LastRotatedAt on the issuer's earliest next-key createdAt — the same value the rotation
// loop schedules its first tick from — so a freshly enabled (or re-enabled) rotation
// reports a next_rotation that matches when the loop will actually fire. A no-op once
// seeded, so the anchor stays stable across restarts and failover.
func (c *Core) seedOIDCKeyRotationState(ctx context.Context, storage sdklogical.Storage, issuer *OIDCIssuer) error {
	st, err := loadOIDCKeyRotationState(ctx, storage)
	if err != nil {
		return err
	}
	if st != nil {
		return nil
	}
	anchor, ok := issuer.NextKeyCreatedAt()
	if !ok {
		anchor = time.Now()
	}
	return saveOIDCKeyRotationState(ctx, storage, &oidcKeyRotationState{LastRotatedAt: anchor})
}

// recordOIDCKeyRotationOutcome persists the result of a signing-key rotation cycle. On
// success it advances the anchor and clears any recorded error; on failure it records the
// error (and its time) while leaving LastRotatedAt anchored on the last success, so a
// failing cycle neither resets the schedule nor hides the reason from the read API.
func (c *Core) recordOIDCKeyRotationOutcome(ctx context.Context, rotErr error) {
	storage := NewBarrierView(c.barrier, oidcIssuerStorePrefix)
	st, err := loadOIDCKeyRotationState(ctx, storage)
	if err != nil || st == nil {
		st = &oidcKeyRotationState{}
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
	if err := saveOIDCKeyRotationState(ctx, storage, st); err != nil {
		c.logger.Warn("oidc issuer: key rotation: persisting status failed", logger.Err(err))
	}
}
