package core

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stephnangue/warden/logger"
)

// InitInput represents the request body for the init operation
type InitInput struct {
	Body struct {
		// PGPKeys specifies an array of PGP public keys used to encrypt the output unseal keys.
		// The keys must be base64-encoded from their original binary representation.
		// The size of this array must be the same as SecretShares.
		PGPKeys []string `json:"pgp_keys,omitempty" doc:"PGP public keys for encrypting unseal keys"`

		// RootTokenPGPKey specifies a PGP public key used to encrypt the initial root token.
		// The key must be base64-encoded from its original binary representation.
		RootTokenPGPKey string `json:"root_token_pgp_key,omitempty" doc:"PGP public key for encrypting root token"`

		// SecretShares specifies the number of shares to split the root key into.
		SecretShares int `json:"secret_shares" default:"5" doc:"Number of key shares to generate"`

		// SecretThreshold specifies the number of shares required to reconstruct the root key.
		// This must be less than or equal to SecretShares.
		SecretThreshold int `json:"secret_threshold" default:"3" doc:"Number of key shares required to unseal"`

		// StoredShares specifies the number of shares that should be encrypted by the HSM and stored for auto-unsealing.
		// Currently must be the same as SecretShares. Only supported when using Auto Unseal.
		StoredShares int `json:"stored_shares,omitempty" doc:"Number of shares to store (auto-unseal only)"`

		// RecoveryShares specifies the number of shares to split the recovery key into.
		// Only available when using Auto Unseal.
		RecoveryShares int `json:"recovery_shares,omitempty" default:"5" doc:"Number of recovery key shares (auto-unseal only)"`

		// RecoveryThreshold specifies the number of shares required to reconstruct the recovery key.
		// This must be less than or equal to RecoveryShares. Only available when using Auto Unseal.
		RecoveryThreshold int `json:"recovery_threshold,omitempty" default:"3" doc:"Number of recovery shares required (auto-unseal only)"`

		// RecoveryPGPKeys specifies an array of PGP public keys used to encrypt the output recovery keys.
		// The keys must be base64-encoded from their original binary representation.
		// The size of this array must be the same as RecoveryShares. Only available when using Auto Unseal.
		RecoveryPGPKeys []string `json:"recovery_pgp_keys,omitempty" doc:"PGP public keys for encrypting recovery keys (auto-unseal only)"`
	}
}

// InitOutput represents the response from the init operation
type InitOutput struct {
	Body struct {
		// Keys contains the unseal keys (base64-encoded, potentially PGP-encrypted)
		Keys []string `json:"keys,omitempty" doc:"Unseal keys for unsealing Warden"`

		// KeysBase64 contains the base64-encoded unseal keys
		KeysBase64 []string `json:"keys_base64,omitempty" doc:"Base64-encoded unseal keys"`

		// RecoveryKeys contains the recovery keys (for auto-unseal, base64-encoded, potentially PGP-encrypted)
		RecoveryKeys []string `json:"recovery_keys,omitempty" doc:"Recovery keys (auto-unseal only)"`

		// RecoveryKeysBase64 contains the base64-encoded recovery keys
		RecoveryKeysBase64 []string `json:"recovery_keys_base64,omitempty" doc:"Base64-encoded recovery keys (auto-unseal only)"`

		// RootToken is the generated root token for system administration
		RootToken string `json:"root_token" doc:"The generated root token for system administration"`
	}
}

// Init initializes Warden with Shamir secret sharing and optional PGP encryption
func (h *SystemHandlers) Init(
	ctx context.Context,
	input *InitInput,
) (*InitOutput, error) {
	// Check if already initialized
	initialized, err := h.core.Initialized(ctx)
	if err != nil {
		h.logger.Error("failed to check initialization status", logger.Err(err))
		return nil, huma.Error500InternalServerError(fmt.Sprintf("Failed to check initialization status: %v", err))
	}
	if initialized {
		h.logger.Warn("attempted to initialize already initialized Warden")
		return nil, huma.Error400BadRequest("Warden is already initialized")
	}

	// Set defaults for secret_shares and secret_threshold if not provided
	secretShares := input.Body.SecretShares
	if secretShares == 0 {
		secretShares = 5
	}
	secretThreshold := input.Body.SecretThreshold
	if secretThreshold == 0 {
		secretThreshold = 3
	}

	// Validate parameters
	if secretThreshold > secretShares {
		return nil, huma.Error400BadRequest("secret_threshold cannot be greater than secret_shares")
	}
	if secretThreshold < 1 {
		return nil, huma.Error400BadRequest("secret_threshold must be at least 1")
	}
	if secretShares < 1 {
		return nil, huma.Error400BadRequest("secret_shares must be at least 1")
	}

	// Validate PGP keys match shares
	if len(input.Body.PGPKeys) > 0 && len(input.Body.PGPKeys) != secretShares {
		return nil, huma.Error400BadRequest(fmt.Sprintf("number of pgp_keys (%d) must match secret_shares (%d)", len(input.Body.PGPKeys), secretShares))
	}

	h.logger.Info("initializing Warden with Shamir secret sharing",
		logger.Int("secret_shares", secretShares),
		logger.Int("secret_threshold", secretThreshold))

	// Build barrier configuration
	barrierConfig := &SealConfig{
		SecretShares:    secretShares,
		SecretThreshold: secretThreshold,
		StoredShares:    uint(input.Body.StoredShares),
		PGPKeys:         input.Body.PGPKeys,
	}

	// Build recovery configuration (only for auto-unseal)
	var recoveryConfig *SealConfig
	if h.core.seal != nil && h.core.seal.RecoveryKeySupported() {
		recoveryShares := input.Body.RecoveryShares
		if recoveryShares == 0 {
			recoveryShares = 5
		}
		recoveryThreshold := input.Body.RecoveryThreshold
		if recoveryThreshold == 0 {
			recoveryThreshold = 3
		}

		// Validate recovery parameters
		if recoveryThreshold > recoveryShares {
			return nil, huma.Error400BadRequest("recovery_threshold cannot be greater than recovery_shares")
		}
		if len(input.Body.RecoveryPGPKeys) > 0 && len(input.Body.RecoveryPGPKeys) != recoveryShares {
			return nil, huma.Error400BadRequest(fmt.Sprintf("number of recovery_pgp_keys (%d) must match recovery_shares (%d)", len(input.Body.RecoveryPGPKeys), recoveryShares))
		}

		recoveryConfig = &SealConfig{
			SecretShares:    recoveryShares,
			SecretThreshold: recoveryThreshold,
			PGPKeys:         input.Body.RecoveryPGPKeys,
		}
	}

	// Initialize core
	initParams := &InitParams{
		BarrierConfig:   barrierConfig,
		RecoveryConfig:  recoveryConfig,
		RootTokenPGPKey: input.Body.RootTokenPGPKey,
	}

	result, err := h.core.Initialize(ctx, initParams)
	if err != nil {
		h.logger.Error("failed to initialize Warden", logger.Err(err))
		return nil, huma.Error500InternalServerError(fmt.Sprintf("Failed to initialize Warden: %v", err))
	}

	h.logger.Info("Warden initialized successfully")

	// Build response
	output := &InitOutput{}
	output.Body.RootToken = result.RootToken

	// Convert secret shares to base64 strings
	if len(result.SecretShares) > 0 {
		output.Body.Keys = make([]string, len(result.SecretShares))
		output.Body.KeysBase64 = make([]string, len(result.SecretShares))
		for i, share := range result.SecretShares {
			encoded := fmt.Sprintf("%x", share)
			output.Body.Keys[i] = encoded
			output.Body.KeysBase64[i] = encoded
		}
	}

	// Convert recovery shares to base64 strings
	if len(result.RecoveryShares) > 0 {
		output.Body.RecoveryKeys = make([]string, len(result.RecoveryShares))
		output.Body.RecoveryKeysBase64 = make([]string, len(result.RecoveryShares))
		for i, share := range result.RecoveryShares {
			encoded := fmt.Sprintf("%x", share)
			output.Body.RecoveryKeys[i] = encoded
			output.Body.RecoveryKeysBase64[i] = encoded
		}
	}

	return output, nil
}

// RevokeRootTokenOutput represents the response from the revoke operation
type RevokeRootTokenOutput struct {
	Body struct {
		Message string `json:"message" doc:"Success message"`
	}
}

// RevokeRootToken revokes the current root token
func (h *SystemHandlers) RevokeRootToken(
	ctx context.Context,
	input *struct{},
) (*RevokeRootTokenOutput, error) {
	// Only root can revoke root token
	principalID, ok := ctx.Value(SystemPrincipalIDKey).(string)
	if !ok || principalID != "root" {
		h.logger.Warn("revoke root token attempted by non-root principal",
			logger.String("principal_id", principalID))
		return nil, huma.Error403Forbidden("Only root principal can revoke root token")
	}

	h.logger.Info("revoking root token", logger.String("principal_id", principalID))

	if err := h.core.tokenStore.RevokeRootToken(); err != nil {
		h.logger.Error("failed to revoke root token", logger.Err(err))
		return nil, huma.Error500InternalServerError(fmt.Sprintf("Failed to revoke root token: %v", err))
	}

	output := &RevokeRootTokenOutput{}
	output.Body.Message = "Root token successfully revoked"
	return output, nil
}
