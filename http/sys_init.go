package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// InitRequest represents the request body for the init operation
type InitRequest struct {
	// SecretShares specifies the number of shares to split the root key into.
	SecretShares int `json:"secret_shares"`

	// SecretThreshold specifies the number of shares required to reconstruct the root key.
	// This must be less than or equal to SecretShares.
	SecretThreshold int `json:"secret_threshold"`

	// PGPKeys specifies an array of PGP public keys used to encrypt the output unseal keys.
	// The keys must be base64-encoded from their original binary representation.
	// The size of this array must be the same as SecretShares.
	PGPKeys []string `json:"pgp_keys,omitempty"`

	// RootTokenPGPKey specifies a PGP public key used to encrypt the initial root token.
	// The key must be base64-encoded from its original binary representation.
	RootTokenPGPKey string `json:"root_token_pgp_key,omitempty"`

	// StoredShares specifies the number of shares that should be encrypted by the HSM
	// and stored for auto-unsealing. Currently must be the same as SecretShares.
	// Only supported when using Auto Unseal.
	StoredShares int `json:"stored_shares,omitempty"`

	// RecoveryShares specifies the number of shares to split the recovery key into.
	// Only available when using Auto Unseal.
	RecoveryShares int `json:"recovery_shares,omitempty"`

	// RecoveryThreshold specifies the number of shares required to reconstruct the recovery key.
	// This must be less than or equal to RecoveryShares.
	// Only available when using Auto Unseal.
	RecoveryThreshold int `json:"recovery_threshold,omitempty"`

	// RecoveryPGPKeys specifies an array of PGP public keys used to encrypt the output recovery keys.
	// The keys must be base64-encoded from their original binary representation.
	// The size of this array must be the same as RecoveryShares.
	// Only available when using Auto Unseal.
	RecoveryPGPKeys []string `json:"recovery_pgp_keys,omitempty"`
}

// InitResponse represents the response from the init operation
type InitResponse struct {
	// Keys contains the unseal keys (hex-encoded)
	Keys []string `json:"keys,omitempty"`

	// KeysBase64 contains the base64-encoded unseal keys
	KeysBase64 []string `json:"keys_base64,omitempty"`

	// RecoveryKeys contains the recovery keys (for auto-unseal, hex-encoded)
	RecoveryKeys []string `json:"recovery_keys,omitempty"`

	// RecoveryKeysBase64 contains the base64-encoded recovery keys
	RecoveryKeysBase64 []string `json:"recovery_keys_base64,omitempty"`

	// RootToken is the generated root token for system administration
	RootToken string `json:"root_token"`
}

// InitStatusResponse represents the response from the init status check
type InitStatusResponse struct {
	Initialized bool `json:"initialized"`
}

// handleSysInit returns an HTTP handler for the /v1/sys/init endpoint.
// It handles:
//   - GET: Check initialization status
//   - PUT/POST: Initialize Warden with Shamir secret sharing
func handleSysInit(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleSysInitGet(c, w, r, log)
		case http.MethodPut, http.MethodPost:
			handleSysInitPut(c, w, r, log)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
}

// handleSysInitGet handles GET /v1/sys/init to check initialization status
func handleSysInitGet(c *core.Core, w http.ResponseWriter, r *http.Request, log *logger.GatedLogger) {
	initialized, err := c.Initialized(r.Context())
	if err != nil {
		log.Error("failed to check initialization status", logger.Err(err))
		respondError(w, http.StatusInternalServerError, "failed to check initialization status")
		return
	}

	respondOk(w, &InitStatusResponse{
		Initialized: initialized,
	})
}

// handleSysInitPut handles PUT/POST /v1/sys/init to initialize Warden
func handleSysInitPut(c *core.Core, w http.ResponseWriter, r *http.Request, log *logger.GatedLogger) {
	// Check if already initialized
	initialized, err := c.Initialized(r.Context())
	if err != nil {
		log.Error("failed to check initialization status", logger.Err(err))
		respondError(w, http.StatusInternalServerError, "failed to check initialization status")
		return
	}
	if initialized {
		log.Warn("attempted to initialize already initialized Warden")
		respondError(w, http.StatusBadRequest, "Warden is already initialized")
		return
	}

	// Parse request body
	var req InitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Error("failed to parse init request", logger.Err(err))
		respondError(w, http.StatusBadRequest, "failed to parse request body")
		return
	}

	// Set defaults for secret_shares and secret_threshold if not provided
	secretShares := req.SecretShares
	if secretShares == 0 {
		secretShares = 5
	}
	secretThreshold := req.SecretThreshold
	if secretThreshold == 0 {
		secretThreshold = 3
	}

	// Validate parameters
	if secretThreshold > secretShares {
		respondError(w, http.StatusBadRequest, "secret_threshold cannot be greater than secret_shares")
		return
	}
	if secretThreshold < 1 {
		respondError(w, http.StatusBadRequest, "secret_threshold must be at least 1")
		return
	}
	if secretShares < 1 {
		respondError(w, http.StatusBadRequest, "secret_shares must be at least 1")
		return
	}

	// Validate PGP keys match shares
	if len(req.PGPKeys) > 0 && len(req.PGPKeys) != secretShares {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("number of pgp_keys (%d) must match secret_shares (%d)", len(req.PGPKeys), secretShares))
		return
	}

	log.Info("initializing Warden with Shamir secret sharing",
		logger.Int("secret_shares", secretShares),
		logger.Int("secret_threshold", secretThreshold))

	// Build barrier configuration
	barrierConfig := &core.SealConfig{
		SecretShares:    secretShares,
		SecretThreshold: secretThreshold,
		StoredShares:    uint(req.StoredShares),
		PGPKeys:         req.PGPKeys,
	}

	// Build recovery configuration (only for auto-unseal)
	var recoveryConfig *core.SealConfig
	if c.SealAccess().RecoveryKeySupported() {
		recoveryShares := req.RecoveryShares
		if recoveryShares == 0 {
			recoveryShares = 5
		}
		recoveryThreshold := req.RecoveryThreshold
		if recoveryThreshold == 0 {
			recoveryThreshold = 3
		}

		// Validate recovery parameters
		if recoveryThreshold > recoveryShares {
			respondError(w, http.StatusBadRequest, "recovery_threshold cannot be greater than recovery_shares")
			return
		}
		if len(req.RecoveryPGPKeys) > 0 && len(req.RecoveryPGPKeys) != recoveryShares {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("number of recovery_pgp_keys (%d) must match recovery_shares (%d)", len(req.RecoveryPGPKeys), recoveryShares))
			return
		}

		recoveryConfig = &core.SealConfig{
			SecretShares:    recoveryShares,
			SecretThreshold: recoveryThreshold,
			PGPKeys:         req.RecoveryPGPKeys,
		}
	}

	// Initialize core
	initParams := &core.InitParams{
		BarrierConfig:   barrierConfig,
		RecoveryConfig:  recoveryConfig,
		RootTokenPGPKey: req.RootTokenPGPKey,
	}

	result, err := c.Initialize(r.Context(), initParams)
	if err != nil {
		log.Error("failed to initialize Warden", logger.Err(err))
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to initialize Warden: %v", err))
		return
	}

	log.Info("Warden initialized successfully")

	// Build response
	resp := &InitResponse{
		RootToken: result.RootToken,
	}

	// Convert secret shares to hex strings
	if len(result.SecretShares) > 0 {
		resp.Keys = make([]string, len(result.SecretShares))
		resp.KeysBase64 = make([]string, len(result.SecretShares))
		for i, share := range result.SecretShares {
			encoded := fmt.Sprintf("%x", share)
			resp.Keys[i] = encoded
			resp.KeysBase64[i] = encoded
		}
	}

	// Convert recovery shares to hex strings
	if len(result.RecoveryShares) > 0 {
		resp.RecoveryKeys = make([]string, len(result.RecoveryShares))
		resp.RecoveryKeysBase64 = make([]string, len(result.RecoveryShares))
		for i, share := range result.RecoveryShares {
			encoded := fmt.Sprintf("%x", share)
			resp.RecoveryKeys[i] = encoded
			resp.RecoveryKeysBase64[i] = encoded
		}
	}

	respondOk(w, resp)
}
