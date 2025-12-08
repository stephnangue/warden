package core

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stephnangue/warden/logger"
)

// InitOutput represents the response from the init operation
type InitOutput struct {
	Body struct {
		RootToken string `json:"root_token" doc:"The generated root token for system administration"`
	}
}

// Init generates a root token for system administration
func (h *SystemHandlers) Init(
	ctx context.Context,
	input *struct{},
) (*InitOutput, error) {
	// Check if already initialized
	if h.core.IsInitialized() {
		h.logger.Warn("attempted to initialize already initialized Warden")
		return nil, huma.Error400BadRequest("Warden is already initialized")
	}

	h.logger.Info("initializing Warden and generating root token")

	// Generate root token
	rootToken, err := h.core.tokenStore.GenerateRootToken()
	if err != nil {
		h.logger.Error("failed to generate root token", logger.Err(err))
		return nil, huma.Error500InternalServerError(fmt.Sprintf("Failed to generate root token: %v", err))
	}

	// Mark as initialized
	h.core.MarkInitialized()

	h.logger.Info("root token generated successfully")

	output := &InitOutput{}
	output.Body.RootToken = rootToken
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
