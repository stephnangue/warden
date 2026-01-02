package auth

import (
	"context"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// TokenStore defines the minimal interface that auth methods need from the token store
// This avoids circular dependencies and allows the core package to provide the implementation
type TokenStore interface {
	GenerateToken(ctx context.Context, tokenType string, authData *logical.AuthData) (*logical.TokenEntry, error)
	ResolveToken(ctx context.Context, tokenValue string) (string, string, error)
	GetToken(tokenValue string) *logical.TokenEntry
	GetMetrics() map[string]int64
	Close()
	GenerateRootToken() (string, error)
	RevokeRootToken() error
}

type Factory interface {
	Type() string
	Class() string
	Create(ctx context.Context,
		mountPath string,
		description string,
		accessor string,
		config map[string]any,
		logger *logger.GatedLogger,
		tokenStore TokenStore,
		roles *authorize.RoleRegistry,
		accessControl *authorize.AccessControl,
		auditAccess audit.AuditAccess,
		storageView sdklogical.Storage) (logical.Backend, error)
	Initialize(logger *logger.GatedLogger) error
	ValidateConfig(config map[string]any) error
}
