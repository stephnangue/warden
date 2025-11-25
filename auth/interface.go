package auth

import (
	"context"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/role"
)

type Factory interface {
	Type() string
	Class() string
	Create(ctx context.Context, 
		mountPath string, 
		description string, 
		accessor string, 
		config map[string]any, 
		logger logger.Logger, 
		tokenStore token.TokenStore, 
		roles *role.RoleRegistry,  
		accessControl *authorize.AccessControl,
		auditAccess  audit.AuditAccess) (logical.Backend, error)
	Initialize(logger logger.Logger) error
}