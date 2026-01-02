package provider

import (
	"context"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)


type Factory interface {
	Type() string
	Class() string
	Create(ctx context.Context,
		mountPath string,
		description string,
		accessor string,
		config map[string]any,
		logger *logger.GatedLogger,
		tokenAccess logical.TokenAccess,
		roles *authorize.RoleRegistry,
		credSources *cred.CredSourceRegistry,
		auditAccess audit.AuditAccess,
		storageView sdklogical.Storage) (logical.Backend, error)
	Initialize(logger *logger.GatedLogger) error
	// ValidateConfig validates provider-specific configuration
	ValidateConfig(config map[string]any) error
}
