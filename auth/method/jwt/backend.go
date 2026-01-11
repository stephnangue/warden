package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/cap/jwt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// JWTAuthConfig represents JWT/OIDC authentication configuration
type JWTAuthConfig struct {
	Name string `json:"name"`
	Mode string `json:"mode" default:"jwt"` // "jwt" or "oidc"

	// OIDC Discovery
	OIDCDiscoveryURL string `json:"oidc_discovery_url,omitempty"`
	OIDCDiscoveryCA  string `json:"oidc_discovery_ca_pem,omitempty"`

	// JWT/JWKS
	JWKSURL              string   `json:"jwks_url,omitempty"`
	JWKSCA               string   `json:"jwks_ca_pem,omitempty"`
	JWTValidationPubKeys []string `json:"jwt_validation_pubkeys,omitempty"`

	// Validation
	BoundIssuer    string            `json:"bound_issuer,omitempty"`
	BoundAudiences []string          `json:"bound_audiences,omitempty"`
	BoundSubject   string            `json:"bound_subject,omitempty"`
	BoundClaims    map[string]any    `json:"bound_claims,omitempty"`
	ClaimMappings  map[string]string `json:"claim_mappings,omitempty"`
	UserClaim      string            `json:"user_claim,omitempty" default:"sub"`
	GroupsClaim    string            `json:"groups_claim,omitempty" default:"groups"`

	// Token settings
	TokenTTL     time.Duration `json:"token_ttl" default:"1h"`
	AuthDeadline time.Duration `json:"auth_deadline" default:"10m"`

	// Internal
	validator *jwt.Validator `json:"-"`
	keySet    jwt.KeySet     `json:"-"`
}

// jwtAuthBackend is the framework-based JWT authentication backend
type jwtAuthBackend struct {
	*framework.Backend
	config      *JWTAuthConfig
	logger      *logger.GatedLogger
	storageView sdklogical.Storage
}

// Factory creates a new JWT auth backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &jwtAuthBackend{
		logger:      conf.Logger,
		storageView: conf.StorageView,
	}

	b.Backend = &framework.Backend{
		Help:         jwtAuthHelp,
		BackendType:  "jwt",
		BackendClass: logical.ClassAuth,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: []*framework.Path{
			b.pathLogin(),
			b.pathConfig(),
			b.pathRole(),
			b.pathRoleList(),
		},
	}

	// Setup the backend with configuration
	if err := b.Backend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	// Initialize JWT config if provided
	if len(conf.Config) > 0 {
		if err := b.setupJWTConfig(ctx, conf.Config); err != nil {
			return nil, fmt.Errorf("failed to setup JWT config: %w", err)
		}
	}

	return b, nil
}

// setupJWTConfig initializes the JWT configuration
func (b *jwtAuthBackend) setupJWTConfig(ctx context.Context, conf map[string]any) error {
	config, err := mapToJWTAuthConfig(conf)
	if err != nil {
		return err
	}

	var keySet jwt.KeySet

	// Set defaults
	if config.TokenTTL == 0 {
		config.TokenTTL = 1 * time.Hour
	}
	if config.AuthDeadline == 0 {
		config.AuthDeadline = config.TokenTTL
	}
	if config.UserClaim == "" {
		config.UserClaim = "sub"
	}

	// Initialize KeySet based on Mode
	switch config.Mode {
	case "oidc":
		if config.OIDCDiscoveryURL == "" {
			return fmt.Errorf("oidc_discovery_url is required for OIDC mode")
		}
		keySet, err = jwt.NewOIDCDiscoveryKeySet(ctx, config.OIDCDiscoveryURL, config.OIDCDiscoveryCA)
		if err != nil {
			return fmt.Errorf("failed to create OIDC discovery keyset: %v", err)
		}

	case "jwt":
		if config.JWKSURL != "" {
			keySet, err = jwt.NewJSONWebKeySet(ctx, config.JWKSURL, config.JWKSCA)
			if err != nil {
				return fmt.Errorf("failed to create JWKS keyset: %v", err)
			}
		} else if len(config.JWTValidationPubKeys) > 0 {
			return fmt.Errorf("static public keys not yet implemented, use jwks_url")
		} else {
			return fmt.Errorf("either jwks_url or jwt_validation_pubkeys is required for JWT mode")
		}

	default:
		return fmt.Errorf("invalid mode: must be 'jwt' or 'oidc'")
	}

	config.keySet = keySet

	// Create validator
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		return fmt.Errorf("failed to create validator: %v", err)
	}
	config.validator = validator

	b.config = config
	return nil
}

// Initialize loads persisted config from storage
func (b *jwtAuthBackend) Initialize(ctx context.Context) error {
	if b.storageView == nil {
		return nil
	}

	// Load persisted config from storage
	entry, err := b.storageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var configMap map[string]any
		if err := entry.DecodeJSON(&configMap); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		if err := b.setupJWTConfig(ctx, configMap); err != nil {
			return fmt.Errorf("failed to setup JWT config from storage: %w", err)
		}
	}
	return nil
}

