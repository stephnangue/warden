package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/role"
)

// JWTAuthConfig represents JWT/OIDC authentication configuration
type JWTAuthConfig struct {
	Name               string            `json:"name"`
	Type               string            `json:"type" default:"jwt"` // "jwt" or "oidc"
	
	// OIDC Discovery
	OIDCDiscoveryURL   string            `json:"oidc_discovery_url,omitempty"`
	OIDCDiscoveryCA    string            `json:"oidc_discovery_ca_pem,omitempty"`
	
	// JWT/JWKS
	JWKSURL            string            `json:"jwks_url,omitempty"`
	JWKSCA             string            `json:"jwks_ca_pem,omitempty"`
	JWTValidationPubKeys []string        `json:"jwt_validation_pubkeys,omitempty"`
	
	// Validation
	BoundIssuer        string            `json:"bound_issuer,omitempty"`
	BoundAudiences     []string          `json:"bound_audiences,omitempty"`
	BoundSubject       string            `json:"bound_subject,omitempty"`
	BoundClaims        map[string]any    `json:"bound_claims,omitempty"`
	ClaimMappings      map[string]string `json:"claim_mappings,omitempty"`
	UserClaim          string            `json:"user_claim,omitempty" default:"sub"`
	GroupsClaim        string            `json:"groups_claim,omitempty" default:"groups"`
	
	// Token settings
	TokenTTL           time.Duration     `json:"token_ttl" default:"1h"`
	AuthDeadline       time.Duration     `json:"token_max_ttl" default:"10m"`
	
	// Internal
	validator          *jwt.Validator    `json:"-"`
	keySet             jwt.KeySet        `json:"-"`
}

// JWTLoginRequest represents the login request
type JWTLoginRequest struct {
	JWT  string `json:"jwt"`
	Role string `json:"role"`
}

func (r *JWTLoginRequest) ToMap() map[string]interface{} {
    return map[string]interface{}{
        "jwt":  r.JWT,
        "role": r.Role,
    }
}

type JWTAuthMethod struct {
	mountPath          string
	description        string
	logger             logger.Logger
	accessor           string
	config             *JWTAuthConfig
	authType           string
	backendClass       string
	router             *chi.Mux
	tokenStore         token.TokenStore
	roles              *role.RoleRegistry
	accessControl      *authorize.AccessControl
	auditAccess       audit.AuditAccess
}

func (m *JWTAuthMethod) GetType() string {
	return m.authType
}

func (m *JWTAuthMethod) GetClass() string {
	return m.backendClass
}

func (m *JWTAuthMethod) GetDescription() string {
	return m.description
}

func (m *JWTAuthMethod) GetAccessor() string {
	return m.accessor
}

func (m *JWTAuthMethod) Cleanup() {
}

func (m *JWTAuthMethod) setupRouter() {
	r := chi.NewRouter()

	r.Use(middleware.RealIP) 

	r.Route("/", func(roles chi.Router) {
		roles.Post("/login", m.handleLogin)
	})

	m.router = r
}


type JWTAuthMethodFactory struct{
	logger             logger.Logger
}

func (f *JWTAuthMethodFactory) Type() string {
	return "jwt"
}

func (f *JWTAuthMethodFactory) Class() string {
	return "auth"
}

func (f *JWTAuthMethodFactory) Initialize(log logger.Logger) error {
	f.logger = log.WithSubsystem(f.Type())

	return nil
}

func (f *JWTAuthMethodFactory) Create(
	ctx context.Context, 
	mountPath string, 
	description string, 
	accessor string, 
	conf map[string]any, 
	logger logger.Logger, 
	tokenStore token.TokenStore, 
	roles *role.RoleRegistry, 
	accessControl *authorize.AccessControl,
	auditAccess audit.AuditAccess,
	) (logical.Backend, error) {
	config, err := mapToJWTAuthConfig(conf)
	if err != nil {
		return nil, err
	}

	var keySet jwt.KeySet

	// Set defaults
	if config.TokenTTL == 0 {
		config.TokenTTL = 1 * time.Hour
	}
	if config.AuthDeadline == 0 {
		config.AuthDeadline = 10 * time.Minute
	}
	if config.UserClaim == "" {
		config.UserClaim = "sub"
	}

	// Initialize KeySet based on type
	switch config.Type {
	case "oidc":
		if config.OIDCDiscoveryURL == "" {
			return nil, fmt.Errorf("oidc_discovery_url is required for OIDC type")
		}
		keySet, err = jwt.NewOIDCDiscoveryKeySet(ctx, config.OIDCDiscoveryURL, config.OIDCDiscoveryCA)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC discovery keyset: %v", err)
		}

	case "jwt":
		if config.JWKSURL != "" {
			// Use JWKS URL
			keySet, err = jwt.NewJSONWebKeySet(ctx, config.JWKSURL, config.JWKSCA)
			if err != nil {
				return nil, fmt.Errorf("failed to create JWKS keyset: %v", err)
			}
		} else if len(config.JWTValidationPubKeys) > 0 {
			// Use static public keys
			// For now, we'll use JWKS approach - you'd need to parse PEM keys for static keys
			return nil, fmt.Errorf("static public keys not yet implemented, use jwks_url")
		} else {
			return nil, fmt.Errorf("either jwks_url or jwt_validation_pubkeys is required for JWT type")
		}

	default:
		return nil, fmt.Errorf("invalid type: must be 'jwt' or 'oidc'")
	}

	config.keySet = keySet

	// Create validator
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %v", err)
	}
	config.validator = validator

	method := &JWTAuthMethod{
		mountPath: mountPath,
		description: description,
		accessor: accessor,
		logger: logger.WithSubsystem(f.Type()).WithSubsystem(accessor),
		config: config,
		authType: f.Type(),
		backendClass: f.Class(),
		tokenStore: tokenStore,
		roles: roles,
		accessControl: accessControl,
		auditAccess: auditAccess,
	}

	method.setupRouter()

	return method, nil
}