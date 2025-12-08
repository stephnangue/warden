package jwt

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
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
	mountPath     string
	description   string
	logger        logger.Logger
	accessor      string
	config        *JWTAuthConfig
	authType      string
	backendClass  string
	router        *chi.Mux
	tokenStore    token.TokenStore
	roles         *authorize.RoleRegistry
	accessControl *authorize.AccessControl
	auditAccess   audit.AuditAccess
	validateFunc  func(conf map[string]any) error
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

func (m *JWTAuthMethod) Config() map[string]any {
	if m.config == nil {
		return map[string]any{}
	}

	return map[string]any{
		"name":                    m.config.Name,
		"mode":                    m.config.Mode,
		"oidc_discovery_url":      m.config.OIDCDiscoveryURL,
		"oidc_discovery_ca_pem":   m.config.OIDCDiscoveryCA,
		"jwks_url":                m.config.JWKSURL,
		"jwks_ca_pem":             m.config.JWKSCA,
		"jwt_validation_pubkeys":  m.config.JWTValidationPubKeys,
		"bound_issuer":            m.config.BoundIssuer,
		"bound_audiences":         m.config.BoundAudiences,
		"bound_subject":           m.config.BoundSubject,
		"bound_claims":            m.config.BoundClaims,
		"claim_mappings":          m.config.ClaimMappings,
		"user_claim":              m.config.UserClaim,
		"groups_claim":            m.config.GroupsClaim,
		"token_ttl":               m.config.TokenTTL.String(),
		"auth_deadline":           m.config.AuthDeadline.String(),
	}
}

func (m *JWTAuthMethod) Setup(conf map[string]any) error {
	// Build current configuration as map
	currentConfig := make(map[string]interface{})
	if m.config != nil {
		currentConfig["name"] = m.config.Name
		currentConfig["mode"] = m.config.Mode
		currentConfig["oidc_discovery_url"] = m.config.OIDCDiscoveryURL
		currentConfig["oidc_discovery_ca_pem"] = m.config.OIDCDiscoveryCA
		currentConfig["jwks_url"] = m.config.JWKSURL
		currentConfig["jwks_ca_pem"] = m.config.JWKSCA
		currentConfig["jwt_validation_pubkeys"] = m.config.JWTValidationPubKeys
		currentConfig["bound_issuer"] = m.config.BoundIssuer
		currentConfig["bound_audiences"] = m.config.BoundAudiences
		currentConfig["bound_subject"] = m.config.BoundSubject
		currentConfig["bound_claims"] = m.config.BoundClaims
		currentConfig["claim_mappings"] = m.config.ClaimMappings
		currentConfig["user_claim"] = m.config.UserClaim
		currentConfig["groups_claim"] = m.config.GroupsClaim
		currentConfig["token_ttl"] = m.config.TokenTTL
		currentConfig["auth_deadline"] = m.config.AuthDeadline
	}

	// Merge incoming config with current config (incoming takes precedence)
	maps.Copy(currentConfig, conf)

	// Validate the merged configuration
	if m.validateFunc != nil {
		if err := m.validateFunc(currentConfig); err != nil {
			m.logger.Warn("config validation failed", logger.Err(err))
			return err
		}
	}

	// Setup the new configuration
	ctx := context.Background()
	newConfig, err := setupConfig(ctx, currentConfig)
	if err != nil {
		m.logger.Error("failed to setup config", logger.Err(err))
		return err
	}

	// Update the auth method configuration
	m.config = newConfig

	m.logger.Info("auth method configuration updated",
		logger.String("mode", m.config.Mode),
		logger.String("bound_issuer", m.config.BoundIssuer),
		logger.String("user_claim", m.config.UserClaim),
	)

	return nil
}

func (m *JWTAuthMethod) setupRouter() {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)

	r.Route("/", func(roles chi.Router) {
		roles.HandleFunc("/login", m.handleLogin)
	})

	m.router = r
}

type JWTAuthMethodFactory struct {
	logger logger.Logger
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

func (f *JWTAuthMethodFactory) ValidateConfig(conf map[string]any) error {
	config, err := mapToJWTAuthConfig(conf)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Validate Mode
	if config.Mode != "jwt" && config.Mode != "oidc" {
		return fmt.Errorf("mode must be 'jwt' or 'oidc', got: %s", config.Mode)
	}

	// Mode-specific validation
	switch config.Mode {
	case "oidc":
		if config.OIDCDiscoveryURL == "" {
			return fmt.Errorf("oidc_discovery_url is required when type is 'oidc'")
		}
	case "jwt":
		if config.JWKSURL == "" && len(config.JWTValidationPubKeys) == 0 {
			return fmt.Errorf("either jwks_url or jwt_validation_pubkeys is required when type is 'jwt'")
		}
	}

	// Validate UserClaim
	if config.UserClaim == "" {
		// This is OK, we'll use default "sub"
	}

	// Validate BoundAudiences format
	for _, aud := range config.BoundAudiences {
		if strings.TrimSpace(aud) == "" {
			return fmt.Errorf("bound_audiences contains empty value")
		}
	}

	// Validate BoundIssuer
	if config.BoundIssuer != "" && strings.TrimSpace(config.BoundIssuer) == "" {
		return fmt.Errorf("bound_issuer cannot be empty string")
	}

	// Validate BoundSubject
	if config.BoundSubject != "" && strings.TrimSpace(config.BoundSubject) == "" {
		return fmt.Errorf("bound_subject cannot be empty string")
	}

	// Validate TokenTTL
	if config.TokenTTL < 0 {
		return fmt.Errorf("token_ttl must be positive or zero")
	}

	// Validate AuthDeadline
	if config.AuthDeadline < 0 {
		return fmt.Errorf("auth_deadline must be positive or zero")
	}

	if(config.AuthDeadline > config.TokenTTL) {
		return fmt.Errorf("auth_deadline must be less than token_ttl")
	}

	return nil
}

func (f *JWTAuthMethodFactory) Create(
	ctx context.Context,
	mountPath string,
	description string,
	accessor string,
	conf map[string]any,
	log logger.Logger,
	tokenStore token.TokenStore,
	roles *authorize.RoleRegistry,
	accessControl *authorize.AccessControl,
	auditAccess audit.AuditAccess,
) (logical.Backend, error) {

	method := &JWTAuthMethod{
		mountPath:     mountPath,
		description:   description,
		accessor:      accessor,
		logger:        log.WithSubsystem(f.Type()).WithSubsystem(accessor),
		authType:      f.Type(),
		backendClass:  f.Class(),
		tokenStore:    tokenStore,
		roles:         roles,
		accessControl: accessControl,
		auditAccess:   auditAccess,
	}

	method.setupRouter()

	method.validateFunc = f.ValidateConfig

	// err := method.Setup(conf)
	// if err != nil {
	// 	return nil, err
	// }

	return method, nil
}

func setupConfig(ctx context.Context, conf map[string]any) (*JWTAuthConfig, error) {
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
		config.AuthDeadline = config.TokenTTL
	}
	if config.UserClaim == "" {
		config.UserClaim = "sub"
	}

	// Initialize KeySet based on Mode
	switch config.Mode {
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

	return config, nil
}


