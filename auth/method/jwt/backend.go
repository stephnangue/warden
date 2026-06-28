package jwt

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/cap/jwt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// JWTAuthConfig represents JWT authentication configuration. Exactly one
// of OIDCDiscoveryURL, JWKSURL, or JWTValidationPubKeys must be set; the
// chosen field determines how token signatures are verified.
type JWTAuthConfig struct {
	// OIDC Discovery
	OIDCDiscoveryURL string `json:"oidc_discovery_url,omitempty"`
	OIDCDiscoveryCA  string `json:"oidc_discovery_ca_pem,omitempty"`

	// JWT/JWKS
	JWKSURL              string   `json:"jwks_url,omitempty"`
	JWKSCA               string   `json:"jwks_ca_pem,omitempty"`
	JWTValidationPubKeys []string `json:"jwt_validation_pubkeys,omitempty"`

	// Validation
	BoundIssuer       string         `json:"bound_issuer,omitempty"`
	BoundAudiences    []string       `json:"bound_audiences,omitempty"`
	BoundSubject      string         `json:"bound_subject,omitempty"`
	BoundClaims       map[string]any `json:"bound_claims,omitempty"`
	UserClaim         string         `json:"user_claim,omitempty" default:"sub"`
	GroupsClaim       string         `json:"groups_claim,omitempty"`
	GroupPolicyPrefix string         `json:"group_policy_prefix,omitempty"`

	// Token settings
	TokenTTL time.Duration `json:"token_ttl" default:"1h"`

	// Default role for transparent operations when no role is specified
	DefaultRole string `json:"default_role,omitempty"`

	// Internal
	validator *jwt.Validator `json:"-"`
	keySet    jwt.KeySet     `json:"-"`
}

// jwtAuthBackend is the framework-based JWT authentication backend
type jwtAuthBackend struct {
	*framework.Backend
	config      *JWTAuthConfig
	configMu    sync.RWMutex
	logger      *logger.GatedLogger
	storageView sdklogical.Storage
}

var _ logical.Factory = Factory

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
				"introspect/roles",
			},
		},
		Paths: []*framework.Path{
			b.pathLogin(),
			b.pathConfig(),
			b.pathRole(),
			b.pathRoleList(),
			b.pathIntrospect(),
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
	if config.UserClaim == "" {
		config.UserClaim = "sub"
	}

	// Exactly one of the three key sources must be set; the chosen field
	// determines how token signatures are verified.
	hasOIDC := config.OIDCDiscoveryURL != ""
	hasJWKS := config.JWKSURL != ""
	hasPubKeys := len(config.JWTValidationPubKeys) > 0

	sourcesSet := 0
	if hasOIDC {
		sourcesSet++
	}
	if hasJWKS {
		sourcesSet++
	}
	if hasPubKeys {
		sourcesSet++
	}
	if sourcesSet != 1 {
		return fmt.Errorf("exactly one of oidc_discovery_url, jwks_url, or jwt_validation_pubkeys must be set (got %d)", sourcesSet)
	}

	switch {
	case hasOIDC:
		if err := verifyOIDCDiscoveryURLReachable(ctx, config.OIDCDiscoveryURL, config.OIDCDiscoveryCA); err != nil {
			return fmt.Errorf("oidc_discovery_url is not reachable: %v", err)
		}
		keySet, err = jwt.NewOIDCDiscoveryKeySet(ctx, config.OIDCDiscoveryURL, config.OIDCDiscoveryCA)
		if err != nil {
			return fmt.Errorf("failed to create OIDC discovery keyset: %v", err)
		}
	case hasJWKS:
		if err := verifyJWKSURLReachable(ctx, config.JWKSURL, config.JWKSCA); err != nil {
			return fmt.Errorf("jwks_url is not reachable: %v", err)
		}
		keySet, err = jwt.NewJSONWebKeySet(ctx, config.JWKSURL, config.JWKSCA)
		if err != nil {
			return fmt.Errorf("failed to create JWKS keyset: %v", err)
		}
	case hasPubKeys:
		pubKeys := make([]crypto.PublicKey, 0, len(config.JWTValidationPubKeys))
		for i, pemStr := range config.JWTValidationPubKeys {
			pubKey, err := jwt.ParsePublicKeyPEM([]byte(pemStr))
			if err != nil {
				return fmt.Errorf("jwt_validation_pubkeys[%d]: failed to parse PEM: %v", i, err)
			}
			pubKeys = append(pubKeys, pubKey)
		}
		keySet, err = jwt.NewStaticKeySet(pubKeys)
		if err != nil {
			return fmt.Errorf("failed to create static keyset: %v", err)
		}
	}

	config.keySet = keySet

	// Create validator
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		return fmt.Errorf("failed to create validator: %v", err)
	}
	config.validator = validator

	b.configMu.Lock()
	b.config = config
	b.configMu.Unlock()
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

// SensitiveConfigFields returns the list of config fields that should be masked in output.
// All current JWT auth config fields are public material — CA certs validate TLS servers
// during the handshake, and static public keys are public by definition — so nothing is masked.
func (b *jwtAuthBackend) SensitiveConfigFields() []string {
	return nil
}

// verifyURLReachable checks that a URL is reachable and returns HTTP 200
func verifyURLReachable(ctx context.Context, url string, caPEM string) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Configure TLS if CA certificate is provided
	if caPEM != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(caPEM)) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// verifyJWKSURLReachable checks that the JWKS URL is reachable
func verifyJWKSURLReachable(ctx context.Context, jwksURL string, caPEM string) error {
	return verifyURLReachable(ctx, jwksURL, caPEM)
}

// verifyOIDCDiscoveryURLReachable checks that the OIDC discovery endpoint is reachable.
// The oidcDiscoveryURL is the issuer URL (e.g., http://localhost:4444); this function
// appends /.well-known/openid-configuration to match what the cap/jwt library does.
func verifyOIDCDiscoveryURLReachable(ctx context.Context, oidcDiscoveryURL string, caPEM string) error {
	wellKnown := strings.TrimSuffix(oidcDiscoveryURL, "/") + "/.well-known/openid-configuration"
	return verifyURLReachable(ctx, wellKnown, caPEM)
}
