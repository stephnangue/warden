package jwt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathLogin returns the login path definition
func (b *jwtAuthBackend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"jwt": {
				Type:        framework.TypeString,
				Description: "JWT token to authenticate",
				Required:    true,
			},
			"role": {
				Type:        framework.TypeString,
				Description: "Role to assume after authentication",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Authenticate using a JWT token",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Authenticate using a JWT token",
			},
		},
		HelpSynopsis:    "Authenticate using a JWT token",
		HelpDescription: "This endpoint authenticates using a JWT token and returns authentication information.",
	}
}

// handleLogin handles the login operation
func (b *jwtAuthBackend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	// Get JWT token
	jwtToken := d.Get("jwt").(string)
	if jwtToken == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("missing jwt token")), nil
	}

	// Get role name
	roleName := d.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("missing role")), nil
	}

	// Check if backend is configured
	if b.config == nil || b.config.validator == nil {
		return &logical.Response{
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("JWT auth backend not configured"),
		}, nil
	}

	// Look up the role
	role, err := b.getRole(ctx, roleName)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if role == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("role %q not found", roleName)), nil
	}

	// Build expected claims - merge global config with role-specific
	expected := jwt.Expected{
		SigningAlgorithms: []jwt.Alg{jwt.RS256, jwt.RS384, jwt.RS512, jwt.ES256, jwt.ES384, jwt.ES512},
	}

	// Global issuer from config
	if b.config.BoundIssuer != "" {
		expected.Issuer = b.config.BoundIssuer
	}

	// Role-specific subject (overrides config)
	if role.BoundSubject != "" {
		expected.Subject = role.BoundSubject
	} else if b.config.BoundSubject != "" {
		expected.Subject = b.config.BoundSubject
	}

	// Role-specific audiences (overrides config)
	if len(role.BoundAudiences) > 0 {
		expected.Audiences = role.BoundAudiences
	} else if len(b.config.BoundAudiences) > 0 {
		expected.Audiences = b.config.BoundAudiences
	}

	claims, err := b.config.validator.Validate(ctx, jwtToken, expected)
	if err != nil {
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        err,
		}, nil
	}

	// Validate bound claims from config
	if err := validateBoundClaims(claims, b.config.BoundClaims); err != nil {
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        err,
		}, nil
	}

	// Validate bound claims from role
	if err := validateBoundClaims(claims, role.BoundClaims); err != nil {
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        err,
		}, nil
	}

	// Extract principal identity - use role's user_claim or fallback to config
	userClaim := role.UserClaim
	if userClaim == "" {
		userClaim = b.config.UserClaim
	}
	principalID := extractClaim(claims, userClaim)
	if principalID == "" {
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("no principal identity found in jwt"),
		}, nil
	}

	// Extract expiration time
	expValue, ok := claims["exp"]
	if !ok {
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("no exp found in jwt"),
		}, nil
	}

	// Parse expiration time
	var expTimestamp int64
	switch v := expValue.(type) {
	case float64:
		expTimestamp = int64(v)
	case int64:
		expTimestamp = v
	case int:
		expTimestamp = int64(v)
	default:
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("invalid exp format in jwt"),
		}, nil
	}

	jwtExpiration := time.Unix(expTimestamp, 0)
	jwtTTL := time.Until(jwtExpiration)

	if jwtTTL <= 0 {
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("jwt has expired"),
		}, nil
	}

	// Calculate effective TTL: min(role.TokenTTL, jwtTTL)
	// The token should never outlive the JWT's actual expiration
	effectiveTTL := jwtTTL
	if role.TokenTTL > 0 && role.TokenTTL < jwtTTL {
		effectiveTTL = role.TokenTTL
	}

	// Return auth response using role configuration
	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID:    principalID,
			RoleName:       roleName,
			Policies:       role.TokenPolicies,
			CredentialSpec: role.CredSpecName,
			TokenType:      role.TokenType,
			TokenTTL:       effectiveTTL,
			ClientIP:       req.ClientIP,
			ClientToken:    jwtToken, // Pass JWT for token types that need the original value
		},
		Data: map[string]any{
			"principal_id": principalID,
			"role":         roleName,
		},
	}, nil
}
