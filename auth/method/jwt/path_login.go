package jwt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
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
				Description: "Role to assume after authentication (falls back to default_role if configured)",
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

	// Get role name — fall back to default_role if configured
	roleName := d.Get("role").(string)
	if roleName == "" && b.config != nil && b.config.DefaultRole != "" {
		roleName = b.config.DefaultRole
	}
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
		b.logger.Warn("login failed: role not found", lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
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
		b.logger.Warn("login failed: JWT validation error", lgr.Err(err), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	// Validate bound claims from config
	if err := validateBoundClaims(claims, b.config.BoundClaims); err != nil {
		b.logger.Warn("login failed: config bound claims check", lgr.Err(err), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	// Validate bound claims from role
	if err := validateBoundClaims(claims, role.BoundClaims); err != nil {
		b.logger.Warn("login failed: role bound claims check", lgr.Err(err), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	// Validate bound URI patterns against the configured claim
	if len(role.BoundURIPatterns) > 0 {
		uriClaim := role.URIClaim
		if uriClaim == "" {
			uriClaim = "sub"
		}
		claimValue := extractClaim(claims, uriClaim)
		if claimValue == "" || !helper.MatchAny(claimValue, role.BoundURIPatterns) {
			b.logger.Warn("login failed: URI pattern mismatch", lgr.String("claim", uriClaim), lgr.String("role", roleName))
			return &logical.Response{
				StatusCode: http.StatusUnauthorized,
				Err:        errAuthFailed,
			}, nil
		}
	}

	// Extract principal identity - use role's user_claim or fallback to config
	userClaim := role.UserClaim
	if userClaim == "" {
		userClaim = b.config.UserClaim
	}
	principalID := extractClaim(claims, userClaim)
	if principalID == "" {
		b.logger.Warn("login failed: no principal identity in JWT", lgr.String("user_claim", userClaim), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	// Extract expiration time
	expValue, ok := claims["exp"]
	if !ok {
		b.logger.Warn("login failed: no exp claim in JWT", lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
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
		b.logger.Warn("login failed: invalid exp format in JWT", lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	jwtExpiration := time.Unix(expTimestamp, 0)
	jwtTTL := time.Until(jwtExpiration)

	if jwtTTL <= 0 {
		b.logger.Warn("login failed: JWT has expired", lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	// Validate max_age (iat freshness) if configured on the role
	if role.MaxAge != "" {
		maxAge, err := role.ParseMaxAge()
		if err != nil {
			b.logger.Warn("login failed: corrupt max_age in role config", lgr.String("role", roleName), lgr.Err(err))
			return &logical.Response{
				StatusCode: http.StatusUnauthorized,
				Err:        errAuthFailed,
			}, nil
		}
		iatValue, ok := claims["iat"]
		if !ok {
			b.logger.Warn("login failed: iat claim required when max_age is set", lgr.String("role", roleName))
			return &logical.Response{
				StatusCode: http.StatusUnauthorized,
				Err:        errAuthFailed,
			}, nil
		}
		var iatTimestamp int64
		switch v := iatValue.(type) {
		case float64:
			iatTimestamp = int64(v)
		case int64:
			iatTimestamp = v
		case int:
			iatTimestamp = int64(v)
		default:
			b.logger.Warn("login failed: invalid iat format in JWT", lgr.String("role", roleName))
			return &logical.Response{
				StatusCode: http.StatusUnauthorized,
				Err:        errAuthFailed,
			}, nil
		}
		age := time.Since(time.Unix(iatTimestamp, 0))
		if age > maxAge {
			b.logger.Warn("login failed: JWT exceeds max_age",
				lgr.String("role", roleName),
				lgr.String("age", age.String()),
				lgr.String("max_age", maxAge.String()))
			return &logical.Response{
				StatusCode: http.StatusUnauthorized,
				Err:        errAuthFailed,
			}, nil
		}
	}

	// Calculate effective TTL: min(role.TokenTTL, jwtTTL)
	// The token should never outlive the JWT's actual expiration
	effectiveTTL := jwtTTL
	roleTTL, err := role.ParseTokenTTL()
	if err != nil {
		b.logger.Warn("corrupt token_ttl in role config, using JWT TTL", lgr.String("role", roleName), lgr.Err(err))
	}
	if roleTTL > 0 && roleTTL < jwtTTL {
		effectiveTTL = roleTTL
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
