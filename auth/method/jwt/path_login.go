package jwt

import (
	"context"
	"fmt"
	"net/http"
	"time"

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
	// Snapshot config under the lock, then release immediately so that
	// the read lock is NOT held across the JWKS/OIDC HTTP round-trip in
	// validator.Validate(). This prevents config writes from blocking
	// until all in-flight login HTTP calls complete.
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()

	// Get JWT token
	jwtToken := d.Get("jwt").(string)
	if jwtToken == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("missing jwt token")), nil
	}

	// Get role name — fall back to default_role if configured
	roleName := d.Get("role").(string)
	if roleName == "" && config != nil && config.DefaultRole != "" {
		roleName = config.DefaultRole
	}
	if roleName == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("missing role")), nil
	}

	// Check if backend is configured
	if config == nil || config.validator == nil {
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

	// Expected claims: the mount's, with the role's subject and audiences
	// overriding where the role sets them.
	claims, err := config.validator.Validate(ctx, jwtToken, expectedClaims(config, role))
	if err != nil {
		b.logger.Warn("login failed: JWT validation error", lgr.Err(err), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	// Post-Validate claim checks (config + role bound claims).
	// Shared with introspection via matchRole so the two paths cannot drift.
	if err := matchRole(claims, config.BoundClaims, role); err != nil {
		b.logger.Warn("login failed: bound claims check", lgr.Err(err), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	// Extract principal identity - use role's user_claim or fallback to config
	userClaim := role.UserClaim
	if userClaim == "" {
		userClaim = config.UserClaim
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
	jwtExpiration, err := tokenExpiry(claims)
	if err != nil {
		b.logger.Warn("login failed: "+err.Error(), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}
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
		iatTimestamp, ok := parseNumericClaim(iatValue)
		if !ok {
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

	// Resolve group-based policies from JWT claims
	policies := role.TokenPolicies
	groupsClaim := role.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = config.GroupsClaim
	}
	if groupsClaim != "" {
		groups := extractGroupsClaim(claims, groupsClaim)
		if len(groups) > 0 {
			prefix := role.GroupPolicyPrefix
			if prefix == "" {
				prefix = config.GroupPolicyPrefix
			}
			if prefix == "" {
				prefix = "group-"
			}
			groupPolicies := make([]string, len(groups))
			for i, group := range groups {
				groupPolicies[i] = prefix + group
			}
			policies = append(append([]string{}, policies...), groupPolicies...)
		}
	}

	// On-behalf-of chain attested by the IdP via RFC 8693 §4.1 "act"
	// claim. Recorded with verified=true; flows through to audit.
	actors := extractActChain(claims)

	// Verified, login-derived metadata mapped from claims per the role's
	// metadata_claims config. Persisted onto the token and matched by
	// token_metadata policy conditions.
	metadata, err := extractMetadata(claims, role.MetadataClaims)
	if err != nil {
		b.logger.Warn("login failed: metadata claim extraction", lgr.Err(err), lgr.String("role", roleName))
		return logical.ErrorResponse(logical.ErrBadRequest(errAuthFailed.Error())), nil
	}

	// The admission adopts the claims map, so it is built after the last
	// read of claims above and nothing reads them after this line.
	admission := newAdmission(claims, jwtToken, b.mountFacts)

	// Return auth response using role configuration.
	// ClientToken carries the raw JWT so that LoginCreateToken can pass it to
	// JWTRoleTokenType.Generate(), which hashes jwt+role to compute the
	// deterministic token ID used for transparent-mode cache lookups.
	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID:    principalID,
			RoleName:       roleName,
			Policies:       policies,
			CredentialSpec: role.CredSpecName,
			TokenType:      role.TokenType,
			TokenTTL:       effectiveTTL,
			ClientIP:       req.ClientIP,
			ClientToken:    jwtToken,
			Actors:         actors,
			Metadata:       metadata,
			Admission:      admission,
		},
		Data: map[string]any{
			"principal_id": principalID,
			"role":         roleName,
		},
	}, nil
}
