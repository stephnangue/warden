package kubernetes

import (
	"context"
	"net/http"
	"time"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathLogin returns the /login path definition.
func (b *kubernetesAuthBackend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"jwt": {
				Type:        framework.TypeString,
				Description: "Kubernetes ServiceAccount JWT (workload identity token).",
				Required:    true,
			},
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role to authenticate against. Falls back to config.default_role if unset.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Authenticate using a Kubernetes ServiceAccount JWT",
			},
		},
		HelpSynopsis: "Authenticate using a Kubernetes ServiceAccount JWT",
		HelpDescription: `Validates the workload's JWT by calling TokenReview on the configured
kube-apiserver, matches the resolved SA against the role's bound
service-account names and namespaces, and issues a token bound to the
role's policies.`,
	}
}

// handleLogin runs the TokenReview-based login flow:
//  1. extract JWT and resolve role (with default_role fallback)
//  2. cheap issuer pre-filter (unverified iss claim) if configured
//  3. TokenReview against the kube-apiserver
//  4. parse the returned system:serviceaccount:<ns>:<name> username
//  5. match against role's bound_service_account_names/namespaces
//  6. enforce role.max_age if configured (against iat claim)
//  7. compute effective TTL = min(role.TokenTTL, jwt-exp-derived-TTL)
//  8. return auth response with PrincipalID + role + policies
//
// All authentication failures collapse to errAuthFailed in the response
// to prevent leaking which check failed; detailed reasons are logged
// server-side via the gated logger.
func (b *kubernetesAuthBackend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Snapshot config under lock so concurrent /config writes don't block
	// the TokenReview HTTP round-trip.
	b.configMu.RLock()
	cfg := b.config
	b.configMu.RUnlock()

	if cfg == nil {
		return logical.ErrorResponse(logical.ErrBadRequest("kubernetes auth method is not configured (POST /config first)")), nil
	}

	jwtToken, _ := d.GetOk("jwt")
	jwtStr, _ := jwtToken.(string)
	if jwtStr == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("jwt is required")), nil
	}

	roleName, _ := d.GetOk("role")
	roleStr, _ := roleName.(string)
	if roleStr == "" {
		roleStr = cfg.DefaultRole
	}
	if roleStr == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("role is required (no default_role configured)")), nil
	}

	role, err := b.getRole(ctx, roleStr)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if role == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("role %q not found", roleStr)), nil
	}

	// Cheap issuer pre-filter: parse-unverified, check iss matches the
	// mount's configured issuer. Cuts noise before the TokenReview round-trip
	// for tokens from the wrong cluster.
	claims, _ := authhelper.ParseJWTClaimsUnverified(jwtStr)
	if cfg.Issuer != "" && !cfg.DisableIssValidation {
		if claims == nil {
			b.logger.Warn("kubernetes login: failed to parse JWT for issuer pre-filter")
			return logical.ErrorResponse(errAuthFailed), nil
		}
		issClaim, _ := claims["iss"].(string)
		if issClaim != cfg.Issuer {
			b.logger.Warn("kubernetes login: iss mismatch",
				lgr.String("role", roleStr),
				lgr.String("got_iss", issClaim),
				lgr.String("want_iss", cfg.Issuer))
			return logical.ErrorResponse(errAuthFailed), nil
		}
	}

	// TokenReview call. Bearer is the operator-configured token_reviewer_jwt
	// when set, otherwise the workload's own JWT (self-reviewing mode).
	bearer := cfg.TokenReviewerJWT
	if bearer == "" {
		bearer = jwtStr
	}
	var audiences []string
	if role.Audience != "" {
		audiences = []string{role.Audience}
	}
	status, err := reviewToken(ctx, cfg.httpClient, cfg.KubernetesHost, bearer, jwtStr, audiences)
	if err != nil {
		b.logger.Warn("kubernetes login: TokenReview call failed",
			lgr.String("role", roleStr),
			lgr.Err(err))
		return logical.ErrorResponse(errAuthFailed), nil
	}
	if !status.Authenticated || status.Error != "" {
		b.logger.Warn("kubernetes login: TokenReview rejected token",
			lgr.String("role", roleStr),
			lgr.String("tokenreview_error", status.Error))
		return logical.ErrorResponse(errAuthFailed), nil
	}

	// Username must be a SA token: "system:serviceaccount:<ns>:<name>".
	// Anything else (system:anonymous, OIDC users, node identities) is
	// out of scope for this auth method.
	saNamespace, saName, ok := parseSAUsername(status.User.Username)
	if !ok {
		b.logger.Warn("kubernetes login: username is not a service account",
			lgr.String("role", roleStr),
			lgr.String("username", status.User.Username))
		return logical.ErrorResponse(errAuthFailed), nil
	}

	if err := matchRoleBindings(role, saNamespace, saName); err != nil {
		b.logger.Warn("kubernetes login: SA binding mismatch",
			lgr.String("role", roleStr),
			lgr.String("sa", saName),
			lgr.String("namespace", saNamespace),
			lgr.Err(err))
		return logical.ErrorResponse(errAuthFailed), nil
	}

	// Optional freshness check via the iat claim. The TokenReview already
	// rejects expired tokens; max_age adds a stricter bound (e.g. only
	// accept tokens issued in the last 5 minutes).
	if role.MaxAge != "" && claims != nil {
		maxAge, parseErr := role.ParseMaxAge()
		if parseErr == nil && maxAge > 0 {
			if iat, ok := claims["iat"].(float64); ok {
				if time.Since(time.Unix(int64(iat), 0)) > maxAge {
					b.logger.Warn("kubernetes login: token older than role.max_age",
						lgr.String("role", roleStr),
						lgr.Float64("iat", iat))
					return logical.ErrorResponse(errAuthFailed), nil
				}
			}
		}
	}

	// Effective TTL: min(role.TokenTTL, jwt-exp-derived). If the JWT has
	// no exp claim or it's already expired, only use role.TokenTTL.
	roleTTL, _ := role.ParseTokenTTL()
	effectiveTTL := roleTTL
	if claims != nil {
		if exp, ok := claims["exp"].(float64); ok {
			until := time.Until(time.Unix(int64(exp), 0))
			if until > 0 && until < effectiveTTL {
				effectiveTTL = until
			}
		}
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID:    status.User.Username,
			RoleName:       roleStr,
			Policies:       role.TokenPolicies,
			CredentialSpec: role.CredSpecName,
			TokenType:      role.TokenType,
			TokenTTL:       effectiveTTL,
			ClientIP:       req.ClientIP,
			// ClientToken carries the raw JWT so LoginCreateToken can pass
			// it to KubernetesRoleTokenType.Generate(), which hashes
			// (mountAccessor + JWT + role) into the deterministic cache ID
			// used for transparent-mode lookups.
			ClientToken: jwtStr,
		},
		Data: map[string]any{
			"principal_id":              status.User.Username,
			"role":                      roleStr,
			"service_account_uid":       status.User.UID,
			"service_account_namespace": saNamespace,
			"service_account_name":      saName,
		},
	}, nil
}
