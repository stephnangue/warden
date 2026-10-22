package jwt

import (
	"context"
	"errors"
	"net/http"
	"time"

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
		HelpSynopsis: "Authenticate using a JWT token",
		HelpDescription: "This endpoint admits a JWT against the mount's configuration and returns what it " +
			"verified. It selects no role: the role a request runs under is granted per request.",
	}
}

// handleLogin admits the JWT against the mount's configuration with
// admitToken, the check introspect/admit runs too, and returns the admission:
// the principal under the mount's user_claim, the token's act chain, and a TTL
// of the mount's token_ttl capped by the JWT's expiry. It carries no role, no
// policies, no credential spec and no metadata.
func (b *jwtAuthBackend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Snapshot config under the lock, then release immediately so that
	// the read lock is NOT held across the JWKS/OIDC HTTP round-trip in
	// validator.Validate(). This prevents config writes from blocking
	// until all in-flight login HTTP calls complete.
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()

	jwtToken := d.Get("jwt").(string)
	if jwtToken == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("missing jwt token")), nil
	}

	now := time.Now()
	claims, err := admitToken(ctx, config, jwtToken, now)
	if errors.Is(err, errNotConfigured) || errors.Is(err, helper.ErrAgentAudiencesRequired) {
		// The mount cannot decide: say so, as a mount condition.
		b.logger.Warn("login failed: mount cannot admit", lgr.Err(err))
		return &logical.Response{
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}, nil
	}
	if err != nil {
		b.logger.Warn("login failed: JWT not admitted", lgr.Err(err))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errAuthFailed,
		}, nil
	}

	// admitToken checked that the principal and exp are there.
	principalID := extractClaim(claims, config.UserClaim)
	exp, _ := tokenExpiry(claims)

	// The token never outlives the JWT, nor the mount's token_ttl.
	ttl := exp.Sub(now)
	if config.TokenTTL > 0 && config.TokenTTL < ttl {
		ttl = config.TokenTTL
	}

	// On-behalf-of chain attested by the IdP via RFC 8693 §4.1 "act"
	// claim. Recorded with verified=true; flows through to audit.
	actors := extractActChain(claims)

	// The admission adopts the claims map, so it is built after the last
	// read of claims above and nothing reads them after this line.
	admission := newAdmission(claims, jwtToken, b.mountFacts)
	admission.AudienceBound = len(config.BoundAudiences) > 0

	// ClientToken carries the raw JWT so that LoginCreateToken can pass it to
	// the identity token type, which hashes it with the mount accessor into
	// the deterministic token ID used for transparent-mode cache lookups.
	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID: principalID,
			TokenType:   logical.TokenTypeIdentity,
			TokenTTL:    ttl,
			ClientIP:    req.ClientIP,
			ClientToken: jwtToken,
			Actors:      actors,
			Admission:   admission,
		},
		Data: map[string]any{
			"principal_id": principalID,
		},
	}, nil
}
