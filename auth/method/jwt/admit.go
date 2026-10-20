package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/cap/jwt"

	"github.com/stephnangue/warden/auth/helper"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// expectedClaims returns what the validator checks a token against: the
// mount's issuer, and the subject and audiences of role where it sets them,
// the mount's otherwise. A nil role is the role-free admission: the mount's
// configuration alone. An empty audience list leaves the audience unchecked.
func expectedClaims(config *JWTAuthConfig, role *JWTRole) jwt.Expected {
	expected := jwt.Expected{
		SigningAlgorithms: []jwt.Alg{jwt.RS256, jwt.RS384, jwt.RS512, jwt.ES256, jwt.ES384, jwt.ES512},
		Issuer:            config.BoundIssuer,
		Subject:           config.BoundSubject,
	}
	if len(config.BoundAudiences) > 0 {
		expected.Audiences = config.BoundAudiences
	}
	if role != nil {
		if role.BoundSubject != "" {
			expected.Subject = role.BoundSubject
		}
		if len(role.BoundAudiences) > 0 {
			expected.Audiences = role.BoundAudiences
		}
	}
	return expected
}

var (
	errNoExp  = errors.New("no exp claim in JWT")
	errBadExp = errors.New("invalid exp format in JWT")
)

// tokenExpiry returns the instant a token's exp claim names, or errNoExp or
// errBadExp.
func tokenExpiry(claims map[string]any) (time.Time, error) {
	v, ok := claims["exp"]
	if !ok {
		return time.Time{}, errNoExp
	}
	secs, ok := parseNumericClaim(v)
	if !ok {
		return time.Time{}, errBadExp
	}
	return time.Unix(secs, 0), nil
}

// errNotConfigured refuses admission on a mount with no configuration.
var errNotConfigured = errors.New("JWT auth backend not configured")

// admitToken verifies token against the mount's configuration alone, with no
// role: the signature, the mount's issuer and subject, its bound_audiences
// (any one of them, when set), its bound_claims, a principal under its
// user_claim, an exp after now, and its max_age against the token's iat at
// now. It returns the validated claims, which the caller hands to
// newAdmission and must not read after, or why the token is not admitted.
//
// It reads config, a snapshot the caller took, and writes nothing.
func admitToken(ctx context.Context, config *JWTAuthConfig, token string, now time.Time) (map[string]any, error) {
	if config == nil || config.validator == nil {
		return nil, errNotConfigured
	}
	claims, err := config.validator.Validate(ctx, token, expectedClaims(config, nil))
	if err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}
	if err := validateBoundClaims(claims, config.BoundClaims); err != nil {
		return nil, fmt.Errorf("bound claims: %w", err)
	}
	if extractClaim(claims, config.UserClaim) == "" {
		return nil, fmt.Errorf("no principal in claim %q", config.UserClaim)
	}
	exp, err := tokenExpiry(claims)
	if err != nil {
		return nil, err
	}
	if !now.Before(exp) {
		return nil, errors.New("JWT has expired")
	}
	if err := helper.CheckMaxAge(config.MaxAge, helper.IssuedAt(claims), now); err != nil {
		return nil, fmt.Errorf("max_age: %w", err)
	}
	return claims, nil
}

// admit is the mount's helper.AdmitFunc: the bearer JWT admitted by
// admitToken under the config in force, as an admission of this mount. An
// unconfigured mount cannot decide, which is an error; a token that fails a
// check is not admitted. Safe for concurrent use: it takes the config under
// configMu and releases it before validating, as login does.
func (b *jwtAuthBackend) admit(ctx context.Context, req *logical.Request, now time.Time) (*logical.Admission, error) {
	token := extractJWTFromRequest(req)
	if token == "" {
		return nil, nil
	}
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()

	claims, err := admitToken(ctx, config, token, now)
	if errors.Is(err, errNotConfigured) {
		return nil, err
	}
	if err != nil {
		b.logger.Debug("introspect/admit: JWT not admitted", lgr.Err(err))
		return nil, nil
	}
	return newAdmission(claims, token, b.mountFacts), nil
}
