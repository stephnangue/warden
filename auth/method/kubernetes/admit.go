package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/helper"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// reviewed is what one TokenReview verified about a workload token.
type reviewed struct {
	status    *tokenReviewStatus
	namespace string // the service account's namespace, from the username
	name      string // the service account's name, from the username
	// claims are the token's claims parsed without checking the signature;
	// the review verified that same token. Nil when it does not parse.
	claims map[string]any
}

// reviewWorkload runs the checks every kubernetes admission makes of a
// workload token: the cheap issuer pre-filter (the unverified iss against the
// mount's issuer, when one is pinned and validation is on), one TokenReview
// asking for audiences (none: the API server's own), and the reviewed
// username naming a service account ("system:serviceaccount:<ns>:<name>";
// anything else is out of scope for this method). The review's bearer is the
// configured token_reviewer_jwt, or the workload's own token (self-review).
//
// It returns what the review verified, or why the token is not admitted. It
// reads cfg, a snapshot the caller took, and writes nothing.
func reviewWorkload(ctx context.Context, cfg *KubernetesAuthConfig, token string, audiences []string) (*reviewed, error) {
	claims, _ := helper.ParseJWTClaimsUnverified(token)
	if cfg.Issuer != "" && !cfg.DisableIssValidation {
		if claims == nil {
			return nil, errors.New("failed to parse JWT for issuer pre-filter")
		}
		if iss, _ := claims["iss"].(string); iss != cfg.Issuer {
			return nil, fmt.Errorf("iss mismatch: got %q, want %q", iss, cfg.Issuer)
		}
	}

	bearer := cfg.TokenReviewerJWT
	if bearer == "" {
		bearer = token
	}
	status, err := reviewToken(ctx, cfg.httpClient, cfg.KubernetesHost, bearer, token, audiences)
	if err != nil {
		return nil, fmt.Errorf("TokenReview call failed: %w", err)
	}
	if !status.Authenticated || status.Error != "" {
		return nil, fmt.Errorf("TokenReview rejected token: %s", status.Error)
	}

	namespace, name, ok := parseSAUsername(status.User.Username)
	if !ok {
		return nil, fmt.Errorf("username %q is not a service account", status.User.Username)
	}
	return &reviewed{status: status, namespace: namespace, name: name, claims: claims}, nil
}

// errNotConfigured refuses admission on a mount with no configuration.
var errNotConfigured = errors.New("kubernetes auth method is not configured")

// admitToken verifies token against the mount's configuration alone, with no
// role: reviewWorkload with the mount's bound_audiences as the review's
// audiences (the API server's own when none are set), the review reporting
// one of them back (an audience-aware reviewer returns the audiences it
// validated; one that returns none of the requested ones is not trusted), and
// the mount's max_age against the token's iat at now. One TokenReview per
// call. It returns what the review verified, or why the token is not
// admitted.
//
// It reads cfg, a snapshot the caller took, and writes nothing.
func admitToken(ctx context.Context, cfg *KubernetesAuthConfig, token string, now time.Time) (*reviewed, error) {
	if cfg == nil {
		return nil, errNotConfigured
	}
	rv, err := reviewWorkload(ctx, cfg, token, cfg.BoundAudiences)
	if err != nil {
		return nil, err
	}
	if len(cfg.BoundAudiences) > 0 && !slices.ContainsFunc(rv.status.Audiences, func(a string) bool {
		return slices.Contains(cfg.BoundAudiences, a)
	}) {
		return nil, errors.New("TokenReview validated none of the mount's bound_audiences")
	}
	if err := authhelper.CheckMaxAge(cfg.MaxAge, authhelper.IssuedAt(rv.claims), now); err != nil {
		return nil, fmt.Errorf("max_age: %w", err)
	}
	return rv, nil
}

// admit is the mount's authhelper.AdmitFunc: the bearer token admitted by
// admitToken under the config in force, as an admission of this mount. A
// TokenReview that fails is logged and not admitted, as discovery treated it
// before. Safe for concurrent use: it takes the config under configMu and
// releases it before the TokenReview round-trip, as login does.
func (b *kubernetesAuthBackend) admit(ctx context.Context, req *logical.Request, now time.Time) *logical.Admission {
	token := extractJWTFromRequest(req)
	if token == "" {
		return nil
	}
	b.configMu.RLock()
	cfg := b.config
	b.configMu.RUnlock()

	rv, err := admitToken(ctx, cfg, token, now)
	if err != nil {
		b.logger.Debug("introspect/admit: token not admitted", lgr.Err(err))
		return nil
	}
	return newAdmission(rv.status, rv.namespace, rv.name, rv.claims, b.mountFacts)
}
