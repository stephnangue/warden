package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// noAudiencesWarning is the config read and write warning of a mount without
// bound_audiences: its reviews check the API server's own audience, which a
// default service-account token for the Kubernetes API carries too.
const noAudiencesWarning = "bound_audiences is empty: TokenReview checks the API server's own audience, " +
	"so a default service-account token for the Kubernetes API is admitted too; " +
	"set bound_audiences to the audience of the projected tokens issued for Warden"

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
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Authenticate using a Kubernetes ServiceAccount JWT",
			},
		},
		HelpSynopsis: "Authenticate using a Kubernetes ServiceAccount JWT",
		HelpDescription: `Validates the workload's JWT by calling TokenReview on the configured
kube-apiserver with the mount's bound_audiences, and returns the reviewed
service account. It selects no role: the role a request runs under is granted
per request.`,
	}
}

// handleLogin admits the workload token against the mount's configuration
// with admitToken, the check introspect/admit runs too (the issuer
// pre-filter, one TokenReview with the mount's bound_audiences, the reviewed
// service account, the mount's max_age), and returns the admission: the
// reviewed username as principal and a TTL of the mount's token_ttl capped by
// the token's exp. It carries no role, no policies, no credential spec and no
// metadata.
//
// Failures of the token collapse to errAuthFailed in the response to prevent
// leaking which check failed; detailed reasons are logged server-side via the
// gated logger.
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

	now := time.Now()
	rv, err := admitToken(ctx, cfg, jwtStr, now)
	if err != nil {
		if errors.Is(err, errTokenReviewCall) {
			b.logger.Warn("kubernetes login: token review failed", lgr.Err(err))
		} else {
			b.logger.Warn("kubernetes login: token not admitted", lgr.Err(err))
		}
		return logical.ErrorResponse(errAuthFailed), nil
	}
	status := rv.status

	// The token never outlives its exp, nor the mount's token_ttl. A token
	// without an exp is capped by the token_ttl alone.
	ttl := cfg.TokenTTL
	if rv.claims != nil {
		if exp, ok := rv.claims["exp"].(float64); ok {
			if until := time.Unix(int64(exp), 0).Sub(now); until > 0 && (ttl <= 0 || until < ttl) {
				ttl = until
			}
		}
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID: status.User.Username,
			TokenType:   "kubernetes_role",
			TokenTTL:    ttl,
			ClientIP:    req.ClientIP,
			// ClientToken carries the raw JWT so LoginCreateToken can pass
			// it to KubernetesRoleTokenType.Generate(), which hashes
			// (mountAccessor + JWT) into the deterministic cache ID used for
			// transparent-mode lookups.
			ClientToken: jwtStr,
			// What the review verified. claims are the ones the issuer
			// pre-filter and max_age already parsed, so the iat costs no
			// extra parse.
			Admission: rv.admission(b.mountFacts),
		},
		Data: map[string]any{
			"principal_id":              status.User.Username,
			"service_account_uid":       status.User.UID,
			"service_account_namespace": rv.namespace,
			"service_account_name":      rv.name,
		},
	}, nil
}
