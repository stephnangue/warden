package kubernetes

import (
	"context"
	"net/http"
	"strings"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathIntrospect returns the introspection path definition. Mirrors the
// JWT auth method: unauthenticated, takes the workload JWT from Bearer
// or req.ClientToken, returns the set of roles this token could assume.
func (b *kubernetesAuthBackend) pathIntrospect() *framework.Path {
	return &framework.Path{
		Pattern: "introspect/roles",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleIntrospectRoles,
				Summary:  "List roles this Kubernetes SA token is allowed to assume",
			},
		},
		HelpSynopsis:    "Discover roles assumable by the presented SA token",
		HelpDescription: "Returns the roles within this mount whose bound service-account + audience constraints are satisfied by the JWT in the Authorization header (or req.ClientToken).",
	}
}

// introspectedRole is the per-role payload returned by introspection.
type introspectedRole struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// handleIntrospectRoles returns the subset of this mount's roles that
// the presented K8s SA token could assume.
//
// Design constraint: JWT introspect can run the local JWKS validator N
// times cheaply; kubernetes can't — each TokenReview is an HTTP
// round-trip. Calling TokenReview per role would amplify apiserver
// load. We make ONE TokenReview without audience binding to learn the
// token's natural audiences + identity, then filter roles locally by
// SA name/namespace and (per-role) audience membership. Login always
// re-runs TokenReview with audience binding, so the actual security
// check still happens there — introspect is a discovery hint, not an
// authorization decision (same trade-off the JWT method makes).
func (b *kubernetesAuthBackend) handleIntrospectRoles(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	cfg := b.config
	b.configMu.RUnlock()

	if cfg == nil {
		return introspectEmpty(), nil
	}

	jwtToken := extractJWTFromRequest(req)
	if jwtToken == "" {
		return introspectEmpty(), nil
	}

	// Per-mount issuer pinning: if the mount has an issuer pinned,
	// short-circuit when the token's iss doesn't match. Keeps the
	// aggregator decoupled from per-mount config.
	if cfg.Issuer != "" && !cfg.DisableIssValidation {
		claims, _ := authhelper.ParseJWTClaimsUnverified(jwtToken)
		if claims == nil {
			return introspectEmpty(), nil
		}
		issClaim, _ := claims["iss"].(string)
		if issClaim != cfg.Issuer {
			return introspectEmpty(), nil
		}
	}

	// Bearer for the TokenReview call: prefer the configured reviewer
	// JWT (standard Vault path); fall back to the workload's JWT in
	// self-reviewing mode.
	bearer := cfg.TokenReviewerJWT
	if bearer == "" {
		bearer = jwtToken
	}

	// One TokenReview with no audience binding. Response status.audiences
	// gives us the token's natural audiences for per-role filtering.
	status, err := reviewToken(ctx, cfg.httpClient, cfg.KubernetesHost, bearer, jwtToken, nil)
	if err != nil {
		b.logger.Warn("introspect: TokenReview call failed", lgr.Err(err))
		return introspectEmpty(), nil
	}
	if !status.Authenticated || status.Error != "" {
		return introspectEmpty(), nil
	}

	saNamespace, saName, ok := parseSAUsername(status.User.Username)
	if !ok {
		return introspectEmpty(), nil
	}

	roleNames, err := b.listRoles(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	matches := make([]introspectedRole, 0, len(roleNames))
	for _, name := range roleNames {
		role, err := b.getRole(ctx, name)
		if err != nil {
			b.logger.Warn("introspect: failed to load role", lgr.String("role", name), lgr.Err(err))
			continue
		}
		if role == nil {
			continue
		}
		if matchRoleBindings(role, saNamespace, saName) != nil {
			continue
		}
		if !audienceMatches(role.Audience, status.Audiences) {
			continue
		}
		matches = append(matches, introspectedRole{
			Name:        role.Name,
			Description: role.Description,
		})
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"roles": matches},
	}, nil
}

func introspectEmpty() *logical.Response {
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"roles": []introspectedRole{}},
	}
}

// extractJWTFromRequest pulls a JWT off an introspect request. Two paths
// (mirrors the JWT auth method):
//  1. Direct HTTP call — Authorization: Bearer <jwt>.
//  2. In-process call from the sys/introspect/roles aggregator — the
//     aggregator places the raw JWT in req.ClientToken before dispatch.
func extractJWTFromRequest(req *logical.Request) string {
	if req.HTTPRequest != nil {
		if auth := req.HTTPRequest.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}
	return req.ClientToken
}
