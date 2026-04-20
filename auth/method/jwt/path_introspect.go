package jwt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathIntrospect returns the introspection path definition.
// Agents call GET auth/{mount}/introspect/roles with only their JWT and
// receive back the roles they could assume, so they can select a role
// per external system without knowing role names up front.
func (b *jwtAuthBackend) pathIntrospect() *framework.Path {
	return &framework.Path{
		Pattern: "introspect/roles",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleIntrospectRoles,
				Summary:  "List roles this JWT is allowed to assume",
			},
		},
		HelpSynopsis:    "Discover roles assumable by the presented JWT",
		HelpDescription: "Returns the roles within this mount whose constraints are satisfied by the JWT in the Authorization header.",
	}
}

// introspectedRole is the per-role payload returned by introspection.
type introspectedRole struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// handleIntrospectRoles returns the subset of this mount's roles that the
// presented JWT could successfully assume. The response is intentionally
// lenient: if the JWT is missing or does not apply to this mount at all,
// return an empty list rather than an error — the system-backend aggregator
// (Part 3) fans out across multiple mounts and must tolerate non-matches.
func (b *jwtAuthBackend) handleIntrospectRoles(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()

	if config == nil || config.validator == nil {
		return introspectEmpty(), nil
	}

	jwtToken := extractJWTFromRequest(req)
	if jwtToken == "" {
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

		claims, err := validateJWTForRole(ctx, config, role, jwtToken)
		if err != nil {
			// JWT fails this role's signature/issuer/subject/audience checks.
			continue
		}
		if err := matchRole(claims, config.BoundClaims, role); err != nil {
			continue
		}
		matches = append(matches, introspectedRole{
			Name:        role.Name,
			Description: role.Description,
		})
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"roles": matches,
		},
	}, nil
}

func introspectEmpty() *logical.Response {
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"roles": []introspectedRole{},
		},
	}
}

// extractJWTFromRequest pulls a JWT off an introspect request. Two paths:
//  1. Direct HTTP call — Authorization: Bearer <jwt>.
//  2. In-process call from the system-backend aggregator (Part 3) — the
//     aggregator places the raw JWT in req.ClientToken before dispatching.
func extractJWTFromRequest(req *logical.Request) string {
	if req.HTTPRequest != nil {
		if auth := req.HTTPRequest.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}
	return req.ClientToken
}

// validateJWTForRole runs the mount's validator with role-specific
// constraints (issuer, subject, audiences) — same construction as login.
// Returns claims on success.
func validateJWTForRole(ctx context.Context, config *JWTAuthConfig, role *JWTRole, jwtToken string) (map[string]any, error) {
	expected := jwt.Expected{
		SigningAlgorithms: []jwt.Alg{jwt.RS256, jwt.RS384, jwt.RS512, jwt.ES256, jwt.ES384, jwt.ES512},
	}
	if config.BoundIssuer != "" {
		expected.Issuer = config.BoundIssuer
	}
	if role.BoundSubject != "" {
		expected.Subject = role.BoundSubject
	} else if config.BoundSubject != "" {
		expected.Subject = config.BoundSubject
	}
	if len(role.BoundAudiences) > 0 {
		expected.Audiences = role.BoundAudiences
	} else if len(config.BoundAudiences) > 0 {
		expected.Audiences = config.BoundAudiences
	}
	return config.validator.Validate(ctx, jwtToken, expected)
}

// matchRole runs the post-Validate claim checks from the login flow:
// config-level bound claims, role-level bound claims, and bound URI
// patterns. Kept as a shared helper so login and introspection cannot
// drift on which checks are enforced.
func matchRole(claims map[string]any, configBoundClaims map[string]any, role *JWTRole) error {
	if err := validateBoundClaims(claims, configBoundClaims); err != nil {
		return err
	}
	if err := validateBoundClaims(claims, role.BoundClaims); err != nil {
		return err
	}
	if len(role.BoundURIPatterns) > 0 {
		uriClaim := role.URIClaim
		if uriClaim == "" {
			uriClaim = "sub"
		}
		claimValue := extractClaim(claims, uriClaim)
		if claimValue == "" || !helper.MatchAny(claimValue, role.BoundURIPatterns) {
			return fmt.Errorf("URI pattern mismatch")
		}
	}
	return nil
}
