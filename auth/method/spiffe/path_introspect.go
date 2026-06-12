package spiffe

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

func (b *spiffeAuthBackend) pathIntrospect() *framework.Path {
	return &framework.Path{
		Pattern: "introspect/roles",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleIntrospectRoles, Summary: "List roles this SVID is allowed to assume"},
		},
		HelpSynopsis:    "Discover roles assumable by the presented SVID",
		HelpDescription: "Returns the roles whose trust domain and SPIFFE-ID constraints are satisfied by the presented X.509-SVID (mTLS/forwarded cert) or JWT-SVID (Authorization: Bearer).",
	}
}

type introspectedRole struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// handleIntrospectRoles returns the subset of roles the presented SVID could
// assume. Intentionally lenient: it never errors on a non-matching credential
// (the system-backend aggregator fans out across mounts and tolerates misses),
// and it swallows every verification error so a generic JWT presented to a
// spiffe mount produces no warning.
func (b *spiffeAuthBackend) handleIntrospectRoles(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cert := extractClientCert(req)
	jwtToken := extractJWTFromRequest(req)
	if cert == nil && jwtToken == "" {
		return introspectEmpty(), nil
	}

	set := b.spiffe.SnapshotBundleSet()
	if set == nil || set.Len() == 0 {
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
		if role == nil || role.TrustDomain == "" {
			continue
		}
		if b.roleAcceptsSVID(set, role, cert, jwtToken) {
			matches = append(matches, introspectedRole{Name: role.Name, Description: role.Description})
		}
	}

	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"roles": matches}}, nil
}

func introspectEmpty() *logical.Response {
	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"roles": []introspectedRole{}}}
}

// roleAcceptsSVID reports whether the presented cert or JWT-SVID would be
// accepted by the role. It swallows all verification errors (advisory check) so
// a non-matching credential never surfaces an error to the aggregator.
func (b *spiffeAuthBackend) roleAcceptsSVID(set *spiffebundle.Set, role *SPIFFERole, cert *x509.Certificate, jwtToken string) bool {
	expectedTD, err := spiffeid.TrustDomainFromString(role.TrustDomain)
	if err != nil {
		return false
	}
	if cert != nil {
		if _, _, err := spiffelib.VerifyX509SVID(set, []*x509.Certificate{cert}, expectedTD, role.AllowedSPIFFEIDs); err == nil {
			return true
		}
	}
	if jwtToken != "" {
		if audience := resolveAudience(role); len(audience) > 0 {
			if _, err := spiffelib.VerifyJWTSVID(set, jwtToken, audience, expectedTD, role.AllowedSPIFFEIDs); err == nil {
				return true
			}
		}
	}
	return false
}
