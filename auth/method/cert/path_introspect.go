package cert

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathIntrospect returns the introspection path definition.
// Agents call GET auth/{mount}/introspect/roles with only their client
// certificate and receive back the roles they could assume.
func (b *certAuthBackend) pathIntrospect() *framework.Path {
	return &framework.Path{
		Pattern: "introspect/roles",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleIntrospectRoles,
				Summary:  "List roles this certificate is allowed to assume",
			},
		},
		HelpSynopsis:    "Discover roles assumable by the presented certificate",
		HelpDescription: "Returns the roles within this mount whose constraints are satisfied by the client certificate presented via mTLS or a trusted forwarding header.",
	}
}

// introspectedRole is the per-role payload returned by introspection.
type introspectedRole struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// handleIntrospectRoles returns the subset of this mount's roles that the
// presented certificate could successfully assume. Intentionally lenient:
// if no certificate is presented, returns an empty list — the system-backend
// aggregator (Part 3) fans out across multiple mounts and must tolerate
// non-matching mounts without error.
func (b *certAuthBackend) handleIntrospectRoles(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	cert := extractClientCert(req)
	if cert == nil {
		return introspectEmpty(), nil
	}

	// Determine the mount mode and, for spiffe mode, snapshot the bundle set once.
	mode := modeX509
	if b.config != nil && b.config.Mode != "" {
		mode = b.config.Mode
	}
	var set *x509bundle.Set
	if mode == modeSPIFFE {
		set = b.snapshotBundleSet()
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
		if b.certSatisfiesRole(cert, role, set, mode) {
			matches = append(matches, introspectedRole{
				Name:        role.Name,
				Description: role.Description,
			})
		}
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

// verifyCertForRole performs the chain-of-trust check that login does
// before calling validateCertConstraints — the certificate must verify
// against the role's effective CA pool. Revocation checks are skipped
// here; introspection is advisory, and the full revocation check runs
// at login time.
func verifyCertForRole(cert *x509.Certificate, role *CertRole, b *certAuthBackend) error {
	caPool, err := b.getCAPool(role)
	if err != nil {
		return err
	}
	if caPool == nil {
		return errCertAuthFailed
	}
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// certSatisfiesRole reports whether the presented certificate would be accepted
// by the role under the mount mode — the same trust decision login makes, minus
// the revocation check (introspection is advisory). In spiffe mode it verifies
// the SVID against the role's trust-domain bundle; otherwise it runs the x509
// chain + constraint checks.
func (b *certAuthBackend) certSatisfiesRole(cert *x509.Certificate, role *CertRole, set *x509bundle.Set, mode string) bool {
	if mode == modeSPIFFE {
		if role.TrustDomain == "" || set == nil {
			return false
		}
		expectedTD, err := spiffeid.TrustDomainFromString(role.TrustDomain)
		if err != nil {
			return false
		}
		_, _, err = verifySPIFFE(set, []*x509.Certificate{cert}, expectedTD, role.AllowedSPIFFEIDs)
		return err == nil
	}

	if err := verifyCertForRole(cert, role, b); err != nil {
		return false
	}
	return validateCertConstraints(cert, role) == nil
}
