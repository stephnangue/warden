package cert

import (
	"context"
	"crypto/x509"
	"net/http"

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

		if err := verifyCertForRole(cert, role, b); err != nil {
			continue
		}
		if err := validateCertConstraints(cert, role); err != nil {
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
