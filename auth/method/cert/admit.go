package cert

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// verifyChain verifies cert, a client certificate, against pool and returns
// the chains it verified along.
func verifyChain(pool *x509.CertPool, cert *x509.Certificate) ([][]*x509.Certificate, error) {
	return cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// principalClaimOf returns the certificate field the principal is read from:
// role's principal_claim, else the mount's, else "cn". A nil role is the
// role-free admission: the mount's configuration alone.
func principalClaimOf(config *CertAuthConfig, role *CertRole) string {
	if role != nil && role.PrincipalClaim != "" {
		return role.PrincipalClaim
	}
	if config != nil && config.PrincipalClaim != "" {
		return config.PrincipalClaim
	}
	return "cn"
}

// errNoTrustedCA refuses admission on a mount with no trusted CA.
var errNoTrustedCA = errors.New("no trusted CA certificates configured")

// admitCert verifies cert against the mount's configuration alone, with no
// role: the chain against the mount's trusted CAs, for client auth, and a
// principal in the mount's principal_claim. It returns the verified chains, or
// why the certificate is not admitted: errNoTrustedCA when the mount has no
// trusted CA to decide with, any other error when the certificate failed a
// check. Revocation is not checked here, as discovery never checked it; a
// login checks it after this.
//
// It reads config, a snapshot the caller took, and writes nothing.
func admitCert(config *CertAuthConfig, cert *x509.Certificate) ([][]*x509.Certificate, error) {
	pool, _ := getCAPool(config, nil) // with no role, the mount's pool: never an error
	if pool == nil {
		return nil, errNoTrustedCA
	}
	chains, err := verifyChain(pool, cert)
	if err != nil {
		return nil, fmt.Errorf("certificate verification: %w", err)
	}
	if claim := principalClaimOf(config, nil); extractPrincipal(cert, claim) == "" {
		return nil, fmt.Errorf("no principal in %q", claim)
	}
	return chains, nil
}

// admit is the mount's helper.AdmitFunc: the presented client certificate
// admitted by admitCert under the config in force, as an admission of this
// mount. A mount without a trusted CA cannot decide, which is an error; a
// certificate that fails a check is not admitted. A certificate carries no
// issue time, so now is unused. Safe for concurrent use: it takes the config
// under configMu and releases it before verifying, as login does.
func (b *certAuthBackend) admit(_ context.Context, req *logical.Request, _ time.Time) (*logical.Admission, error) {
	cert := extractClientCert(req)
	if cert == nil {
		return nil, nil
	}
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()

	chains, err := admitCert(config, cert)
	if errors.Is(err, errNoTrustedCA) {
		return nil, err
	}
	if err != nil {
		b.logger.Debug("introspect/admit: certificate not admitted", lgr.Err(err))
		return nil, nil
	}
	return newAdmission(cert, chains, b.mountFacts), nil
}
