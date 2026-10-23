package cert

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/stephnangue/warden/auth/helper"
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
// the mount's principal_claim, else "cn".
func principalClaimOf(config *CertAuthConfig) string {
	if config != nil && config.PrincipalClaim != "" {
		return config.PrincipalClaim
	}
	return "cn"
}

// errNoTrustedCA refuses admission on a mount with no trusted CA.
var errNoTrustedCA = helper.AdmitError(helper.ErrAdmitNoTrustedCA, "no trusted CA certificates configured")

// admitCert verifies cert against the mount's configuration: the chain
// against the mount's trusted CAs, for client auth, and a
// principal in the mount's principal_claim. It returns the verified chains, or
// why the certificate is not admitted: errNoTrustedCA when the mount has no
// trusted CA to decide with, any other error when the certificate failed a
// check. Revocation is not checked here, as discovery never checked it; a
// login checks it after this.
//
// It is the one admission check of the mount: login and introspect/admit both
// call it, so they cannot drift. It reads config, a snapshot the caller took,
// and writes nothing.
func admitCert(config *CertAuthConfig, cert *x509.Certificate) ([][]*x509.Certificate, error) {
	pool := getCAPool(config)
	if pool == nil {
		return nil, errNoTrustedCA
	}
	chains, err := verifyChain(pool, cert)
	if err != nil {
		return nil, fmt.Errorf("certificate verification: %w", err)
	}
	if claim := principalClaimOf(config); extractPrincipal(cert, claim) == "" {
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
