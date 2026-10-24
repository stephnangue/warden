package cert

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// errCertAuthFailed is a generic error returned for all certificate authentication
// failures to prevent information leakage about which specific check failed.
var errCertAuthFailed = fmt.Errorf("authentication failed")

// pathLogin returns the login path definition
func (b *certAuthBackend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields:  map[string]*framework.FieldSchema{},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Authenticate using a TLS client certificate",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Authenticate using a TLS client certificate",
			},
		},
		HelpSynopsis: "Authenticate using a TLS client certificate",
		HelpDescription: "This endpoint admits a client certificate presented via TLS or forwarded by a trusted load balancer " +
			"against the mount's trusted CAs and revocation settings. It selects no role: the role a request runs under " +
			"is granted per request.",
	}
}

// handleLogin admits the client certificate against the mount's configuration
// with admitCert, the check introspect/admit runs too (the chain against the
// mount's trusted CAs, a principal under the mount's principal_claim), then
// checks its revocation, and returns the admission: the principal and a TTL of
// the mount's token_ttl capped by the certificate's NotAfter. It carries no
// role, no policies, no credential spec and no metadata.
func (b *certAuthBackend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Snapshot config under the lock, then release it: the lock is NOT held
	// across the OCSP/CRL round-trip, so a config write neither waits on
	// in-flight logins nor, while it waits, stalls new ones. The snapshot
	// carries its own CA pool and revocation checker, so one login is judged
	// by one configuration throughout.
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()

	// Extract client certificate from TLS connection or forwarded header
	cert := extractClientCert(req)
	if cert == nil {
		return logical.ErrorResponse(logical.ErrBadRequest("no client certificate provided")), nil
	}

	verifiedChains, err := admitCert(config, cert)
	if errors.Is(err, errNoTrustedCA) {
		return &logical.Response{
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}, nil
	}
	if err != nil {
		b.logger.Warn("login failed: certificate not admitted", lgr.Err(err))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errCertAuthFailed,
		}, nil
	}

	// Check certificate revocation status if configured
	if config.revocationChecker != nil {
		if err := config.revocationChecker.checkRevocation(cert, verifiedChains, config.RevocationMode); err != nil {
			b.logger.Warn("login failed: certificate revocation check", lgr.Err(err))
			return &logical.Response{
				StatusCode: http.StatusUnauthorized,
				Err:        errCertAuthFailed,
			}, nil
		}
	}

	// admitCert checked that the principal is there.
	principalID := extractPrincipal(cert, principalClaimOf(config))

	// Certificate fingerprint for token caching in transparent mode
	fingerprint := certFingerprint(cert)

	// The leaf's fields, and the anchors of the chains it verified along.
	admission := newAdmission(cert, verifiedChains, b.mountFacts)
	admission.PrincipalID = principalID

	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID: principalID,
			TokenType:   logical.TokenTypeIdentity,
			TokenTTL:    calculateTTL(config, cert, time.Now()),
			ClientIP:    req.ClientIP,
			ClientToken: fingerprint, // Cert fingerprint for token type caching
			Admission:   admission,
		},
		Data: map[string]any{
			"principal_id": principalID,
			"fingerprint":  fingerprint,
		},
	}, nil
}

// getCAPool returns the mount's trusted CA pool, or nil when it has none.
func getCAPool(config *CertAuthConfig) *x509.CertPool {
	if config == nil {
		return nil
	}
	return config.caPool
}

// calculateTTL returns the TTL of a certificate's admission at now: the
// mount's token_ttl, capped by the certificate's NotAfter (0 once it has
// passed). A zero token_ttl is no cap from the mount.
func calculateTTL(config *CertAuthConfig, cert *x509.Certificate, now time.Time) time.Duration {
	certTTL := cert.NotAfter.Sub(now)
	if certTTL <= 0 {
		return 0
	}
	if config != nil && config.TokenTTL > 0 && config.TokenTTL < certTTL {
		return config.TokenTTL
	}
	return certTTL
}

// extractPrincipal extracts the principal identity from the certificate based on the claim type.
func extractPrincipal(cert *x509.Certificate, claim string) string {
	switch claim {
	case "cn":
		return cert.Subject.CommonName
	case "dns_san":
		if len(cert.DNSNames) > 0 {
			return cert.DNSNames[0]
		}
	case "email_san":
		if len(cert.EmailAddresses) > 0 {
			return cert.EmailAddresses[0]
		}
	case "uri_san":
		if len(cert.URIs) > 0 {
			return cert.URIs[0].String()
		}
	case "serial":
		return cert.SerialNumber.String()
	}
	return ""
}
