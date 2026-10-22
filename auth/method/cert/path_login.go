package cert

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/stephnangue/warden/auth/helper"
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
	principalID := extractPrincipal(cert, principalClaimOf(config, nil))

	// Certificate fingerprint for token caching in transparent mode
	fingerprint := certFingerprint(cert)

	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID: principalID,
			TokenType:   "cert_role",
			TokenTTL:    calculateTTL(config, cert, time.Now()),
			ClientIP:    req.ClientIP,
			ClientToken: fingerprint, // Cert fingerprint for token type caching
			// The leaf's fields, and the anchors of the chains it verified
			// along.
			Admission: newAdmission(cert, verifiedChains, b.mountFacts),
		},
		Data: map[string]any{
			"principal_id": principalID,
			"fingerprint":  fingerprint,
		},
	}, nil
}

// getCAPool returns the CA pool to use for cert verification.
// Role-specific CA overrides the global trusted CAs. A nil role is the
// role-free admission: the mount's pool alone. nil when there is none.
func getCAPool(config *CertAuthConfig, role *CertRole) (*x509.CertPool, error) {
	if role != nil && role.Certificate != "" {
		return buildCAPool(role.Certificate)
	}
	if config != nil && config.caPool != nil {
		return config.caPool, nil
	}
	return nil, nil
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

// validateCertConstraints checks whether the certificate satisfies the role constraints.
// If a constraint list is empty, it is not enforced.
func validateCertConstraints(cert *x509.Certificate, role *CertRole) error {
	if len(role.AllowedCommonNames) > 0 {
		if !matchesGlob(cert.Subject.CommonName, role.AllowedCommonNames) {
			return fmt.Errorf("certificate CN %q not allowed by role", cert.Subject.CommonName)
		}
	}

	if len(role.AllowedDNSSANs) > 0 {
		if !matchesAnyGlob(cert.DNSNames, role.AllowedDNSSANs) {
			return fmt.Errorf("certificate DNS SANs not allowed by role")
		}
	}

	if len(role.AllowedEmailSANs) > 0 {
		if !matchesAnyGlob(cert.EmailAddresses, role.AllowedEmailSANs) {
			return fmt.Errorf("certificate email SANs not allowed by role")
		}
	}

	if len(role.AllowedURISANs) > 0 {
		matched := false
		for _, u := range cert.URIs {
			if helper.MatchAny(u.String(), role.AllowedURISANs) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("certificate URI SANs not allowed by role")
		}
	}

	if len(role.AllowedOrganizationalUnits) > 0 {
		if !matchesAnyExact(cert.Subject.OrganizationalUnit, role.AllowedOrganizationalUnits) {
			return fmt.Errorf("certificate OU not allowed by role")
		}
	}

	if len(role.AllowedOrganizations) > 0 {
		if !matchesAnyExact(cert.Subject.Organization, role.AllowedOrganizations) {
			return fmt.Errorf("certificate organization not allowed by role")
		}
	}

	return nil
}

// validCertMetadataFields lists the certificate field selectors usable in a
// role's metadata_mappings.
var validCertMetadataFields = map[string]bool{
	"cn":        true,
	"serial":    true,
	"ou":        true,
	"org":       true,
	"dns_san":   true,
	"email_san": true,
	"uri_san":   true,
}

// extractCertMetadata builds the token metadata map from verified certificate
// fields using the role's mappings (cert field selector -> metadata key, source
// -> key). Empty fields are skipped. Returns nil when nothing was mapped.
func extractCertMetadata(cert *x509.Certificate, mappings map[string]string) map[string]string {
	if len(mappings) == 0 {
		return nil
	}
	md := make(map[string]string)
	for source, target := range mappings {
		if v := certFieldValue(cert, source); v != "" {
			md[target] = v
		}
	}
	if len(md) == 0 {
		return nil
	}
	return md
}

// certFieldValue renders a certificate field selector to a string. Multi-valued
// fields (OU, Org, and the SAN lists) are comma-joined so the result is a single
// deterministic metadata value.
func certFieldValue(cert *x509.Certificate, field string) string {
	switch field {
	case "cn":
		return cert.Subject.CommonName
	case "serial":
		return cert.SerialNumber.String()
	case "ou":
		return strings.Join(cert.Subject.OrganizationalUnit, ",")
	case "org":
		return strings.Join(cert.Subject.Organization, ",")
	case "dns_san":
		return strings.Join(cert.DNSNames, ",")
	case "email_san":
		return strings.Join(cert.EmailAddresses, ",")
	case "uri_san":
		uris := make([]string, len(cert.URIs))
		for i, u := range cert.URIs {
			uris[i] = u.String()
		}
		return strings.Join(uris, ",")
	}
	return ""
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

// matchesGlob checks if a value matches any of the glob patterns.
func matchesGlob(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := path.Match(pattern, value); matched {
			return true
		}
	}
	return false
}

// matchesAnyGlob checks if any of the values matches any of the glob patterns.
func matchesAnyGlob(values []string, patterns []string) bool {
	for _, v := range values {
		if matchesGlob(v, patterns) {
			return true
		}
	}
	return false
}

// matchesAnyExact checks if any of the values matches any of the allowed values exactly.
func matchesAnyExact(values []string, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = struct{}{}
	}
	for _, v := range values {
		if _, ok := allowedSet[v]; ok {
			return true
		}
	}
	return false
}
