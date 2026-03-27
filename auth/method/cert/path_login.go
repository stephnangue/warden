package cert

import (
	"context"
	"crypto/x509"
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
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Role to assume after authentication (falls back to default_role if configured)",
			},
		},
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
		HelpSynopsis:    "Authenticate using a TLS client certificate",
		HelpDescription: "This endpoint authenticates using a client certificate presented via TLS or forwarded by a trusted load balancer.",
	}
}

// handleLogin handles the certificate login operation
func (b *certAuthBackend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	// Extract client certificate from TLS connection or forwarded header
	cert := extractClientCert(req)
	if cert == nil {
		return logical.ErrorResponse(logical.ErrBadRequest("no client certificate provided")), nil
	}

	// Get role name — fall back to default_role if configured
	roleName := d.Get("role").(string)
	if roleName == "" && b.config != nil && b.config.DefaultRole != "" {
		roleName = b.config.DefaultRole
	}
	if roleName == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("missing role")), nil
	}

	// Look up the role
	role, err := b.getRole(ctx, roleName)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if role == nil {
		b.logger.Warn("login failed: role not found", lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errCertAuthFailed,
		}, nil
	}

	// Build CA pool: role-specific overrides global
	caPool, err := b.getCAPool(role)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if caPool == nil {
		return &logical.Response{
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("no trusted CA certificates configured"),
		}, nil
	}

	// Verify certificate chain
	verifyOpts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	verifiedChains, err := cert.Verify(verifyOpts)
	if err != nil {
		b.logger.Warn("login failed: certificate verification error", lgr.Err(err), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errCertAuthFailed,
		}, nil
	}

	// Check certificate revocation status if configured
	if b.revocationChecker != nil && b.config != nil &&
		b.config.RevocationMode != "" && b.config.RevocationMode != "none" {
		if err := b.revocationChecker.checkRevocation(cert, verifiedChains, b.config.RevocationMode); err != nil {
			b.logger.Warn("login failed: certificate revocation check", lgr.Err(err), lgr.String("role", roleName))
			return &logical.Response{
				StatusCode: http.StatusUnauthorized,
				Err:        errCertAuthFailed,
			}, nil
		}
	}

	// Validate role constraints
	if err := validateCertConstraints(cert, role); err != nil {
		b.logger.Warn("login failed: certificate constraint check", lgr.Err(err), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errCertAuthFailed,
		}, nil
	}

	// Determine principal claim source: role overrides global config
	principalClaim := role.PrincipalClaim
	if principalClaim == "" && b.config != nil {
		principalClaim = b.config.PrincipalClaim
	}
	if principalClaim == "" {
		principalClaim = "cn"
	}

	// Extract principal identity from the certificate
	principalID := extractPrincipal(cert, principalClaim)
	if principalID == "" {
		b.logger.Warn("login failed: no principal identity in certificate",
			lgr.String("principal_claim", principalClaim), lgr.String("role", roleName))
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        errCertAuthFailed,
		}, nil
	}

	// Calculate effective TTL
	effectiveTTL := b.calculateTTL(cert, role)

	tokenType := "cert_role"

	// Certificate fingerprint for token caching in transparent mode
	fingerprint := certFingerprint(cert)

	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID:    principalID,
			RoleName:       roleName,
			Policies:       role.TokenPolicies,
			CredentialSpec: role.CredSpecName,
			TokenType:      tokenType,
			TokenTTL:       effectiveTTL,
			ClientIP:       req.ClientIP,
			ClientToken:    fingerprint, // Cert fingerprint for token type caching
		},
		Data: map[string]any{
			"principal_id": principalID,
			"role":         roleName,
			"fingerprint":  fingerprint,
		},
	}, nil
}

// getCAPool returns the CA pool to use for cert verification.
// Role-specific CA overrides the global trusted CAs.
func (b *certAuthBackend) getCAPool(role *CertRole) (*x509.CertPool, error) {
	if role.Certificate != "" {
		return buildCAPool(role.Certificate)
	}
	if b.config != nil && b.config.caPool != nil {
		return b.config.caPool, nil
	}
	return nil, nil
}

// calculateTTL returns the effective TTL, capped by the certificate's NotAfter.
func (b *certAuthBackend) calculateTTL(cert *x509.Certificate, role *CertRole) time.Duration {
	// Start with the certificate's remaining validity
	certTTL := time.Until(cert.NotAfter)
	if certTTL <= 0 {
		return 0
	}

	// Role TTL
	roleTTL, err := role.ParseTokenTTL()
	if err != nil {
		roleTTL = time.Hour
	}

	// Global config TTL
	var configTTL time.Duration
	if b.config != nil {
		configTTL = b.config.TokenTTL
	}

	// Pick the smallest positive TTL among: certTTL, roleTTL, configTTL
	effectiveTTL := certTTL
	if roleTTL > 0 && roleTTL < effectiveTTL {
		effectiveTTL = roleTTL
	}
	if configTTL > 0 && configTTL < effectiveTTL {
		effectiveTTL = configTTL
	}

	return effectiveTTL
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
	case "spiffe_id":
		for _, u := range cert.URIs {
			if strings.HasPrefix(u.String(), "spiffe://") {
				return u.String()
			}
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
