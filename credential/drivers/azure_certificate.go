package drivers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/stephnangue/warden/logger"
)

// Certificate authentication (auth_method=certificate).
//
// The app proves itself to Entra ID with a client assertion it signs with the key of a
// certificate registered on it — what Entra calls a certificate credential. The
// assertion is PS256 and names the certificate by its SHA-256 thumbprint (x5t#S256);
// it lives five minutes and is never reused, so the key itself never leaves Warden.

// acquireTokenWithCertificateOp names the source-token request in errors.
const acquireTokenWithCertificateOp = "acquireTokenWithCertificate"

// entraTokenURL is the token endpoint of tenantID at the source's authority. A
// certificate assertion names it as its audience, so it follows login_endpoint just
// as the request does.
func (d *AzureDriver) entraTokenURL(tenantID string) string {
	return fmt.Sprintf("%s/%s/oauth2/v2.0/token", d.loginBase(), tenantID)
}

// certClientAssertion signs a client assertion for clientID at tenantID's token
// endpoint with the source's certificate.
//
// The certificate's expiry is checked first, so an expired certificate is reported
// as what it is rather than as Entra's opaque refusal of the assertion.
func (d *AzureDriver) certClientAssertion(tenantID, clientID string) (string, error) {
	ca := d.cert
	if ca == nil {
		return "", fmt.Errorf("azure: the source has no certificate")
	}
	now := d.clock()
	if now.After(ca.cert.leaf.NotAfter) {
		return "", fmt.Errorf("azure: the source certificate (x5t#S256 %s) expired at %s; register a new certificate on app %s and update the source",
			ca.cert.x5tS256, ca.cert.leaf.NotAfter.UTC().Format(time.RFC3339), clientID)
	}
	// Validation admits a certificate starting a few minutes ahead, for clock skew;
	// until it starts, Entra would refuse it as though it were the wrong certificate.
	if now.Before(ca.cert.leaf.NotBefore) {
		return "", fmt.Errorf("azure: the source certificate (x5t#S256 %s) is not valid until %s",
			ca.cert.x5tS256, ca.cert.leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	d.warnCertExpiry(now)

	claims, err := certClientAssertionClaims(clientID, d.entraTokenURL(tenantID))
	if err != nil {
		return "", fmt.Errorf("azure: %w", err)
	}
	assertion, err := signCertClientAssertionLocal(ca.key, ca.cert.x5tS256, claims)
	if err != nil {
		return "", fmt.Errorf("azure: %w", err)
	}
	return assertion, nil
}

// acquireTokenWithCertificate obtains a token for the source's own app with the
// client-credentials grant, authenticated by a certificate assertion.
//
// It reads the response as an on-behalf-of request does: Entra's codes classify a
// refusal, and no response body is copied into an error.
func (d *AzureDriver) acquireTokenWithCertificate(ctx context.Context, tenantID, clientID, resourceURI string) (string, int, error) {
	// tenantID was validated with the source config; postEntraTokenRequest checks it
	// again before it reaches a URL.
	assertion, err := d.certClientAssertion(tenantID, clientID)
	if err != nil {
		return "", 0, err
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_assertion_type", clientAssertionType)
	form.Set("client_assertion", assertion)
	form.Set("scope", azureScope(resourceURI))
	form.Set("grant_type", "client_credentials")

	tok, err := d.postEntraTokenRequest(ctx, tenantID, form, acquireTokenWithCertificateOp)
	if err != nil {
		return "", 0, classifyEntraCertAuthError(err, clientID, d.cert.cert.x5tS256)
	}
	return tok.AccessToken, tok.ExpiresIn, nil
}

// classifyEntraCertAuthError explains a refused certificate assertion. AADSTS700027
// covers every way the assertion's signature can fail — the certificate is not
// registered on the app, has expired there, or the key does not match it — and
// Entra files them all under invalid_client.
func classifyEntraCertAuthError(err error, clientID, x5tS256 string) error {
	var ete *entraTokenError
	if !errors.As(err, &ete) {
		return fmt.Errorf("azure: token request failed: %w", err)
	}
	if ete.hasCode(700027) || ete.code == "invalid_client" {
		return certRefusedError(clientID, x5tS256, ete)
	}
	return fmt.Errorf("azure: token request refused: %w", ete)
}

// certRefusedError is the operator-facing message for a certificate assertion Entra
// refused. Entra files an assertion outside its validity window (500133) under
// invalid_client too; that one is Warden's clock, not the certificate, and says so.
func certRefusedError(clientID, x5tS256 string, ete *entraTokenError) error {
	if ete.hasCode(500133) {
		return fmt.Errorf("azure: Entra ID refused the certificate assertion of app %s as outside its validity window; check Warden's clock: %w",
			clientID, ete)
	}
	return fmt.Errorf("azure: Entra ID refused the certificate assertion of app %s (x5t#S256 %s); the certificate must be registered on the app, unexpired there, and match the source's private key: %w",
		clientID, x5tS256, ete)
}

// warnCertExpiry logs when the source certificate is close to expiry. It is called on
// the paths that sign with the certificate, and logs at most once per
// azureCertWarnInterval: a single atomic load in the common case.
func (d *AzureDriver) warnCertExpiry(now time.Time) {
	ca := d.cert
	if ca == nil || d.logger == nil {
		return
	}
	next := d.certWarnNext.Load()
	if now.UnixNano() < next || !d.certWarnNext.CompareAndSwap(next, now.Add(azureCertWarnInterval).UnixNano()) {
		return
	}
	if !ca.cert.expiresWithin(now, azureCertWarnSoon) {
		return
	}
	fields := []logger.TypedField{
		logger.String("x5t_s256", ca.cert.x5tS256),
		logger.String("thumbprint_sha1", ca.cert.sha1Hex),
		logger.String("not_after", ca.cert.leaf.NotAfter.UTC().Format(time.RFC3339)),
	}
	if ca.cert.expiresWithin(now, azureCertWarnUrgent) {
		d.logger.Error("azure source certificate expires within 7 days; roll it over or every mint on this source will fail", fields...)
		return
	}
	d.logger.Warn("azure source certificate expires within 30 days; roll it over", fields...)
}
