package drivers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/remotesign"
	"github.com/stephnangue/warden/logger"
)

// Certificate authentication (auth_method=certificate).
//
// The app proves itself to Entra ID with a client assertion it signs with the key of a
// certificate registered on it — what Entra calls a certificate credential. The
// assertion is PS256 and names the certificate by its SHA-256 thumbprint (x5t#S256);
// it lives five minutes and is never reused, so the key itself never leaves Warden.
// The key may also be held in a KMS Warden never reads: the source's secret_spec then
// names a signer spec, and each mint signs with the capability it fetches.

var (
	_ credential.ChainedSecretMinter   = (*AzureDriver)(nil)
	_ credential.ChainedExchangeMinter = (*AzureDriver)(nil)
)

// acquireTokenWithCertificateOp names the source-token request in errors.
const acquireTokenWithCertificateOp = "acquireTokenWithCertificate"

// entraTokenURL is the token endpoint of tenantID at the source's authority. A
// certificate assertion names it as its audience, so it follows login_endpoint just
// as the request does.
func (d *AzureDriver) entraTokenURL(tenantID string) string {
	return fmt.Sprintf("%s/%s/oauth2/v2.0/token", d.loginBase(), tenantID)
}

// certClientAssertion signs a client assertion for clientID at tenantID's token
// endpoint with the source's certificate: with the key the source holds, or — when
// the key is held in a KMS — with kms, the signing capability the calling mint
// fetched through the source's secret_spec.
//
// The certificate's expiry is checked first, so an expired certificate is reported
// as what it is rather than as Entra's opaque refusal of the assertion.
func (d *AzureDriver) certClientAssertion(ctx context.Context, tenantID, clientID string, kms *remotesign.Capability) (string, error) {
	ca := d.cert
	if ca == nil {
		return "", fmt.Errorf("azure: the source has no certificate")
	}
	if ca.kmsKey() && kms == nil {
		// Reached only by an operation that runs without a mint — none should, since
		// those are disabled for such a source — or by a spec bypassing chaining.
		return "", fmt.Errorf("azure: the source's certificate key is held in a KMS and is reached only with a signing capability fetched through its %s; this operation has none",
			credential.ConfigSecretSpec)
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
	if !ca.kmsKey() {
		assertion, err := signCertClientAssertionLocal(ca.key, ca.cert.x5tS256, claims)
		if err != nil {
			return "", fmt.Errorf("azure: %w", err)
		}
		return assertion, nil
	}
	if err := d.checkKMSKey(ctx, kms); err != nil {
		return "", err
	}
	assertion, err := signCertClientAssertionWithCapability(ctx, d.capSigners, kms, ca.cert.x5tS256, claims)
	if err != nil {
		return "", fmt.Errorf("azure: %w", err)
	}
	return assertion, nil
}

// checkKMSKey confirms a capability's key is the certificate's, once per key version.
//
// A mismatch would have every assertion refused by Entra as signed by an unregistered
// key, so it is caught here and named, before anything is signed. It carries the
// chaining sentinel, because the common cause is a cached capability pinned to the
// version before a KMS key was rotated and the source given the new version's
// certificate: a fresh capability pins the new version and matches. A mismatch that
// persists costs one refetch and one key read per mint, never a request to Entra.
func (d *AzureDriver) checkKMSKey(ctx context.Context, kms *remotesign.Capability) error {
	id := kms.KeyID()
	if _, ok := d.kmsKeysChecked.Load(id); ok {
		return nil
	}
	pub, err := d.capSigners.PublicKey(ctx, kms)
	if err != nil {
		return fmt.Errorf("azure: reading the signing key's public half: %w", capabilityError(err))
	}
	if err := d.cert.cert.matchesPublicKey(pub); err != nil {
		return fmt.Errorf("azure: KMS key %q version %s: %w; issue and register a certificate for this key version, then update the source: %w",
			kms.Ref.KeyName, kms.Ref.Version, err, credential.ErrChainedSecretRejected)
	}
	// Counted only when new, so concurrent first uses of one key count once. A
	// Clear racing a Store can leave a few more entries than the count; the bound
	// is approximate, which is all a memory bound needs.
	if _, loaded := d.kmsKeysChecked.LoadOrStore(id, struct{}{}); !loaded {
		if d.kmsKeysCheckedSize.Add(1) > maxKMSKeysChecked {
			d.kmsKeysChecked.Clear()
			d.kmsKeysCheckedSize.Store(0)
		}
	}
	return nil
}

// kmsCapability reads the signing capability a chained mint fetched for a certificate
// source whose key is held in a KMS.
//
// The capability must be for the source's own app: the certificate is registered on
// it alone, so a capability naming another client is a misconfigured signer spec,
// refused without the chaining sentinel since a refetch would name the same client.
func (d *AzureDriver) kmsCapability(material credential.SecretMaterial) (*remotesign.Capability, error) {
	if d.cert == nil || !d.cert.kmsKey() {
		return nil, fmt.Errorf("azure: only a certificate source whose key is held in a KMS chains its credential")
	}
	chained, err := chainedClientAuthFromMaterial(clientAuthKMSPrivateKeyJWT, material)
	if err != nil {
		return nil, fmt.Errorf("azure: %w", err)
	}
	if want := d.getClientID(); chained.clientID != want {
		return nil, fmt.Errorf("azure: the signing capability is for client %q, but this source authenticates app %q (set payload.client_id on the signer spec to the source's client_id)",
			chained.clientID, want)
	}
	return chained.kms, nil
}

// MintFromSecret implements credential.ChainedSecretMinter for a certificate source
// whose key is held in a KMS: material is the signing capability the source's
// secret_spec minted for this caller. It serves secret_read; on_behalf_of arrives
// through MintCredentialWithExchangeFromSecret.
func (d *AzureDriver) MintFromSecret(ctx context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	kms, err := d.kmsCapability(material)
	if err != nil {
		return nil, nil, 0, "", err
	}
	switch mintMethod := credential.GetString(spec.Config, "mint_method", "bearer_token"); mintMethod {
	case "secret_read":
		return d.mintViaSecretReadWith(ctx, spec, kms)
	case azureMintMethodOnBehalfOf:
		return nil, nil, 0, "", errAzureOBONeedsUser
	default:
		return nil, nil, 0, "", fmt.Errorf("azure: a certificate source whose key is held in a KMS serves mint_method=secret_read and on_behalf_of, not %q", mintMethod)
	}
}

// MintCredentialWithExchangeFromSecret implements credential.ChainedExchangeMinter for
// a certificate source whose key is held in a KMS: an on_behalf_of exchange whose app
// authenticates with an assertion signed through the fetched capability.
func (d *AzureDriver) MintCredentialWithExchangeFromSecret(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if credential.GetString(spec.Config, "mint_method", "") != azureMintMethodOnBehalfOf {
		return nil, nil, 0, "", fmt.Errorf("azure: a certificate source whose key is held in a KMS exchanges only for mint_method=on_behalf_of")
	}
	kms, err := d.kmsCapability(material)
	if err != nil {
		return nil, nil, 0, "", err
	}
	return d.mintOnBehalfOfWith(ctx, spec, inputs, kms)
}

// acquireTokenWithCertificate obtains a token for the source's own app with the
// client-credentials grant, authenticated by a certificate assertion; kms is the
// signing capability when the certificate's key is held in a KMS.
//
// It reads the response as an on-behalf-of request does: Entra's codes classify a
// refusal, and no response body is copied into an error.
func (d *AzureDriver) acquireTokenWithCertificate(ctx context.Context, tenantID, clientID, resourceURI string, kms *remotesign.Capability) (string, int, error) {
	// tenantID was validated with the source config; postEntraTokenRequest checks it
	// again before it reaches a URL.
	assertion, err := d.certClientAssertion(ctx, tenantID, clientID, kms)
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
