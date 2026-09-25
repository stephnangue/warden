package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// Azure Key Vault reads (mint_method=secret_read).
const (
	// keyVaultResource is the resource a Key Vault data-plane token is requested
	// for. It names the service, not a vault, so one token reads any vault the
	// identity holding it is allowed to.
	keyVaultResource = "https://vault.azure.net/"

	// keyVaultDNSSuffix is the public-cloud data-plane suffix: a vault named acme is
	// reached at https://acme.vault.azure.net.
	keyVaultDNSSuffix = "vault.azure.net"

	// keyVaultAPIVersion is the data-plane API version the read is made against.
	keyVaultAPIVersion = "7.4"

	// keyVaultMaxSecretSize is the largest secret Key Vault stores (25 KB). A value
	// beyond it cannot have come from the service, so it is refused rather than vended.
	keyVaultMaxSecretSize = 25 * 1024
)

// keyVaultSecretURL builds the URL a secret read addresses, resolving any
// {{user.<claim>}} / {{agent.<claim>}} template in the secret name first so one spec
// can serve many callers and each reads only its own secret.
//
// The resolved name is checked again against Key Vault's charset. The claim
// allow-list admits '.', '_' and '@', which a Key Vault secret name does not; left
// to the service, such a name would come back as a 404, which reads like a missing
// secret rather than a template that resolved to something unusable.
//
// With no endpoint override the vault is the host, https://<vault_name>.vault.azure.net.
// An override replaces the whole base, so a source that sets one reads every spec
// through it; vault_name is still required and validated, and still names the vault
// in metadata and in the warden_resource claim.
func (d *AzureDriver) keyVaultSecretURL(spec *credential.CredSpec, userClaims, agentClaims map[string]string) (string, error) {
	vaultName := credential.GetString(spec.Config, "vault_name", "")
	if err := credential.ValidateKeyVaultName(vaultName); err != nil {
		return "", err
	}

	secretName, err := credential.GetStringRequired(spec.Config, "secret_name")
	if err != nil {
		return "", err
	}
	secretName, err = resolveClaimTemplate(secretName, userClaims, agentClaims, "secret_name")
	if err != nil {
		return "", err
	}
	if err := credential.ValidateKeyVaultSecretName(secretName); err != nil {
		return "", fmt.Errorf("resolved %w", err)
	}

	// Every segment is escaped as well as validated: a config that drifted past
	// the write-time checks still cannot reshape the request.
	path := "/secrets/" + url.PathEscape(secretName)
	if version := credential.GetString(spec.Config, "secret_version", ""); version != "" {
		if err := credential.ValidateKeyVaultSecretVersion(version); err != nil {
			return "", err
		}
		path += "/" + url.PathEscape(version)
	}

	base := d.keyVaultEndpoint
	if base == "" {
		base = fmt.Sprintf("https://%s.%s", vaultName, keyVaultDNSSuffix)
	}
	return base + path + "?api-version=" + keyVaultAPIVersion, nil
}

// keyVaultSecretBundle is the part of Key Vault's SecretBundle the read consumes.
type keyVaultSecretBundle struct {
	Value      string `json:"value"`
	ID         string `json:"id"`
	Attributes struct {
		Enabled   *bool  `json:"enabled"`
		NotBefore *int64 `json:"nbf"`
		Expires   *int64 `json:"exp"`
	} `json:"attributes"`
}

// readKeyVaultSecret reads a Key Vault secret with the given bearer token and returns
// it as the credential's data. The token may be the source's own (static auth) or one
// obtained for this caller through federation.
//
// Key Vault serves a secret outside its nbf/exp window — Microsoft documents the
// window as informational, honoured by clients — so the read enforces it: a secret
// that is not yet valid or has expired is refused, not vended. A secret with an expiry
// comes back with a lifetime that ends there, which bounds any cache of it; one
// without has no lifetime and no lease, since nothing here can expire or revoke a
// stored secret.
func (d *AzureDriver) readKeyVaultSecret(ctx context.Context, bearerToken string, spec *credential.CredSpec,
	userClaims, agentClaims map[string]string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {

	secretURL, err := d.keyVaultSecretURL(spec, userClaims, agentClaims)
	if err != nil {
		return nil, nil, 0, "", err
	}
	// The URL minus its query names the secret in every message below; it holds no
	// secret material.
	secretRef, _, _ := strings.Cut(secretURL, "?")

	// One attempt: this is the data path, and a failure surfaces to the caller, who
	// can retry, rather than stalling it behind backoff.
	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "GET",
		url:         secretURL,
		bearerToken: bearerToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "getSecret",
	}, nil, 1)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to read Key Vault secret %s: %w", secretRef, err)
	}

	var bundle keyVaultSecretBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to decode Key Vault secret %s: %w", secretRef, err)
	}

	if bundle.Attributes.Enabled != nil && !*bundle.Attributes.Enabled {
		return nil, nil, 0, "", fmt.Errorf("Key Vault secret %s is disabled", secretRef)
	}
	now := time.Now()
	if nbf := bundle.Attributes.NotBefore; nbf != nil && now.Before(time.Unix(*nbf, 0)) {
		return nil, nil, 0, "", fmt.Errorf("Key Vault secret %s is not valid before %s", secretRef, time.Unix(*nbf, 0).UTC().Format(time.RFC3339))
	}
	var ttl time.Duration
	if exp := bundle.Attributes.Expires; exp != nil {
		expiresAt := time.Unix(*exp, 0)
		if !now.Before(expiresAt) {
			return nil, nil, 0, "", fmt.Errorf("Key Vault secret %s expired at %s", secretRef, expiresAt.UTC().Format(time.RFC3339))
		}
		ttl = expiresAt.Sub(now)
	}

	if bundle.Value == "" {
		return nil, nil, 0, "", fmt.Errorf("Key Vault secret %s has an empty value", secretRef)
	}
	if len(bundle.Value) > keyVaultMaxSecretSize {
		return nil, nil, 0, "", fmt.Errorf("Key Vault secret %s is %d bytes, beyond the %d Key Vault stores", secretRef, len(bundle.Value), keyVaultMaxSecretSize)
	}

	rawData, err := parseSecretPayload([]byte(bundle.Value))
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("Key Vault secret %s: %w", secretRef, err)
	}
	rawData = credential.ApplyKeyMap(rawData, credential.GetString(spec.Config, "json_key_map", ""))
	if len(rawData) == 0 {
		return nil, nil, 0, "", fmt.Errorf("Key Vault secret %s yielded no fields; check 'json_key_map' against the stored payload", secretRef)
	}

	metadata := keyVaultSecretMetadata(spec, bundle, ttl, now)

	if d.logger != nil {
		d.logger.Debug("read Azure Key Vault secret",
			logger.String("spec", spec.Name),
			logger.String("secret", secretRef),
		)
	}

	return rawData, metadata, ttl, "", nil
}

// keyVaultSecretMetadata builds clear-loggable metadata for a Key Vault read: which
// vault, which secret and which version was served. The version comes from the id
// Key Vault returns, so an unpinned read records the version it actually got.
func keyVaultSecretMetadata(spec *credential.CredSpec, bundle keyVaultSecretBundle, ttl time.Duration, now time.Time) map[string]interface{} {
	metadata := map[string]interface{}{
		"vault_name": credential.GetString(spec.Config, "vault_name", ""),
	}
	// id is https://<vault>.vault.azure.net/secrets/<name>/<version>.
	if u, err := url.Parse(bundle.ID); err == nil {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) == 3 && parts[0] == "secrets" {
			metadata["secret_name"] = parts[1]
			metadata["secret_version"] = parts[2]
		}
	}
	if ttl > 0 {
		metadata["expiration"] = now.Add(ttl).UTC().Format(time.RFC3339)
	}
	return metadata
}
