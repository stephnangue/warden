package drivers

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// defaultCloudflareChainTTL bounds how long a served Cloudflare credential is
// reused before the chain is walked again. See MintFromSecret.
const defaultCloudflareChainTTL = 30 * time.Minute

// cloudflareR2Fields are the credential's R2 halves. They are read by name and
// never stand in for the API token.
var cloudflareR2Fields = map[string]bool{"access_key_id": true, "secret_access_key": true}

// CloudflareDriver serves Cloudflare credentials that live in another spec: an
// API token for the REST API, an R2 key pair for object storage, or both. The
// source holds nothing. Each spec names, through its own secret_spec, the spec
// that yields its credential, and Warden fetches it per request as the caller.
//
// It makes no request to Cloudflare. The credential already exists, so there is
// nothing to create and nothing to revoke.
type CloudflareDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
}

// CloudflareDriverFactory creates CloudflareDriver instances.
type CloudflareDriverFactory struct{}

var (
	_ credential.SourceDriver        = (*CloudflareDriver)(nil)
	_ credential.ChainedSecretMinter = (*CloudflareDriver)(nil)
)

// Type returns the driver type identifier.
func (f *CloudflareDriverFactory) Type() string {
	return credential.SourceTypeCloudflare
}

// ValidateConfig accepts a source with no configuration, and refuses a
// source-level secret_spec: the credential is each spec's own, so the reference
// belongs on the spec. A source-level one would apply to every spec at once and
// give no spec a way to name a different credential.
//
// The reference's modifiers are refused with it. The minting layer would apply
// a source-level secret_field or secret_cache_ttl to each spec's reference, but
// only half-way: the spec, which the driver and the credential type read, would
// not show them, so a field naming an R2 half would pass unchecked and the served
// credential's TTL would not follow the cache's.
func (f *CloudflareDriverFactory) ValidateConfig(config credential.Config) error {
	for _, key := range []string{credential.ConfigSecretSpec, credential.ConfigSecretField, credential.ConfigSecretCacheTTL} {
		if config.Get(key) != "" {
			return fmt.Errorf("'%s' belongs on each cloudflare_keys spec, not on the source: the credential is the spec's own", key)
		}
	}
	return nil
}

// SensitiveConfigFields returns nothing: the source holds no secret.
func (f *CloudflareDriverFactory) SensitiveConfigFields() []string {
	return nil
}

// StoredSecrets reports nothing: the source holds no secret, and its specs
// fetch theirs through secret_spec.
func (f *CloudflareDriverFactory) StoredSecrets(_ credential.Config) []string {
	return nil
}

// InferCredentialType returns cloudflare_keys, the only type this source serves.
func (f *CloudflareDriverFactory) InferCredentialType(_ credential.Config) (string, error) {
	return credential.TypeCloudflareKeys, nil
}

// Create instantiates a CloudflareDriver.
func (f *CloudflareDriverFactory) Create(config credential.Config, log *logger.GatedLogger) (credential.SourceDriver, error) {
	return &CloudflareDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeCloudflare,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeCloudflare),
	}, nil
}

// MintCredential fails closed. Every cloudflare_keys spec on this source names a
// secret_spec, so the minting layer calls MintFromSecret instead; reaching here
// means a spec without one, which the credential type refuses at create.
func (d *CloudflareDriver) MintCredential(_ context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("cloudflare: spec %q must set %s naming a spec that yields its credential; the credential is served from that material, never minted here",
		spec.Name, credential.ConfigSecretSpec)
}

// MintFromSecret serves the credential the referenced spec yielded.
//
// The API token is read as api_token, or as the field secret_field names when
// the secret stores it under another key; with neither, a single-key secret is
// taken as the token. The R2 pair is read by name, both halves or neither.
func (d *CloudflareDriver) MintFromSecret(_ context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// The spec must name the reference itself. The source refuses one at
	// write, but a source stored before that check is not re-validated against
	// the specs bound to it, so this is the guard that holds.
	if spec.Config.Get(credential.ConfigSecretSpec) == "" {
		return nil, nil, 0, "", fmt.Errorf("cloudflare: spec %q must set its own %s naming a spec that yields its credential",
			spec.Name, credential.ConfigSecretSpec)
	}

	token, err := cloudflareTokenFromMaterial(spec, material)
	if err != nil {
		return nil, nil, 0, "", err
	}

	accessKeyID := material.Data["access_key_id"]
	secretAccessKey := material.Data["secret_access_key"]
	if (accessKeyID == "") != (secretAccessKey == "") {
		return nil, nil, 0, "", fmt.Errorf("cloudflare: fetched secret material must hold both 'access_key_id' and 'secret_access_key' for R2, or neither: %w",
			credential.ErrChainedSecretIncomplete)
	}
	if token == "" && accessKeyID == "" {
		return nil, nil, 0, "", fmt.Errorf("cloudflare: fetched secret material holds neither 'api_token' nor 'access_key_id' and 'secret_access_key': %w",
			credential.ErrChainedSecretIncomplete)
	}

	// The TTL is advisory. This mint makes no request, so it never sees the
	// credential rejected after a rotation upstream, and a zero TTL would pin it
	// in cache for the caller's whole session. With no lease id the credential
	// is not revocable, so this only forces the chain to be walked again.
	ttl := credential.GetDuration(spec.Config, credential.ConfigSecretCacheTTL, 0)
	if ttl <= 0 {
		ttl = defaultCloudflareChainTTL
	}

	rawData := map[string]interface{}{}
	if token != "" {
		rawData["api_token"] = token
	}
	if accessKeyID != "" {
		rawData["access_key_id"] = accessKeyID
		rawData["secret_access_key"] = secretAccessKey
	}

	d.logger.Info("served Cloudflare credential from fetched secret material",
		logger.String("spec", spec.Name),
		logger.Bool("api_token", token != ""),
		logger.String("access_key_id", truncateID(accessKeyID, 8)),
		logger.String("ttl", ttl.String()),
	)

	return rawData, nil, ttl, "", nil
}

// cloudflareTokenFromMaterial resolves the API token, or "" when the material
// holds none, which leaves an R2-only credential.
func cloudflareTokenFromMaterial(spec *credential.CredSpec, material credential.SecretMaterial) (string, error) {
	// A field the spec names is the operator saying where the token is, so it
	// wins over the conventional name, and an empty one is an error rather than
	// a silent fall back to some other key.
	if field := spec.Config.Get(credential.ConfigSecretField); field != "" {
		token := material.Data[field]
		if token == "" {
			// Incomplete rather than a plain error, so a cached copy fetched before
			// the key was added is evicted and the chain walked again once.
			return "", fmt.Errorf("cloudflare: secret_field %q is empty or absent in the fetched secret material: %w",
				field, credential.ErrChainedSecretIncomplete)
		}
		return token, nil
	}
	if token := material.Data["api_token"]; token != "" {
		return token, nil
	}
	// A single-key secret resolves its field on its own. It is the token unless
	// that key is an R2 half, which would then be missing its other half and is
	// reported as such by the caller.
	if material.Field != "" && !cloudflareR2Fields[material.Field] {
		return material.Secret(), nil
	}
	return "", nil
}

// Revoke is a no-op: the credential is served, not created, so there is no lease
// to release.
func (d *CloudflareDriver) Revoke(_ context.Context, leaseID string) error {
	if leaseID != "" {
		d.logger.Warn("cloudflare credentials are served from secret material and hold no lease; nothing to revoke",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the source type.
func (d *CloudflareDriver) Type() string {
	return credential.SourceTypeCloudflare
}

// Cleanup releases nothing: the driver holds no client or connection.
func (d *CloudflareDriver) Cleanup(_ context.Context) error {
	return nil
}
