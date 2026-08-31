package drivers

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/remotesign"
	"github.com/stephnangue/warden/logger"
)

// mintMethodTransitSigner mints a scoped signing capability rather than a secret: a
// short-lived token that may do nothing but sign with one named key, plus the
// coordinates naming that key. A consumer chains it and asks the store to sign, so the
// private key is read by nobody — including Warden.
const mintMethodTransitSigner = "transit_signer"

// defaultTransitMount is the conventional mount path for a transit engine.
const defaultTransitMount = "transit"

// defaultSigningAlg is the algorithm assumed when a spec names none. RS256 is the one
// algorithm essentially every authorization server accepts for client assertions.
const defaultSigningAlg = "RS256"

// transitSignerPayloadPrefix marks spec-config keys carried verbatim into the minted
// payload. What travels there means something only to the consumer — the OAuth client
// the key is registered to, a key id an authorization server selects on — so this
// driver copies it without interpreting it, rather than growing config keys for a
// protocol it does not speak.
const transitSignerPayloadPrefix = "payload."

// mintTransitSigner builds the signing capability. The login token IS the credential,
// as with a plain token mint, so it is never revoked here: the consumer needs it live
// for as long as it holds the material.
//
// Every coordinate is resolved and checked now, against the real key, so a
// misconfiguration surfaces here naming the key and its actual type — rather than much
// later as an assertion the authorization server rejects for reasons it will not
// explain.
func (d *VaultDriver) mintTransitSigner(
	ctx context.Context,
	client *api.Client,
	spec *credential.CredSpec,
	loginAuth *api.SecretAuth,
	loginTTL time.Duration,
	userClaims, agentClaims map[string]string,
) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	keyName, err := resolveClaimTemplate(credential.GetString(spec.Config, "transit_key", ""),
		userClaims, agentClaims, "transit_key")
	if err != nil {
		return nil, nil, 0, "", err
	}
	if keyName == "" {
		return nil, nil, 0, "", fmt.Errorf("vault: transit_key is required for mint_method=%s", mintMethodTransitSigner)
	}
	mount := credential.GetString(spec.Config, "transit_mount", defaultTransitMount)
	alg := credential.GetString(spec.Config, "signing_alg", defaultSigningAlg)

	version, err := transitSignerVersion(spec.Config)
	if err != nil {
		return nil, nil, 0, "", err
	}

	// Timeout 0 inherits this request's deadline, which is the right bound: the
	// capability is being minted for this mint and nothing else.
	backend, err := remotesign.NewTransitClientBackend(client, mount, 0, d.logger)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("vault: %w", err)
	}
	defer backend.Close()

	// Reads the key, checks it can sign alg, checks it is non-exportable, and resolves
	// "latest" to a concrete number.
	info, err := backend.NamedKeyInfo(ctx, keyName, alg, version)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("vault: signing key %q is unusable for %s: %w", keyName, alg, err)
	}

	payload, err := transitSignerPayloadFields(spec.Config, userClaims, agentClaims)
	if err != nil {
		return nil, nil, 0, "", err
	}
	if payload["client_id"] == "" {
		return nil, nil, 0, "", fmt.Errorf(
			"vault: mint_method=%s requires %sclient_id on the spec: the consumer names the client its assertion is for, and this driver only carries that name",
			mintMethodTransitSigner, transitSignerPayloadPrefix)
	}

	// A key id the operator did not set is derived from the key and the exact version
	// that will sign, so it always names the public half the authorization server has
	// to hold. Derived after resolution, so a templated key yields a per-caller id.
	if payload["kid"] == "" {
		payload["kid"] = fmt.Sprintf("%s-v%d", info.Ref.KeyName, info.Ref.Version)
	}

	if loginTTL <= 0 {
		// A role issuing a token with no expiry: give the cache layer a positive
		// lifetime rather than a zero, which would read as "static" and never refresh.
		loginTTL = 1 * time.Hour
	}
	if spec.MaxTTL > 0 && loginTTL > spec.MaxTTL {
		loginTTL = spec.MaxTTL
	}

	rawData := map[string]interface{}{
		"kms_backend":         remotesign.BackendTypeTransit,
		"vault_token":         loginAuth.ClientToken,
		"vault_address":       credential.GetString(d.credSource.Config, "vault_address", ""),
		"transit_mount":       mount,
		"transit_key":         info.Ref.KeyName,
		"transit_key_version": strconv.Itoa(info.Ref.Version),
		"signing_alg":         alg,
		// Lets the consumer skip a round trip it already knows will fail, and tell a
		// spent capability apart from a broken one.
		"token_expires_at": time.Now().Add(loginTTL).UTC().Format(time.RFC3339),
	}
	if ns := credential.GetString(d.credSource.Config, "vault_namespace", ""); ns != "" {
		rawData["vault_namespace"] = ns
	}
	for k, v := range payload {
		rawData[k] = v
	}

	// Warden cannot prove the role's policy is as narrow as it should be: a policy is a
	// name here, and enforcing what is behind it belongs to the store. Recording what
	// the login actually granted at least makes a too-broad role visible in an audit
	// log rather than nowhere at all.
	// A token issued without an accessor is not tracked in the store and cannot be
	// revoked or renewed — the cheap, self-expiring shape this capability wants, since
	// it is minted per request and deliberately never revoked. One issued WITH an
	// accessor is persisted instead, so every mint becomes a storage write the store
	// must later clean up.
	//
	// This is recorded rather than enforced. What actually bounds the capability is the
	// role's policy, not the token's shape: with only sign and key-read granted, a
	// tracked token is no more useful to a thief than an untracked one. The cost is
	// operational, so it is the operator's to weigh — but not silently.
	//
	// Every value is a string: credential metadata is flattened to strings on parse, so
	// a slice or a number here fails the mint outright rather than being coerced.
	batch := loginAuth.Accessor == ""
	metadata := map[string]interface{}{
		"role":                d.effectiveJWTRole(spec),
		"policies":            strings.Join(loginAuth.Policies, ","),
		"transit_key":         info.Ref.KeyName,
		"transit_key_version": strconv.Itoa(info.Ref.Version),
		"tracked_token":       strconv.FormatBool(!batch),
	}
	if loginAuth.Accessor != "" {
		metadata["accessor"] = loginAuth.Accessor
	}

	if d.logger != nil {
		if !batch {
			d.logger.Warn("signing capability minted as a tracked token",
				logger.String("spec", spec.Name),
				logger.String("jwt_role", d.effectiveJWTRole(spec)),
				logger.String("detail", "this capability is minted per request and never revoked, so each one is a stored token left to expire; token_type=batch on the role avoids the write"),
			)
		}
		d.logger.Debug("minted a scoped signing capability",
			logger.String("spec", spec.Name),
			logger.String("jwt_role", d.effectiveJWTRole(spec)),
			logger.String("transit_key", info.Ref.KeyName),
			logger.Int("key_version", info.Ref.Version),
			logger.Bool("batch_token", batch),
			logger.String("ttl", loginTTL.String()),
		)
	}

	return rawData, metadata, loginTTL, "", nil
}

// transitSignerVersion reads an optional pinned key version. Absent means "resolve the
// latest at mint time"; either way the resolved number is what travels, never "latest",
// so a held capability keeps signing with the version it was checked against instead of
// whatever happens to be newest when it eventually signs.
func transitSignerVersion(config map[string]string) (int, error) {
	raw := strings.TrimSpace(credential.GetString(config, "transit_key_version", ""))
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return 0, fmt.Errorf("vault: transit_key_version must be a positive integer, got %q", raw)
	}
	return v, nil
}

// validateTransitSignerSpec checks what must hold before a login is attempted. It is a
// no-op for every other mint method.
//
// The capability's entire value is that it can do nothing but sign. Inheriting the
// source's role would hand the consumer whatever that role grants — quietly, and with
// broader reach than the key material this replaces, which would make the feature worse
// than storing the key. So the narrow role is required on the spec, and required here,
// before the login that would otherwise have already obtained the broad token.
func validateTransitSignerSpec(mintMethod string, spec *credential.CredSpec) error {
	if mintMethod != mintMethodTransitSigner {
		return nil
	}
	if credential.GetString(spec.Config, "jwt_role", "") == "" {
		return fmt.Errorf(
			"vault: mint_method=%s requires a spec-level jwt_role naming a role whose policy grants only signing with the key; inheriting the source's role would mint a broader capability than the key it replaces",
			mintMethodTransitSigner)
	}
	return nil
}

// transitSignerCoordinates are the payload names this driver writes itself. The
// passthrough bag may not use them: stripped of its prefix, payload.vault_token would
// land on the same key as the capability's real token and, being merged second, would
// replace it — sending the capability somewhere else, or spending a token that is not
// the one this mint obtained.
var transitSignerCoordinates = map[string]struct{}{
	"kms_backend": {}, "vault_token": {}, "vault_address": {}, "vault_namespace": {},
	"transit_mount": {}, "transit_key": {}, "transit_key_version": {},
	"signing_alg": {}, "token_expires_at": {},
}

// transitSignerPayloadFields collects the payload.* passthrough bag with its prefix
// stripped. Values may be claim-templated, so one spec can front a different client and
// a different key per caller.
//
// A name the driver writes itself is refused rather than dropped: silently ignoring it
// would leave an operator with a spec that reads as though it set something.
func transitSignerPayloadFields(config map[string]string, userClaims, agentClaims map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range credential.GetPrefixed(config, transitSignerPayloadPrefix) {
		if _, reserved := transitSignerCoordinates[k]; reserved {
			return nil, fmt.Errorf(
				"vault: %s%s is not allowed: %q is part of the signing capability this mint writes, and carrying one here would replace it",
				transitSignerPayloadPrefix, k, k)
		}
		resolved, err := resolveClaimTemplate(v, userClaims, agentClaims, transitSignerPayloadPrefix+k)
		if err != nil {
			return nil, err
		}
		out[k] = resolved
	}
	return out, nil
}
