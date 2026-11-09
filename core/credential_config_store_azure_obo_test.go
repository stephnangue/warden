package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/profiles"
	"github.com/stephnangue/warden/logical"
)

const (
	oboTestTenant = "00000000-0000-0000-0000-000000000001"
	oboTestClient = "11111111-1111-1111-1111-111111111111"
)

// oboSpecConfig is a keyless on_behalf_of spec; extra overrides or adds keys, and an
// empty value deletes one.
func oboSpecConfig(extra map[string]string) credential.Config {
	cfg := map[string]string{
		"mint_method":                       "on_behalf_of",
		"tenant_id":                         oboTestTenant,
		"client_id":                         oboTestClient,
		"resource_uri":                      "https://graph.microsoft.com/",
		credential.ConfigSubjectTokenSource: credential.SourceUserIdentity,
		credential.ConfigActorTokenSource:   credential.SourceWardenIdentity,
	}
	for k, v := range extra {
		if v == "" {
			delete(cfg, k)
			continue
		}
		cfg[k] = v
	}
	return credential.NewConfig(cfg)
}

func createAzureOBOSources(t *testing.T, ctx context.Context, store *CredentialConfigStore) {
	t.Helper()
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "azure-fed", Type: credential.SourceTypeAzure,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}),
	}))
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "azure-static", Type: credential.SourceTypeAzure,
		Config: credential.NewConfig(map[string]string{
			"auth_method":   "static",
			"tenant_id":     oboTestTenant,
			"client_id":     oboTestClient,
			"client_secret": "s3cret",
			"secret_id":     "22222222-2222-2222-2222-222222222222",
		}),
	}))
}

// The user_identity subject and an actor are pinned to token_exchange sources so a
// federation driver never logs in with the user's raw JWT. An azure on_behalf_of
// spec is the one exception — the user's token is only ever the OBO assertion — and
// these cases pin both the exception and its limits.
func TestCredentialConfigStore_ValidateSpec_AzureOnBehalfOf(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	createAzureOBOSources(t, ctx, store)

	create := func(name, source string, cfg credential.Config) error {
		return store.CreateSpec(ctx, &credential.CredSpec{
			Name: name, Type: credential.TypeAzureBearerToken, Source: source, Config: cfg,
		})
	}

	// Keyless: user token as subject, Warden assertion as the app's credential.
	require.NoError(t, create("obo-keyless", "azure-fed", oboSpecConfig(nil)))
	stored, err := store.GetSpec(ctx, "obo-keyless")
	require.NoError(t, err)
	assert.Equal(t, profiles.MinimalProfileName, stored.Config.Get(credential.ConfigAssertionProfile),
		"the actor assertion gets the Azure create-time default")
	assert.Empty(t, stored.Config.Get(credential.ConfigAssertionAudience), "the audience is derived from the source")

	// Static: no actor, the source's own app.
	require.NoError(t, create("obo-static", "azure-static", oboSpecConfig(map[string]string{
		credential.ConfigActorTokenSource: "",
	})))

	// Keyless: the spec may name another app than the one the source names, since
	// the Warden assertion is checked against that app's own federated credential.
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "azure-fed-app", Type: credential.SourceTypeAzure,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "client_id": oboTestClient}),
	}))
	require.NoError(t, create("obo-keyless-other-app", "azure-fed-app", oboSpecConfig(map[string]string{
		"client_id": "33333333-3333-3333-3333-333333333333",
	})))

	tests := []struct {
		name, source string
		cfg          credential.Config
		wantErr      string
	}{
		{"keyless without an actor", "azure-fed",
			oboSpecConfig(map[string]string{credential.ConfigActorTokenSource: ""}), "actor_token_source=warden_identity"},
		{"keyless with the agent's JWT as actor", "azure-fed",
			oboSpecConfig(map[string]string{credential.ConfigActorTokenSource: credential.SourceAgentIdentity}), "actor_token_source=warden_identity"},
		{"static with an actor", "azure-static",
			oboSpecConfig(nil), "remove actor_token_source"},
		{"static naming another app", "azure-static",
			oboSpecConfig(map[string]string{credential.ConfigActorTokenSource: "", "client_id": "33333333-3333-3333-3333-333333333333"}), "'client_id' must match"},
		{"user claims projected into an agent-only assertion", "azure-fed",
			oboSpecConfig(map[string]string{credential.ConfigAssertionUserClaims: "email"}), "assertion_user_claims"},
		{"subject token type has no use", "azure-fed",
			oboSpecConfig(map[string]string{credential.ConfigSubjectTokenType: credential.TokenTypeJWT}), "subject_token_type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := create("obo-bad", tc.source, tc.cfg)
			require.Error(t, err)
			assertBadRequest(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	// The pin still holds for every other azure mint method.
	err = create("bearer-user", "azure-fed", credential.NewConfig(map[string]string{
		"mint_method":                       "bearer_token",
		"tenant_id":                         oboTestTenant,
		"client_id":                         oboTestClient,
		credential.ConfigSubjectTokenSource: credential.SourceUserIdentity,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token_exchange")
}

// A certificate source authenticates on_behalf_of as a static one does — with its own
// credential, for its own app — so it takes the static shape and refuses the rest.
func TestCredentialConfigStore_ValidateSpec_AzureOnBehalfOf_Certificate(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	// No certificate or private_key: this store has no driver registry, so the
	// source's own config is not validated, and the spec rules read auth_method only.
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "azure-cert", Type: credential.SourceTypeAzure,
		Config: credential.NewConfig(map[string]string{
			"auth_method": "certificate",
			"tenant_id":   oboTestTenant,
			"client_id":   oboTestClient,
		}),
	}))
	create := func(name string, cfg credential.Config) error {
		return store.CreateSpec(ctx, &credential.CredSpec{
			Name: name, Type: credential.TypeAzureBearerToken, Source: "azure-cert", Config: cfg,
		})
	}

	require.NoError(t, create("obo-cert", oboSpecConfig(map[string]string{credential.ConfigActorTokenSource: ""})))

	err := create("obo-cert-actor", oboSpecConfig(nil))
	require.Error(t, err)
	assertBadRequest(t, err)
	assert.Contains(t, err.Error(), "remove actor_token_source")

	err = create("obo-cert-other-app", oboSpecConfig(map[string]string{
		credential.ConfigActorTokenSource: "", "client_id": "33333333-3333-3333-3333-333333333333",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'client_id' must match")
}

// A certificate source whose key is held in a KMS chains a signing capability: it
// serves on_behalf_of (an exchange spec on a chained source, which the generic chained
// rule would refuse) and secret_read, never a bearer_token spec, and takes the
// reference on the source only.
func TestCredentialConfigStore_ValidateSpec_AzureKMSCertificate(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	createEntraSigner(t, ctx, store)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "azure-kms", Type: credential.SourceTypeAzure,
		Config: credential.NewConfig(map[string]string{
			"auth_method":               "certificate",
			"tenant_id":                 oboTestTenant,
			"client_id":                 oboTestClient,
			credential.ConfigSecretSpec: "entra-signer",
		}),
	}))
	create := func(name, typ string, cfg credential.Config) error {
		return store.CreateSpec(ctx, &credential.CredSpec{Name: name, Type: typ, Source: "azure-kms", Config: cfg})
	}

	require.NoError(t, create("obo-kms", credential.TypeAzureBearerToken,
		oboSpecConfig(map[string]string{credential.ConfigActorTokenSource: ""})))

	err := create("obo-kms-actor", credential.TypeAzureBearerToken, oboSpecConfig(nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove actor_token_source")

	err = create("bearer-kms", credential.TypeAzureBearerToken, credential.NewConfig(map[string]string{
		"mint_method": "bearer_token", "client_id": oboTestClient, "client_secret": "s",
	}))
	require.Error(t, err)
	assertBadRequest(t, err)
	assert.Contains(t, err.Error(), "serves mint_method=secret_read and on_behalf_of")

	// A bearer_token spec asking for federation is refused here too, at write time.
	err = create("bearer-kms-fed", credential.TypeAzureBearerToken, credential.NewConfig(map[string]string{
		"mint_method": "bearer_token", "tenant_id": oboTestTenant, "client_id": oboTestClient,
		credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "serves mint_method=secret_read and on_behalf_of")

	err = create("obo-spec-ref", credential.TypeAzureBearerToken, oboSpecConfig(map[string]string{
		credential.ConfigActorTokenSource: "", credential.ConfigSecretSpec: "entra-signer",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set secret_spec on the source")
}

// createEntraSigner creates the signer a KMS certificate source chains: a
// transit_signer spec minted as the caller.
func createEntraSigner(t *testing.T, ctx context.Context, store *CredentialConfigStore) {
	t.Helper()
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "openbao", Type: credential.SourceTypeVault,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}),
	}))
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "entra-signer", Type: credential.TypeKeyValue, Source: "openbao",
		Config: credential.NewConfig(map[string]string{
			"mint_method":                       "transit_signer",
			"transit_key":                       "warden-entra",
			"signing_alg":                       "PS256",
			"jwt_role":                          "warden-entra-signer",
			"payload.client_id":                 oboTestClient,
			credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
			credential.ConfigAssertionAudience:  "https://openbao.example/warden",
		}),
	}))
}

// Moving a certificate source's key into a KMS would strand a bound bearer_token
// spec — every mint and every scheduled rotation would fail — so the edit is refused.
func TestCredentialConfigStore_UpdateSource_StrandsAzureBearerOnKMS(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	createEntraSigner(t, ctx, store)
	certSource := func(extra map[string]string) *credential.CredSource {
		cfg := map[string]string{"auth_method": "certificate", "tenant_id": oboTestTenant, "client_id": oboTestClient}
		for k, v := range extra {
			cfg[k] = v
		}
		return &credential.CredSource{Name: "azure-cert", Type: credential.SourceTypeAzure, Config: credential.NewConfig(cfg)}
	}
	require.NoError(t, store.CreateSource(ctx, certSource(nil)))
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "workload", Type: credential.TypeAzureBearerToken, Source: "azure-cert",
		Config: credential.NewConfig(map[string]string{
			"mint_method": "bearer_token", "client_id": oboTestClient, "client_secret": "s",
		}),
	}))

	err := store.UpdateSource(ctx, certSource(map[string]string{credential.ConfigSecretSpec: "entra-signer"}),
		UpdateSourceOptions{SkipConnectionTest: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `spec "workload"`)
	assert.Contains(t, err.Error(), "serves mint_method=secret_read and on_behalf_of")
}

// Switching a source between keyless and static changes what authenticates a bound
// on_behalf_of spec's app, so the edit is refused until the spec is updated.
func TestCredentialConfigStore_UpdateSource_StrandsAzureOnBehalfOf(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	createAzureOBOSources(t, ctx, store)
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "obo-keyless", Type: credential.TypeAzureBearerToken, Source: "azure-fed", Config: oboSpecConfig(nil),
	}))

	err := store.UpdateSource(ctx, &credential.CredSource{
		Name: "azure-fed", Type: credential.SourceTypeAzure,
		Config: credential.NewConfig(map[string]string{
			"auth_method":   "static",
			"tenant_id":     oboTestTenant,
			"client_id":     oboTestClient,
			"client_secret": "s3cret",
			"secret_id":     "22222222-2222-2222-2222-222222222222",
		}),
	}, UpdateSourceOptions{SkipConnectionTest: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `spec "obo-keyless"`)
	assert.Contains(t, err.Error(), "remove actor_token_source")
}

// An on_behalf_of spec resolves exactly like the token_exchange delegation shape:
// the user's token is the subject, forwarded eagerly; the app's credential is a
// Warden assertion of the agent, minted lazily on a cache miss. The assertion
// names only the agent — the user is never disclosed into the client credential —
// and carries the audience Entra's federated credential expects.
func TestResolveExchangeInputs_AzureOnBehalfOf(t *testing.T) {
	c, ctx := exchangeResolveEnv(t)
	c.oidcIssuer = newReadyIssuer(t, "https://warden-oidc.example")
	createAzureOBOSources(t, ctx, c.credConfigStore)
	require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
		Name: "obo", Type: credential.TypeAzureBearerToken, Source: "azure-fed", Config: oboSpecConfig(nil),
	}))

	te := &logical.TokenEntry{
		CredentialSpec: "obo",
		PrincipalID:    "agent-1",
		NamespaceID:    "root",
		MountAccessor:  "auth_jwt_1",
	}
	resolve := func(userToken string) *credential.ExchangeInputs {
		t.Helper()
		req := requestWith("s.opaque-session", nil)
		req.User = &logical.UserPrincipal{TokenEntry: &logical.TokenEntry{}, RawToken: userToken}
		inputs, err := resolveExchangeInputsForTest(c, ctx, req, te)
		require.NoError(t, err)
		require.NotNil(t, inputs)
		return inputs
	}

	inputs := resolve("eyJ.user-a")
	assert.Equal(t, "eyJ.user-a", inputs.SubjectToken, "the user's token is the OBO assertion")
	assert.Empty(t, inputs.ActorToken, "the app's assertion is minted lazily")
	require.NotNil(t, inputs.ResolveActorToken)
	assert.Contains(t, inputs.ActorCacheIdentity, wardenSubject(te))
	assert.Contains(t, inputs.ActorCacheIdentity, "api://AzureADTokenExchange")

	tok, err := inputs.ResolveActorToken(ctx)
	require.NoError(t, err)
	claims := decodeAssertionClaims(t, tok)
	assert.Equal(t, wardenSubject(te), claims["sub"], "the FIC subject is the agent's wid:")
	assert.Equal(t, "api://AzureADTokenExchange", claims["aud"])
	for k := range claims {
		assert.Contains(t, []string{"iss", "sub", "aud", "iat", "nbf", "exp", "jti"}, k,
			"the minimal profile carries registered claims only; nothing about the user")
	}

	// The cache key follows the user: the same token keys alike, another user apart.
	assert.Equal(t, inputs.Fingerprint(), resolve("eyJ.user-a").Fingerprint())
	assert.NotEqual(t, inputs.Fingerprint(), resolve("eyJ.user-b").Fingerprint())
}
