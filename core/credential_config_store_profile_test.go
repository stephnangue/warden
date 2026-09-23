package core

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertBadRequest asserts the error carries HTTP 400, so an operator's bad value
// is reported as their mistake rather than as a server fault.
func assertBadRequest(t *testing.T, err error) {
	t.Helper()
	var coded *logical.CodedError
	require.ErrorAs(t, err, &coded, "want a *logical.CodedError, got %T: %v", err, err)
	assert.Equal(t, http.StatusBadRequest, coded.Code())
}

// pinnedTestProfile is a source-pinned profile for the spec-create pin test.
type pinnedTestProfile struct{}

func (pinnedTestProfile) Name() string                         { return "pinned_shape" }
func (pinnedTestProfile) Typ() string                          { return "JWT" }
func (pinnedTestProfile) ValidateSpec(credential.Config) error { return nil }
func (pinnedTestProfile) SourceTypes() []string                { return []string{credential.SourceTypeAWS} }
func (pinnedTestProfile) Claims(credential.AssertionRequest) (map[string]any, error) {
	return nil, nil
}

// TestCredentialConfigStore_ValidateSpec_AssertionProfile is the check that does not
// exist for any other spec-config value: nothing in the tree rejects an unknown
// VALUE on its own (ValidateSchema walks only declared validators), so without the
// explicit call in validateSpec an assertion_profile typo would be stored happily
// and fail only at mint, on every request the spec ever served.
func TestCredentialConfigStore_ValidateSpec_AssertionProfile(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "aws-fed", Type: credential.SourceTypeAWS,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}),
	}))
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "vault-src", Type: credential.SourceTypeVault,
		Config: credential.NewConfig(map[string]string{
			"address": "https://vault.example", "auth_method": "oidc_federation",
		}),
	}))
	require.NoError(t, store.core.assertionProfileRegistry.Register(pinnedTestProfile{}))

	spec := func(name, source, profile string) *credential.CredSpec {
		cfg := map[string]string{
			credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
			credential.ConfigAssertionAudience:  "sts.amazonaws.com",
			"mint_method":                       "secrets_manager",
			"secret_id":                         "prod/db",
		}
		if profile != "" {
			cfg[credential.ConfigAssertionProfile] = profile
		}
		return &credential.CredSpec{
			Name: name, Type: "vault_token", Source: source, Config: credential.NewConfig(cfg),
		}
	}

	tests := []struct {
		name     string
		spec     *credential.CredSpec
		errorMsg string // empty => expect success
	}{
		{
			name: "unset is accepted (means default)",
			spec: spec("prof-unset", "aws-fed", ""),
		},
		{
			name: "explicit default is accepted",
			spec: spec("prof-default", "aws-fed", credential.DefaultAssertionProfileName),
		},
		{
			name:     "a typo is rejected at create, not at mint",
			spec:     spec("prof-typo", "aws-fed", "nope"),
			errorMsg: "unknown assertion profile: nope",
		},
		{
			name: "a source-pinned profile is accepted on a matching source",
			spec: spec("prof-pinned-ok", "aws-fed", "pinned_shape"),
		},
		{
			name:     "a source-pinned profile is rejected on the wrong source",
			spec:     spec("prof-pinned-bad", "vault-src", "pinned_shape"),
			errorMsg: "requires a source of type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.CreateSpec(ctx, tt.spec)
			if tt.errorMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
			// It must surface as a 400, not a 500: the operator's value is wrong.
			assertBadRequest(t, err)
		})
	}
}

// Validation runs on UPDATE as well as create — the update handler merges config and
// calls UpdateSpec → validateSpec — so a good spec cannot be edited into a bad one.
func TestCredentialConfigStore_ValidateSpec_AssertionProfileOnUpdate(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "aws-fed", Type: credential.SourceTypeAWS,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}),
	}))

	base := map[string]string{
		credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
		credential.ConfigAssertionAudience:  "sts.amazonaws.com",
		"mint_method":                       "secrets_manager",
		"secret_id":                         "prod/db",
	}
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "prof-upd", Type: "vault_token", Source: "aws-fed",
		Config: credential.NewConfig(base),
	}))

	// Editing in a good profile is fine.
	good := map[string]string{}
	for k, v := range base {
		good[k] = v
	}
	good[credential.ConfigAssertionProfile] = credential.DefaultAssertionProfileName
	require.NoError(t, store.UpdateSpec(ctx, &credential.CredSpec{
		Name: "prof-upd", Type: "vault_token", Source: "aws-fed",
		Config: credential.NewConfig(good),
	}))

	// Editing in a bad one is rejected.
	bad := map[string]string{}
	for k, v := range base {
		bad[k] = v
	}
	bad[credential.ConfigAssertionProfile] = "nope"
	err := store.UpdateSpec(ctx, &credential.CredSpec{
		Name: "prof-upd", Type: "vault_token", Source: "aws-fed",
		Config: credential.NewConfig(bad),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown assertion profile: nope")
	assertBadRequest(t, err)
}

// The key is gated on warden_identity by the structural validator, so a spec that
// mints no assertion cannot carry it at all — the same rule as its four siblings.
func TestCredentialConfigStore_ValidateSpec_AssertionProfileNeedsWardenIdentity(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "vault-kv", Type: credential.SourceTypeVault,
		Config: credential.NewConfig(map[string]string{
			"address": "https://vault.example", "auth_method": "oidc_federation",
		}),
	}))

	err := store.CreateSpec(ctx, &credential.CredSpec{
		Name: "static-key", Type: "api_key", Source: "vault-kv",
		Config: credential.NewConfig(map[string]string{
			"mint_method":                     "static_apikey",
			"kv2_mount":                       "secret",
			"secret_path":                     "apis/orders",
			credential.ConfigAssertionProfile: credential.DefaultAssertionProfileName,
		}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigAssertionProfile)
	assert.Contains(t, err.Error(), credential.SourceWardenIdentity)
}
