package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keylessPlanRequest calls a keyless-plan handler the way the router would.
func keylessPlanRequest(t *testing.T, backend *SystemBackend, ctx context.Context, kind, name string, raw map[string]any) *logical.Response {
	t.Helper()
	body := map[string]any{"name": name}
	for k, v := range raw {
		body[k] = v
	}
	pattern := "cred/" + kind + "s/"
	for _, p := range backend.pathCredentials() {
		if !strings.HasPrefix(p.Pattern, pattern) || !strings.HasSuffix(p.Pattern, "/keyless-plan") {
			continue
		}
		req := createTestRequest(logical.CreateOperation, pattern+name+"/keyless-plan", body)
		fd := createFieldData(p.Fields, body)
		var resp *logical.Response
		var err error
		if kind == "source" {
			resp, err = backend.handleCredentialSourceKeylessPlan(ctx, req, fd)
		} else {
			resp, err = backend.handleCredentialSpecKeylessPlan(ctx, req, fd)
		}
		require.NoError(t, err)
		return resp
	}
	t.Fatalf("no keyless-plan path for %s", kind)
	return nil
}

// planFromResponse decodes response data the way a client does, through JSON.
func planFromResponse(t *testing.T, resp *logical.Response) KeylessPlan {
	t.Helper()
	require.Equalf(t, http.StatusOK, resp.StatusCode, "%+v %v", resp.Data, resp.Err)
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var plan KeylessPlan
	require.NoError(t, json.Unmarshal(raw, &plan))
	assert.Equal(t, len(plan.Blockers) == 0, resp.Data["ready"], "ready mirrors the blockers")
	return plan
}

// seedSource stores a source without validating it: the connection test a
// create runs would authenticate a keyed source against its provider.
func seedSource(t *testing.T, c *Core, ctx context.Context, source *credential.CredSource) {
	t.Helper()
	ns, err := namespace.FromContext(ctx)
	require.NoError(t, err)
	require.NoError(t, c.credConfigStore.persistSource(ns.UUID, source))
}

func createKeyedAWS(t *testing.T, c *Core, ctx context.Context) {
	t.Helper()
	seedSource(t, c, ctx, &credential.CredSource{
		Name: "aws-prod", Type: credential.SourceTypeAWS,
		RotationPeriod: 24 * time.Hour,
		Config: credential.NewConfig(map[string]string{
			"region":            "us-east-1",
			"access_key_id":     "AKIAEXAMPLEOLD",
			"secret_access_key": "stored-secret",
		}),
	})
	require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
		Name: "deploy", Type: credential.TypeAWSAccessKeys, Source: "aws-prod",
		MaxTTL: time.Hour,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "sts_assume_role",
			"role_arn":    "arn:aws:iam::111122223333:role/Deploy",
		}),
	}))
}

func TestPlanKeylessSource_AWS(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.oidcIssuer = newReadyIssuer(t, "https://warden.example.com")
	createKeyedAWS(t, c, ctx)
	before, err := c.credConfigStore.ListSources(ctx)
	require.NoError(t, err)

	plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "aws-prod", nil))
	require.Empty(t, plan.Blockers)

	require.NotNil(t, plan.Source)
	assert.Equal(t, "aws-prod-keyless", plan.Source.Name)
	assert.Equal(t, "aws-prod", plan.Source.Replaces)
	assert.Equal(t, map[string]string{"region": "us-east-1", "auth_method": "oidc_federation"}, plan.Source.Config,
		"the cleared keys are absent, not empty")

	require.Len(t, plan.Specs, 1)
	spec := plan.Specs[0]
	assert.Equal(t, "deploy-keyless", spec.Name)
	assert.Equal(t, "aws-prod-keyless", spec.Source)
	assert.Equal(t, "deploy", spec.Replaces)
	assert.Equal(t, int64(3600), spec.MaxTTL)
	assert.Equal(t, "warden_identity", spec.Config["subject_token_source"])
	assert.Equal(t, "aws", spec.Config["assertion_profile"])

	var bodies []string
	for _, p := range plan.Prerequisites {
		bodies = append(bodies, p.Body)
	}
	joined := strings.Join(bodies, "\n")
	assert.Contains(t, joined, "create-open-id-connect-provider")
	assert.Contains(t, joined, "sts:TagSession")
	assert.Contains(t, joined, "wid:"+"root:", "the subject is scoped to the namespace")

	require.Len(t, plan.Leftovers, 1)
	assert.Equal(t, "AKIAEXAMPLEOLD", plan.Leftovers[0].ID)
	assert.Contains(t, strings.Join(plan.Notes, "\n"), "rotation_period is not carried over")

	// Nothing was written.
	after, err := c.credConfigStore.ListSources(ctx)
	require.NoError(t, err)
	assert.Len(t, after, len(before))
	_, err = c.credConfigStore.GetSpec(ctx, "deploy-keyless")
	assert.ErrorIs(t, err, ErrSpecNotFound)
	stored, err := c.credConfigStore.GetSource(ctx, "aws-prod")
	require.NoError(t, err)
	assert.Equal(t, "stored-secret", stored.Config.Get("secret_access_key"))
}

func TestPlanKeylessSource_ResponseCarriesNoSecret(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.oidcIssuer = newReadyIssuer(t, "https://warden.example.com")
	createKeyedAWS(t, c, ctx)

	resp := keylessPlanRequest(t, backend, ctx, "source", "aws-prod", nil)
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "stored-secret")
}

// A plan shows nothing a read would not: a key the read path masks stays masked,
// except ca_data, which is not a secret and keeps the create command pasteable.
func TestKeylessPlanData_MasksWhatAReadMasks(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)
	data := backend.keylessPlanData(&KeylessPlan{
		Source: &KeylessObject{
			Name: "k8s-keyless", Type: credential.SourceTypeKubernetes, Replaces: "k8s",
			Config: map[string]string{"kubernetes_url": "https://k8s.example", "auth_method": "oidc_federation", "ca_data": "PEM"},
		},
		Specs: []KeylessObject{{
			Name: "key-keyless", Type: credential.TypeAPIKey, Source: "k8s-keyless", Replaces: "key",
			Config: map[string]string{"secret_spec": "vault-key", "x_signing_key": "maybe-secret"},
		}},
	})

	source := data["source"].(map[string]any)["config"].(map[string]string)
	assert.Equal(t, "PEM", source["ca_data"])
	spec := data["specs"].([]any)[0].(map[string]any)["config"].(map[string]string)
	assert.Equal(t, maskValue, spec["x_signing_key"], "an undeclared api_key field may be a second secret")
	assert.Equal(t, "vault-key", spec["secret_spec"])

	notes := strings.Join(data["notes"].([]string), "\n")
	assert.Contains(t, notes, "x_signing_key (from key)")
}

func TestPlanKeylessSource_Inputs(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.oidcIssuer = newReadyIssuer(t, "https://warden.example.com")
	createKeyedAWS(t, c, ctx)

	t.Run("names", func(t *testing.T) {
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "aws-prod", map[string]any{
			"new_name": "aws-wif",
			"specs":    map[string]any{"deploy": map[string]any{"name": "deploy-wif"}},
		}))
		require.Empty(t, plan.Blockers)
		assert.Equal(t, "aws-wif", plan.Source.Name)
		assert.Equal(t, "deploy-wif", plan.Specs[0].Name)
		assert.Equal(t, "aws-wif", plan.Specs[0].Source)
		assert.NotContains(t, plan.Specs[0].Config, "name", "the name input is not a config key")
	})

	t.Run("a secret input is refused", func(t *testing.T) {
		resp := keylessPlanRequest(t, backend, ctx, "source", "aws-prod", map[string]any{
			"target": map[string]any{"secret_access_key": "leak"},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), "secret field")
	})

	t.Run("an unknown spec is refused", func(t *testing.T) {
		resp := keylessPlanRequest(t, backend, ctx, "source", "aws-prod", map[string]any{
			"specs": map[string]any{"deplyo": map[string]any{"name": "x"}},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), `"deplyo"`)
	})

	t.Run("a name no route matches blocks", func(t *testing.T) {
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "aws-prod", map[string]any{
			"new_name": "aws prod",
			"specs":    map[string]any{"deploy": map[string]any{"name": "x;y"}},
		}))
		blockers := strings.Join(plan.Blockers, "\n")
		assert.Contains(t, blockers, `"aws prod" is not a valid credential source name`)
		assert.Contains(t, blockers, `"x;y" is not a valid credential spec name`)
	})

	t.Run("target name is refused", func(t *testing.T) {
		resp := keylessPlanRequest(t, backend, ctx, "source", "aws-prod", map[string]any{
			"target": map[string]any{"name": "aws-wif"},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), "new_name")
	})

	t.Run("a taken name blocks", func(t *testing.T) {
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "aws-prod", map[string]any{
			"new_name": "aws-prod",
		}))
		assert.Contains(t, strings.Join(plan.Blockers, "\n"), `named "aws-prod" already exists`)
	})
}

func TestPlanKeylessSource_Blockers(t *testing.T) {
	t.Run("no issuer", func(t *testing.T) {
		backend, ctx, c := setupTestSystemBackend(t)
		createKeyedAWS(t, c, ctx)
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "aws-prod", nil))
		assert.Contains(t, strings.Join(plan.Blockers, "\n"), "enable the OIDC issuer")
		assert.Empty(t, plan.Prerequisites)
	})

	t.Run("a spec with no keyless form", func(t *testing.T) {
		backend, ctx, c := setupTestSystemBackend(t)
		c.oidcIssuer = newReadyIssuer(t, "https://warden.example.com")
		createKeyedAWS(t, c, ctx)
		require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
			Name: "rds", Type: credential.TypeDBAuthToken, Source: "aws-prod",
			Config: credential.NewConfig(map[string]string{
				"mint_method": "rds_iam_token", "db_endpoint": "db.example:5432", "db_user": "app",
			}),
		}))

		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "aws-prod", nil))
		assert.Contains(t, strings.Join(plan.Blockers, "\n"), `spec "rds": rds_iam_token has no federated form`)
		require.Len(t, plan.Specs, 1, "the other spec is still planned")
		assert.Equal(t, "deploy-keyless", plan.Specs[0].Name)
	})

	t.Run("a missing input is reported once", func(t *testing.T) {
		backend, ctx, c := setupTestSystemBackend(t)
		c.oidcIssuer = newReadyIssuer(t, "https://warden.example.com")
		seedSource(t, c, ctx, &credential.CredSource{
			Name: "vault-prod", Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "https://vault.example.com", "auth_method": "approle", "role_id": "r", "secret_id": "s",
			}),
		})
		ns, err := namespace.FromContext(ctx)
		require.NoError(t, err)
		require.NoError(t, c.credConfigStore.persistSpec(ns.UUID, &credential.CredSpec{
			Name: "app-token", Type: credential.TypeVaultToken, Source: "vault-prod",
			Config: credential.NewConfig(map[string]string{"mint_method": "vault_token"}),
		}))

		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "vault-prod", nil))
		assert.Equal(t, []string{`the source needs input "jwt_role"`, `the source needs input "audience"`}, plan.Blockers,
			"validation, which would fail on the same inputs, waits for them")
	})

	t.Run("a keyless source", func(t *testing.T) {
		backend, ctx, c := setupTestSystemBackend(t)
		c.oidcIssuer = newReadyIssuer(t, "https://warden.example.com")
		require.NoError(t, c.credConfigStore.CreateSource(ctx, &credential.CredSource{
			Name: "aws-wif", Type: credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{"region": "us-east-1", "auth_method": "oidc_federation"}),
		}))
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "aws-wif", nil))
		assert.Contains(t, strings.Join(plan.Blockers, "\n"), "already stores no secret")
	})

	t.Run("not found", func(t *testing.T) {
		backend, ctx, _ := setupTestSystemBackend(t)
		resp := keylessPlanRequest(t, backend, ctx, "source", "missing", nil)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestPlanKeylessSource_IssuerWithPath(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.oidcIssuer = newReadyIssuer(t, "https://warden.example.com/oidc")
	createKeyedAWS(t, c, ctx)

	plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "source", "aws-prod", nil))
	assert.Contains(t, strings.Join(plan.Notes, "\n"), "https://warden.example.com/.well-known/openid-configuration")
}

func TestPlanKeylessSpec(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	require.NoError(t, c.credConfigStore.CreateSource(ctx, &credential.CredSource{
		Name: "gh", Type: credential.SourceTypeGitHub,
		Config: credential.NewConfig(map[string]string{}),
	}))
	require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
		Name: "gh-pat", Type: credential.TypeGitHubToken, Source: "gh",
		Config: credential.NewConfig(map[string]string{"mint_method": "pat", "token": "ghp_stored"}),
	}))
	require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
		Name: "static-key", Type: credential.TypeAPIKey, Source: builtinLocalSourceName,
		Config: credential.NewConfig(map[string]string{"api_key": "sk_stored"}),
	}))

	t.Run("needs secret_spec", func(t *testing.T) {
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "spec", "gh-pat", nil))
		require.Len(t, plan.Blockers, 1, "validation waits for the input: %v", plan.Blockers)
		assert.Contains(t, plan.Blockers[0], `needs input "secret_spec"`)
		require.Len(t, plan.Leftovers, 1)
		assert.Equal(t, "token", plan.Leftovers[0].Kind)
	})

	t.Run("chained", func(t *testing.T) {
		seedSource(t, c, ctx, &credential.CredSource{
			Name: "vault", Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://localhost:8200", "auth_method": "oidc_federation", "jwt_role": "agents",
			}),
		})
		ns, err := namespace.FromContext(ctx)
		require.NoError(t, err)
		require.NoError(t, c.credConfigStore.persistSpec(ns.UUID, &credential.CredSpec{
			Name: "gh-secret", Type: credential.TypeKeyValue, Source: "vault",
			Config: credential.NewConfig(map[string]string{
				"kv2_mount": "secret", "secret_path": "github/pat",
				"subject_token_source": "warden_identity", "assertion_audience": "vault",
			}),
		}))

		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "spec", "gh-pat", map[string]any{
			"new_name": "gh-chained",
			"target":   map[string]any{"secret_spec": "gh-secret"},
		}))
		require.Empty(t, plan.Blockers)
		require.Len(t, plan.Specs, 1)
		assert.Equal(t, "gh-chained", plan.Specs[0].Name)
		assert.Equal(t, "gh", plan.Specs[0].Source, "a spec plan keeps the source")
		assert.Equal(t, map[string]string{"mint_method": "pat", "secret_spec": "gh-secret"}, plan.Specs[0].Config)
	})

	t.Run("a secret input is refused", func(t *testing.T) {
		resp := keylessPlanRequest(t, backend, ctx, "spec", "gh-pat", map[string]any{
			"target": map[string]any{"token": "ghp_new"},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("specs is for a source plan", func(t *testing.T) {
		resp := keylessPlanRequest(t, backend, ctx, "spec", "gh-pat", map[string]any{
			"specs": map[string]any{"x": map[string]any{}},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("a spec on a keyed source", func(t *testing.T) {
		seedSource(t, c, ctx, &credential.CredSource{
			Name: "scw", Type: credential.SourceTypeScaleway,
			Config: credential.NewConfig(map[string]string{
				"management_access_key": "SCWOLD", "management_secret_key": "stored", "organization_id": "org",
			}),
		})
		ns, err := namespace.FromContext(ctx)
		require.NoError(t, err)
		require.NoError(t, c.credConfigStore.persistSpec(ns.UUID, &credential.CredSpec{
			Name: "scw-static", Type: credential.TypeScalewayKeys, Source: "scw",
			Config: credential.NewConfig(map[string]string{"access_key": "SCWSPEC", "secret_key": "spec-stored"}),
		}))
		in := map[string]any{"target": map[string]any{"secret_spec": "gh-secret"}}

		backend.core.keylessEnforcement = KeylessEnforcementWarn
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "spec", "scw-static", in))
		assert.Contains(t, strings.Join(plan.Notes, "\n"), `source "scw" still stores management_secret_key, so the create will warn`)
		assert.NotContains(t, strings.Join(plan.Blockers, "\n"), `source "scw" still stores`)

		backend.core.keylessEnforcement = KeylessEnforcementEnforce
		plan = planFromResponse(t, keylessPlanRequest(t, backend, ctx, "spec", "scw-static", in))
		assert.Contains(t, strings.Join(plan.Blockers, "\n"), `source "scw" still stores management_secret_key, so keyless_enforcement_level=enforce would refuse the create`)
	})

	t.Run("a local spec blocks", func(t *testing.T) {
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "spec", "static-key", nil))
		require.Len(t, plan.Blockers, 1)
		assert.Contains(t, plan.Blockers[0], "local source")
		assert.Contains(t, plan.Blockers[0], "for api_key, a source of type apikey)",
			"only the source that serves the key chained is named, not elastic or grafana, which mint it")
		assert.Empty(t, plan.Specs)
	})

	t.Run("a local cloudflare spec is pointed at the cloudflare source", func(t *testing.T) {
		require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
			Name: "cf-local", Type: credential.TypeCloudflareKeys, Source: builtinLocalSourceName,
			Config: credential.NewConfig(map[string]string{"api_token": "cf_stored"}),
		}))
		plan := planFromResponse(t, keylessPlanRequest(t, backend, ctx, "spec", "cf-local", nil))
		require.Len(t, plan.Blockers, 1)
		assert.Contains(t, plan.Blockers[0], "for cloudflare_keys, a source of type cloudflare)")

		// The R2 access key id is no secret, but a chained spec carries it no more
		// than the secret beside it, so an R2 spec is pointed there too.
		for name, cfg := range map[string]map[string]string{
			"cf-local-r2":   {"access_key_id": "ak", "secret_access_key": "sk"},
			"cf-local-both": {"api_token": "t", "access_key_id": "ak", "secret_access_key": "sk"},
		} {
			assert.Equal(t, []string{credential.SourceTypeCloudflare}, c.keylessSourceTypesFor(&credential.CredSpec{
				Name: name, Type: credential.TypeCloudflareKeys, Config: credential.NewConfig(cfg),
			}), name)
		}
	})

	t.Run("no home keeps the generic wording", func(t *testing.T) {
		assert.Empty(t, c.keylessSourceTypesFor(&credential.CredSpec{
			Type: credential.TypeAWSAccessKeys, Config: credential.NewConfig(map[string]string{"access_key_id": "a", "secret_access_key": "s"}),
		}), "an aws source serves aws_access_keys by federation, not by fetching a stored pair")
	})
}
