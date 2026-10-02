package drivers

import (
	"encoding/json"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keylessCase is a keyed source config and the inputs its keyless plan needs.
type keylessCase struct {
	keyed  map[string]string
	inputs map[string]string
}

const testSAKey = `{"type":"service_account","project_id":"proj","private_key_id":"kid-1","private_key":"-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n","client_email":"src@proj.iam.gserviceaccount.com"}`

// keylessCases covers every source type that can hold a secret.
var keylessCases = map[string]keylessCase{
	credential.SourceTypeAWS: {
		keyed:  map[string]string{"region": "us-east-1", "access_key_id": "AKIAOLD", "secret_access_key": "s", "assume_role_arn": "arn:aws:iam::111122223333:role/Src", "session_name": "warden"},
		inputs: map[string]string{},
	},
	credential.SourceTypeVault: {
		keyed:  map[string]string{"vault_address": "https://vault.example", "auth_method": "approle", "role_id": "r", "secret_id": "s", "secret_id_accessor": "acc", "approle_mount": "approle", "role_name": "warden"},
		inputs: map[string]string{"jwt_role": "warden-agents", "audience": "https://vault.example/warden"},
	},
	credential.SourceTypeAzure: {
		keyed:  map[string]string{"tenant_id": "00000000-0000-0000-0000-000000000000", "client_id": "11111111-1111-1111-1111-111111111111", "client_secret": "s", "secret_id": "22222222-2222-2222-2222-222222222222"},
		inputs: map[string]string{},
	},
	credential.SourceTypeGCP: {
		keyed:  map[string]string{"service_account_key": testSAKey},
		inputs: map[string]string{"workload_identity_provider": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/warden/providers/warden"},
	},
	credential.SourceTypeKubernetes: {
		keyed:  map[string]string{"kubernetes_url": "https://k8s.example", "token": "t"},
		inputs: map[string]string{"audience": "kubernetes"},
	},
	credential.SourceTypeAlicloud: {
		keyed:  map[string]string{"auth_method": "static", "access_key_id": "LTAIOLD", "access_key_secret": "s", "management_user_name": "warden"},
		inputs: map[string]string{"oidc_provider_arn": "acs:ram::1234567890123456:oidc-provider/warden", "audience": "sts.aliyuncs.com"},
	},
	credential.SourceTypeElastic: {
		keyed:  map[string]string{"elastic_url": "https://es.example", "api_key": "k", "api_key_id": "id"},
		inputs: map[string]string{credential.ConfigSecretSpec: "es-key"},
	},
	credential.SourceTypeGrafana: {
		keyed:  map[string]string{"grafana_url": "https://grafana.example", "admin_token": "t"},
		inputs: map[string]string{credential.ConfigSecretSpec: "grafana-token"},
	},
	credential.SourceTypeIBM: {
		keyed:  map[string]string{"api_key": "k", "account_id": "acct"},
		inputs: map[string]string{credential.ConfigSecretSpec: "ibm-key"},
	},
	credential.SourceTypeOVH: {
		keyed:  map[string]string{"client_id": "id", "client_secret": "s"},
		inputs: map[string]string{credential.ConfigSecretSpec: "ovh-client"},
	},
	credential.SourceTypeScaleway: {
		keyed:  map[string]string{"management_access_key": "SCWOLD", "management_secret_key": "s"},
		inputs: map[string]string{credential.ConfigSecretSpec: "scw-key"},
	},
	credential.SourceTypeGitLab: {
		keyed:  map[string]string{"gitlab_address": "https://gitlab.example", "auth_method": "pat", "personal_access_token": "glpat"},
		inputs: map[string]string{credential.ConfigSecretSpec: "gitlab-pat"},
	},
	credential.SourceTypeOAuth2: {
		keyed:  map[string]string{"token_url": "https://idp.example/token", "client_id": "id", "client_secret": "s"},
		inputs: map[string]string{credential.ConfigSecretSpec: "idp-client"},
	},
	credential.SourceTypeTokenExchange: {
		keyed:  map[string]string{"token_url": "https://idp.example/token", "client_id": "id", "client_secret": "s"},
		inputs: map[string]string{credential.ConfigSecretSpec: "idp-client"},
	},
}

// A source that can hold a secret must know how to stop holding it. These
// hold none of their own, so their sources have nothing to plan.
var noSourceSecret = map[string]bool{
	credential.SourceTypeLocal:      true,
	credential.SourceTypeAPIKey:     true,
	credential.SourceTypeGitHub:     true,
	credential.SourceTypeAnthropic:  true,
	credential.SourceTypeCloudflare: true,
	credential.SourceTypeOpenAI:     true,
}

func TestKeylessPlanners_Completeness(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := credential.NewDriverRegistry(log)
	require.NoError(t, RegisterBuiltinDrivers(registry))

	for _, sourceType := range registry.ListFactories() {
		factory, err := registry.GetFactory(sourceType)
		require.NoError(t, err)
		_, plans := factory.(credential.KeylessPlanner)
		if noSourceSecret[sourceType] {
			continue
		}
		assert.Truef(t, plans, "source type %q can hold a secret but has no keyless planner", sourceType)
		_, hasCase := keylessCases[sourceType]
		assert.Truef(t, hasCase, "source type %q needs a keylessCases entry", sourceType)
	}
}

// The planned delta, applied to a keyed config, must satisfy the driver's own
// keyless-mode validation and leave no stored secret. Pinning the delta to the
// real validator, not to a copied field list, is what keeps the two in step.
func TestKeylessPlanners_DeltaPassesTheDriversValidation(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := credential.NewDriverRegistry(log)
	require.NoError(t, RegisterBuiltinDrivers(registry))

	for sourceType, tc := range keylessCases {
		t.Run(sourceType, func(t *testing.T) {
			factory, err := registry.GetFactory(sourceType)
			require.NoError(t, err)
			planner := factory.(credential.KeylessPlanner)
			current := credential.NewConfig(tc.keyed)
			require.NotEmpty(t, factory.StoredSecrets(current), "precondition: the keyed config stores a secret")

			plan, err := planner.PlanKeyless(current, tc.inputs)
			require.NoError(t, err)
			assert.Empty(t, plan.NeedsInput, "all inputs were supplied")
			assert.NotEmpty(t, plan.Leftovers, "the plan names what stays live upstream")

			keyless := current.WithAll(plan.Delta)
			assert.NoError(t, factory.ValidateConfig(keyless))
			assert.Nil(t, factory.StoredSecrets(keyless))
		})
	}
}

// Missing inputs are reported, not guessed.
func TestKeylessPlanners_NeedsInput(t *testing.T) {
	for _, tc := range []struct {
		factory credential.KeylessPlanner
		current map[string]string
		want    []string
	}{
		{&VaultDriverFactory{}, map[string]string{"vault_address": "https://v"}, []string{"jwt_role", "audience"}},
		{&GCPDriverFactory{}, map[string]string{"service_account_key": testSAKey}, []string{"workload_identity_provider"}},
		{&AlicloudDriverFactory{}, map[string]string{"access_key_id": "a"}, []string{"oidc_provider_arn", "audience"}},
		{&ElasticDriverFactory{}, map[string]string{"api_key": "k"}, []string{credential.ConfigSecretSpec}},
	} {
		plan, err := tc.factory.PlanKeyless(credential.NewConfig(tc.current), nil)
		require.NoError(t, err)
		assert.Equal(t, tc.want, plan.NeedsInput)
	}
}

func TestKeylessSpecPlans(t *testing.T) {
	t.Run("aws blocks database tokens and needs role_arn for secret reads", func(t *testing.T) {
		f := &AWSDriverFactory{}
		p, err := f.PlanKeylessSpec(credential.TypeDBAuthToken, credential.NewConfig(map[string]string{"mint_method": "rds_iam_token"}), credential.Config{}, credential.Config{}, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, p.Blocker)

		p, err = f.PlanKeylessSpec(credential.TypeAPIKey, credential.NewConfig(map[string]string{"mint_method": "secrets_manager", "secret_id": "x"}), credential.Config{}, credential.Config{}, nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"role_arn"}, p.NeedsInput)

		p, err = f.PlanKeylessSpec(credential.TypeAWSAccessKeys, credential.NewConfig(map[string]string{"mint_method": "sts_assume_role", "role_arn": "arn:aws:iam::1:role/R", "external_id": "e"}), credential.Config{}, credential.Config{}, nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
			credential.ConfigAssertionProfile:   "aws",
			"external_id":                       "",
		}, p.Delta)
	})

	t.Run("hvault vault_token drops token_role", func(t *testing.T) {
		p, err := (&VaultDriverFactory{}).PlanKeylessSpec(credential.TypeVaultToken, credential.NewConfig(map[string]string{"mint_method": "vault_token", "token_role": "reader"}), credential.Config{}, credential.Config{}, nil)
		require.NoError(t, err)
		assert.Equal(t, "", p.Delta["token_role"])
		assert.Equal(t, credential.SourceWardenIdentity, p.Delta[credential.ConfigSubjectTokenSource])
	})

	t.Run("gcp keeps the service account identity by default", func(t *testing.T) {
		current := credential.NewConfig(map[string]string{"service_account_key": testSAKey})
		spec := credential.NewConfig(map[string]string{"mint_method": "access_token", "scopes": "cloud-platform"})

		p, err := (&GCPDriverFactory{}).PlanKeylessSpec(credential.TypeGCPAccessToken, spec, current, credential.Config{}, nil)
		require.NoError(t, err)
		assert.Equal(t, "impersonated_access_token", p.Delta["mint_method"])
		assert.Equal(t, "src@proj.iam.gserviceaccount.com", p.Delta["target_service_account"])
		assert.Equal(t, []string{gcpChoiceKeepIdentity, gcpChoiceFederatedPrincipal}, p.Choices)

		p, err = (&GCPDriverFactory{}).PlanKeylessSpec(credential.TypeGCPAccessToken, spec, current, credential.Config{}, map[string]string{choiceInput: gcpChoiceFederatedPrincipal})
		require.NoError(t, err)
		assert.NotContains(t, p.Delta, "mint_method")
		assert.NotContains(t, p.Delta, choiceInput, "the choice selector is not a config key")

		_, err = (&GCPDriverFactory{}).PlanKeylessSpec(credential.TypeGCPAccessToken, spec, current, credential.Config{}, map[string]string{choiceInput: "bogus"})
		assert.Error(t, err)
	})

	t.Run("oauth2 blocks authorization_code", func(t *testing.T) {
		p, err := (&OAuth2DriverFactory{}).PlanKeylessSpec(credential.TypeOAuthBearerToken, credential.NewConfig(map[string]string{"auth_method": "authorization_code"}), credential.Config{}, credential.Config{}, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, p.Blocker)
	})

	t.Run("oauth2 reports a spec's own client secret", func(t *testing.T) {
		p, err := (&OAuth2DriverFactory{}).PlanKeylessSpec(credential.TypeOAuthBearerToken, credential.NewConfig(map[string]string{
			"client_id": "app-1", "client_secret": "cs",
		}), credential.Config{}, credential.Config{}, nil)
		require.NoError(t, err)
		require.Len(t, p.Leftovers, 1)
		assert.Equal(t, "app-1", p.Leftovers[0].ID)
	})

	t.Run("an agent_identity input is kept", func(t *testing.T) {
		p, err := (&KubernetesDriverFactory{}).PlanKeylessSpec(credential.TypeKubernetesToken, credential.NewConfig(nil), credential.Config{}, credential.Config{},
			map[string]string{credential.ConfigSubjectTokenSource: credential.SourceAgentIdentity})
		require.NoError(t, err)
		assert.Equal(t, credential.SourceAgentIdentity, p.Delta[credential.ConfigSubjectTokenSource])
	})
}

// A leftover names a credential without revealing any value a read masks: a
// plan shows nothing a read would not.
func TestKeylessLeftovers_RevealNothingMasked(t *testing.T) {
	const sentinel = "MASKED-SENTINEL-VALUE"
	var leftovers []credential.Leftover

	vault := credential.NewConfig(map[string]string{
		"vault_address": "https://v", "auth_method": "approle", "role_id": "r",
		"secret_id": sentinel, "secret_id_accessor": sentinel, "role_name": "warden",
	})
	sp, err := (&VaultDriverFactory{}).PlanKeyless(vault, nil)
	require.NoError(t, err)
	leftovers = append(leftovers, sp.Leftovers...)

	azureSpec := credential.NewConfig(map[string]string{
		"tenant_id": "t", "client_id": "app", "client_secret": sentinel, "secret_id": sentinel,
	})
	p, err := (&AzureDriverFactory{}).PlanKeylessSpec(credential.TypeAzureBearerToken, azureSpec, credential.Config{}, credential.Config{}, nil)
	require.NoError(t, err)
	require.NotEmpty(t, p.Leftovers, "the spec's client secret is reported")
	leftovers = append(leftovers, p.Leftovers...)

	for _, l := range leftovers {
		assert.NotContains(t, l.ID+" "+l.WhereToDelete, sentinel, "%+v", l)
	}
}

var testTrustEnv = credential.TrustEnv{
	IssuerURL:      "https://warden.example.com",
	JWKSURL:        "https://warden.example.com/oidc/jwks",
	SubjectPrefix:  "wid:root:",
	NamespaceClaim: "root",
}

// The rendered JSON bodies parse, and carry the issuer, the audience and the
// namespace's subject pattern where each provider expects them.
func TestKeylessPrerequisites_Shapes(t *testing.T) {
	t.Run("aws trust policy", func(t *testing.T) {
		keyless := credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"})
		specs := []credential.PlannedSpec{{Name: "deploy", Config: credential.NewConfig(map[string]string{
			"role_arn": "arn:aws:iam::111122223333:role/Deploy", "subject_token_source": "warden_identity", "assertion_profile": "aws",
		})}}
		prereqs := (&AWSDriverFactory{}).KeylessPrerequisites(keyless, specs, testTrustEnv)
		require.GreaterOrEqual(t, len(prereqs), 2)
		assert.Contains(t, prereqs[0].Body, "--client-id-list sts.amazonaws.com")

		var policy struct {
			Statement []struct {
				Principal map[string]string
				Action    []string
				Condition map[string]map[string]string
			}
		}
		require.NoError(t, json.Unmarshal([]byte(prereqs[1].Body), &policy))
		st := policy.Statement[0]
		assert.Equal(t, "arn:aws:iam::111122223333:oidc-provider/warden.example.com", st.Principal["Federated"])
		assert.ElementsMatch(t, []string{"sts:AssumeRoleWithWebIdentity", "sts:TagSession"}, st.Action)
		assert.Equal(t, "sts.amazonaws.com", st.Condition["StringEquals"]["warden.example.com:aud"])
		assert.Equal(t, "wid:root:*", st.Condition["StringLike"]["warden.example.com:sub"])
	})

	t.Run("azure federated credential", func(t *testing.T) {
		keyless := credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "client_id": "app-1"})
		prereqs := (&AzureDriverFactory{}).KeylessPrerequisites(keyless, nil, testTrustEnv)
		body := prereqs[0].Body[:len(prereqs[0].Body)-len("\n\n# az ad app federated-credential create --id app-1 --parameters credential.json")]
		var fic map[string]any
		require.NoError(t, json.Unmarshal([]byte(body), &fic))
		assert.Equal(t, "https://warden.example.com", fic["issuer"])
		assert.Equal(t, []any{"api://AzureADTokenExchange"}, fic["audiences"])
		assert.Contains(t, prereqs[len(prereqs)-1].Body, "20 federated credentials")
	})

	t.Run("vault role", func(t *testing.T) {
		keyless := credential.NewConfig(map[string]string{"jwt_role": "warden-agents", "audience": "https://vault.example/warden"})
		prereqs := (&VaultDriverFactory{}).KeylessPrerequisites(keyless, nil, testTrustEnv)
		assert.Contains(t, prereqs[0].Body, `jwks_url="https://warden.example.com/oidc/jwks"`)
		assert.Contains(t, prereqs[0].Body, `bound_issuer="https://warden.example.com"`)
		assert.Contains(t, prereqs[0].Body, `"bound_claims_type": "glob"`)
		assert.Contains(t, prereqs[0].Body, `"sub": "wid:root:*"`)
		assert.Contains(t, prereqs[0].Body, `"<the policies the AppRole role granted>"`, "placeholders are not HTML-escaped")
	})

	t.Run("gcp provider and grant", func(t *testing.T) {
		keyless := credential.NewConfig(map[string]string{"workload_identity_provider": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov"})
		specs := []credential.PlannedSpec{{Name: "t", Config: credential.NewConfig(map[string]string{"target_service_account": "sa@p.iam.gserviceaccount.com", "subject_token_source": "warden_identity"})}}
		prereqs := (&GCPDriverFactory{}).KeylessPrerequisites(keyless, specs, testTrustEnv)
		assert.Contains(t, prereqs[0].Body, "create-oidc prov")
		assert.Contains(t, prereqs[0].Body, "--workload-identity-pool=pool")
		assert.Contains(t, prereqs[1].Body, "workloadIdentityPools/pool/*")
		assert.Contains(t, prereqs[len(prereqs)-1].Body, "127 bytes")
	})

	t.Run("alicloud trust policy", func(t *testing.T) {
		keyless := credential.NewConfig(map[string]string{"oidc_provider_arn": "acs:ram::1:oidc-provider/warden", "audience": "sts.aliyuncs.com"})
		specs := []credential.PlannedSpec{{Name: "r", Config: credential.NewConfig(map[string]string{"role_arn": "acs:ram::1:role/r", "subject_token_source": "warden_identity"})}}
		prereqs := (&AlicloudDriverFactory{}).KeylessPrerequisites(keyless, specs, testTrustEnv)
		require.Len(t, prereqs, 2)
		var policy map[string]any
		require.NoError(t, json.Unmarshal([]byte(prereqs[1].Body), &policy))
		assert.Contains(t, prereqs[1].Body, `"oidc:sub"`)
	})

	// A spec that discloses a user mints delegation tokens whose sub is the user's
	// raw id, so each verifier that can bind claims is told to bind warden_namespace
	// beside it. A spec on another profile, or filling the actor slot, is not listed.
	t.Run("delegation specs are told to bind warden_namespace", func(t *testing.T) {
		specs := []credential.PlannedSpec{
			{Name: "as-user", Config: credential.NewConfig(map[string]string{"subject_token_source": "warden_identity", "assertion_user_claims": "sub"})},
			{Name: "as-user-minimal", Config: credential.NewConfig(map[string]string{"subject_token_source": "warden_identity", "assertion_user_claims": "sub", "assertion_profile": "minimal"})},
			{Name: "actor-slot", Config: credential.NewConfig(map[string]string{"subject_token_source": "user_identity", "actor_token_source": "warden_identity", "assertion_user_claims": "sub"})},
			{Name: "agent-only", Config: credential.NewConfig(map[string]string{"subject_token_source": "warden_identity"})},
		}
		for name, prereqs := range map[string][]credential.Prerequisite{
			"vault":      (&VaultDriverFactory{}).KeylessPrerequisites(credential.NewConfig(map[string]string{"audience": "a"}), specs, testTrustEnv),
			"gcp":        (&GCPDriverFactory{}).KeylessPrerequisites(credential.NewConfig(map[string]string{}), specs, testTrustEnv),
			"kubernetes": (&KubernetesDriverFactory{}).KeylessPrerequisites(credential.NewConfig(map[string]string{"audience": "k"}), specs, testTrustEnv),
		} {
			note := prereqs[len(prereqs)-1]
			assert.Equal(t, "as-user", note.Where, name)
			assert.Contains(t, note.Body, `warden_namespace = "root"`, name)
		}

		none := (&VaultDriverFactory{}).KeylessPrerequisites(credential.NewConfig(map[string]string{"audience": "a"}), specs[1:], testTrustEnv)
		for _, p := range none {
			assert.NotEqual(t, "Delegation specs", p.Title)
		}
	})

	t.Run("agent_identity specs are pointed at their own issuer", func(t *testing.T) {
		specs := []credential.PlannedSpec{{Name: "fwd", Config: credential.NewConfig(map[string]string{"subject_token_source": "agent_identity"})}}
		prereqs := (&KubernetesDriverFactory{}).KeylessPrerequisites(credential.NewConfig(map[string]string{"audience": "k"}), specs, testTrustEnv)
		assert.Equal(t, "fwd", prereqs[len(prereqs)-1].Where)
	})
}

// A public-client token_exchange source is already keyless. Its plan changes
// nothing: it must not clear the client_id the authorization server may know it by,
// ask for a secret_spec the source would refuse, or name a client secret that does
// not exist.
func TestKeylessPlan_TokenExchangePublicClient(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	current := credential.NewConfig(map[string]string{
		"token_url": "https://as.example/token", "client_auth": clientAuthNone, "client_id": "warden",
	})

	plan, err := f.PlanKeyless(current, map[string]string{})
	require.NoError(t, err)
	assert.Empty(t, plan.Delta)
	assert.Empty(t, plan.NeedsInput)
	assert.Empty(t, plan.Leftovers)
	require.Len(t, plan.Notes, 1)
	assert.Contains(t, plan.Notes[0], "already keyless")
	require.NoError(t, f.ValidateConfig(current.WithAll(plan.Delta)), "the unchanged config still validates")

	assert.Empty(t, f.KeylessPrerequisites(current, nil, testTrustEnv))
}
