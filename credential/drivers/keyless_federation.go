package drivers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/stephnangue/warden/credential"
)

// Federation planners: the source stops holding a key and presents the
// caller's identity assertion instead. The rendered prerequisites follow the
// providers' documented trust formats; TestKeylessPrerequisites_Shapes pins
// each one.

// federatedSpecDelta starts every federated spec rewrite: a spec that does not
// already exchange an identity learns to present the caller's Warden identity,
// or the source the operator names.
func federatedSpecDelta(spec credential.Config, inputs map[string]string) map[string]string {
	delta := map[string]string{}
	if !credential.SpecRequestsExchange(spec) {
		src := inputs[credential.ConfigSubjectTokenSource]
		if src == "" {
			src = credential.SourceWardenIdentity
		}
		delta[credential.ConfigSubjectTokenSource] = src
	}
	return delta
}

// usesWardenIdentity reports whether a keyless spec presents Warden's own
// assertion, which is what the rendered trust applies to. A spec forwarding the
// agent's own token is trusted against that token's issuer, unknown here.
func usesWardenIdentity(spec credential.Config) bool {
	return spec.Get(credential.ConfigSubjectTokenSource) == credential.SourceWardenIdentity
}

// agentIdentityNote is rendered when some specs forward the agent's own token.
func agentIdentityNote(specs []credential.PlannedSpec) []credential.Prerequisite {
	var names []string
	for _, s := range specs {
		if s.Config.Get(credential.ConfigSubjectTokenSource) == credential.SourceAgentIdentity {
			names = append(names, s.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return []credential.Prerequisite{{
		Title:  "Agent identity specs",
		Where:  strings.Join(names, ", "),
		Format: "text",
		Body: "These specs forward the agent's own token, so the upstream must trust the issuer of that token " +
			"(your agents' identity provider), not Warden. Configure that trust as above with that issuer's URL and subjects.",
	}}
}

// delegationNote is rendered when some specs mint delegation tokens: a
// warden_identity subject on the default profile with assertion_user_claims set.
// Their sub is the user's raw id — not tenant-qualified like the agent's composite —
// so the verifier must bind warden_namespace beside it; bind says how, for this
// verifier.
func delegationNote(specs []credential.PlannedSpec, env credential.TrustEnv, bind string) []credential.Prerequisite {
	var names []string
	for _, s := range specs {
		if usesWardenIdentity(s.Config) &&
			credential.AssertionProfileName(s.Config) == credential.DefaultAssertionProfileName &&
			len(credential.AssertionUserClaimKeys(s.Config)) > 0 {
			names = append(names, s.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return []credential.Prerequisite{{
		Title:  "Delegation specs",
		Where:  strings.Join(names, ", "),
		Format: "text",
		Body: "These specs set assertion_user_claims, so their assertions are RFC 8693 delegation tokens: sub is the user's own id " +
			"and act.sub the agent's " + env.SubjectPrefix + "<mount_accessor>:<principal_id>. A user id is not tenant-qualified, " +
			"so bind warden_namespace = \"" + env.NamespaceClaim + "\" together with it: " + bind,
	}}
}

// subjectPattern is the subject every agent of the namespace presents, up to
// the mount and principal: "wid:<namespace>:*".
func subjectPattern(env credential.TrustEnv) string {
	return env.SubjectPrefix + "*"
}

func prettyJSON(v any) string {
	// Not HTML-escaped: a body is pasted into a terminal or console, where a
	// "<placeholder>" shown as <placeholder> reads as corrupted.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Sprintf("%v", v)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// ============================================================================
// AWS
// ============================================================================

func (f *AWSDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	delta := map[string]string{"auth_method": awsAuthMethodOIDCFederation}
	clearPresent(delta, current, "access_key_id", "secret_access_key", "assume_role_arn",
		"session_name", "session_duration", "external_id", "activation_delay")
	withInputs(delta, inputs)

	plan := &credential.KeylessSourcePlan{
		Delta: delta,
		Notes: []string{"sessions already issued with the stored key stay valid until they expire"},
	}
	if id := current.Get("access_key_id"); id != "" {
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind: "IAM access key", ID: id,
			WhereToDelete: "aws iam delete-access-key --access-key-id " + id + " (on the IAM user that owns it)",
		})
	}
	return plan, nil
}

func (f *AWSDriverFactory) PlanKeylessSpec(_ string, spec, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	switch mm := spec.Get("mint_method"); mm {
	case "rds_iam_token", "redshift_iam_token":
		return &credential.KeylessSpecPlan{Blocker: mm + " has no federated form on an aws source; move the spec to a separate source that keeps its key, or delete it"}, nil
	}

	delta := federatedSpecDelta(spec, inputs)
	clearPresent(delta, spec, "external_id")
	plan := &credential.KeylessSpecPlan{}
	if spec.Get("mint_method") == "sts_assume_role" && spec.Get(credential.ConfigAssertionProfile) == "" {
		delta[credential.ConfigAssertionProfile] = "aws"
		plan.Behaviour = "sessions carry the agent's identity as session tags (assertion_profile=aws), which the trust policy must allow with sts:TagSession"
	}
	if (spec.Get("mint_method") == "secrets_manager" || spec.Get("mint_method") == "secret_read") &&
		inputOr(inputs, spec, "role_arn") == "" {
		plan.NeedsInput = append(plan.NeedsInput, "role_arn")
	}
	plan.Delta = withInputs(delta, inputs)
	return plan, nil
}

func (f *AWSDriverFactory) KeylessPrerequisites(keyless credential.Config, specs []credential.PlannedSpec, env credential.TrustEnv) []credential.Prerequisite {
	aud, _ := awsAssertionAudience(keyless)
	host := strings.TrimPrefix(env.IssuerURL, "https://")
	prereqs := []credential.Prerequisite{{
		Title:  "IAM OIDC identity provider",
		Where:  "the AWS account of each role below",
		Format: "shell",
		Body:   fmt.Sprintf("aws iam create-open-id-connect-provider \\\n  --url %s \\\n  --client-id-list %s", env.IssuerURL, aud),
	}}

	// One trust policy per role, allowing TagSession if any spec on it tags.
	type roleTrust struct{ tags bool }
	roles := map[string]*roleTrust{}
	for _, s := range specs {
		arn := s.Config.Get("role_arn")
		if arn == "" || !usesWardenIdentity(s.Config) {
			continue
		}
		if roles[arn] == nil {
			roles[arn] = &roleTrust{}
		}
		if s.Config.Get(credential.ConfigAssertionProfile) == "aws" {
			roles[arn].tags = true
		}
	}
	for _, arn := range slices.Sorted(func(yield func(string) bool) {
		for k := range roles {
			if !yield(k) {
				return
			}
		}
	}) {
		account := awsAccountOf(arn)
		actions := []string{"sts:AssumeRoleWithWebIdentity"}
		if roles[arn].tags {
			actions = append(actions, "sts:TagSession")
		}
		policy := map[string]any{
			"Version": "2012-10-17",
			"Statement": []any{map[string]any{
				"Effect":    "Allow",
				"Principal": map[string]any{"Federated": fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", account, host)},
				"Action":    actions,
				"Condition": map[string]any{
					"StringEquals": map[string]any{host + ":aud": aud},
					"StringLike":   map[string]any{host + ":sub": subjectPattern(env)},
				},
			}},
		}
		prereqs = append(prereqs, credential.Prerequisite{
			Title: "Trust policy", Where: "IAM role " + arn, Format: "json", Body: prettyJSON(policy),
		})
	}

	prereqs = append(prereqs, credential.Prerequisite{
		Title:  "Notes",
		Where:  "every role that trusts this provider",
		Format: "text",
		Body: "The subject pattern trusts every agent of the namespace. Narrow it to one auth mount with " +
			env.SubjectPrefix + "<mount_accessor>:*, or add a condition on aws:RequestTag/warden_role.\n" +
			"When any token carries session tags, every role trusting this provider must allow sts:TagSession, " +
			"or AssumeRoleWithWebIdentity fails for it.",
	})
	return append(prereqs, agentIdentityNote(specs)...)
}

// awsAccountOf returns the account id in an IAM ARN, or a placeholder.
func awsAccountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 4 && parts[4] != "" {
		return parts[4]
	}
	return "<account-id>"
}

// ============================================================================
// Vault / OpenBao (hvault)
// ============================================================================

func (f *VaultDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	delta := map[string]string{"auth_method": vaultAuthMethodOIDCFederation}
	clearPresent(delta, current, "role_id", "secret_id", "secret_id_accessor", "approle_mount", "role_name", "token")
	withInputs(delta, inputs)

	plan := &credential.KeylessSourcePlan{
		Delta: delta,
		Notes: []string{
			"every request logs in at the JWT role, whose token_policies now decide what minted credentials can do",
			"federated mints are not leases: tokens and dynamic secrets can no longer be revoked early and expire at their TTL",
		},
	}
	if inputOr(inputs, current, "jwt_role") == "" {
		plan.NeedsInput = append(plan.NeedsInput, "jwt_role")
	}
	if inputOr(inputs, current, "audience") == "" {
		plan.NeedsInput = append(plan.NeedsInput, "audience")
	}

	mount := credential.GetString(current, "approle_mount", "approle")
	role := credential.GetString(current, "role_name", "<role>")
	// The accessor is named by where to find it, not by value: a read masks it,
	// and a plan shows nothing a read would not.
	switch {
	case current.Get("secret_id_accessor") != "":
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind: "AppRole secret_id", ID: "its accessor is stored on the source",
			WhereToDelete: fmt.Sprintf("list the accessors with vault list auth/%s/role/%s/secret-id, then "+
				"vault write auth/%s/role/%s/secret-id-accessor/destroy secret_id_accessor=<accessor>", mount, role, mount, role),
		})
	case current.Get("secret_id") != "":
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind: "AppRole secret_id", ID: "stored on the source, no accessor recorded",
			WhereToDelete: fmt.Sprintf("vault write auth/%s/role/%s/secret-id/destroy secret_id=<the secret_id>", mount, role),
		})
	case current.Get("auth_method") == "":
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind: "Vault token", ID: "from the server environment",
			WhereToDelete: "revoke it in Vault and remove it from the server's environment",
		})
	}
	return plan, nil
}

func (f *VaultDriverFactory) PlanKeylessSpec(specType string, spec, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	delta := federatedSpecDelta(spec, inputs)
	plan := &credential.KeylessSpecPlan{}
	if specType == credential.TypeVaultToken {
		if role := spec.Get("token_role"); role != "" {
			delta["token_role"] = ""
			plan.Behaviour = fmt.Sprintf("the minted token is the JWT login token, with the JWT role's policies instead of token role %q's, and it can no longer be revoked early", role)
		}
	}
	plan.Delta = withInputs(delta, inputs)
	return plan, nil
}

func (f *VaultDriverFactory) KeylessPrerequisites(keyless credential.Config, specs []credential.PlannedSpec, env credential.TrustEnv) []credential.Prerequisite {
	mount := credential.GetString(keyless, "jwt_mount", "jwt")
	role := credential.GetString(keyless, "jwt_role", "<jwt_role>")
	aud := credential.GetString(keyless, "audience", "<audience>")

	roleBody := prettyJSON(map[string]any{
		"role_type":         "jwt",
		"user_claim":        "sub",
		"bound_audiences":   []string{aud},
		"bound_claims_type": "glob",
		"bound_claims":      map[string]string{"sub": subjectPattern(env)},
		"token_policies":    []string{"<the policies the AppRole role granted>"},
	})
	return append([]credential.Prerequisite{{
		Title:  "JWT auth method and role",
		Where:  "Vault",
		Format: "shell",
		// jwks_url rather than oidc_discovery_url: the key set is always at the
		// origin root, while discovery is only found under an issuer URL with
		// no path.
		Body: fmt.Sprintf("vault auth enable -path=%s jwt   # if not already enabled\n"+
			"vault write auth/%s/config \\\n  jwks_url=%q \\\n  bound_issuer=%q\n"+
			"vault write auth/%s/role/%s - <<'EOF'\n%s\nEOF",
			mount, mount, env.JWKSURL, env.IssuerURL, mount, role, roleBody),
	}}, append(agentIdentityNote(specs), delegationNote(specs, env,
		"give them their own JWT role (jwt_role on the spec) with user_claim \"sub\" and "+
			"bound_claims {\"warden_namespace\": \""+env.NamespaceClaim+"\"}, since their sub no longer matches the agents' pattern.")...)...)
}

// ============================================================================
// Azure
// ============================================================================

func (f *AzureDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	delta := map[string]string{"auth_method": azureAuthMethodOIDCFederation}
	clearPresent(delta, current, "client_secret", "secret_id")
	withInputs(delta, inputs)

	plan := &credential.KeylessSourcePlan{Delta: delta}
	if id := current.Get("secret_id"); id != "" {
		app := current.Get("client_id")
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind: "client secret", ID: id,
			WhereToDelete: fmt.Sprintf("az ad app credential delete --id %s --key-id %s", app, id),
		})
	}
	return plan, nil
}

func (f *AzureDriverFactory) PlanKeylessSpec(specType string, spec, current, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	delta := federatedSpecDelta(spec, inputs)
	plan := &credential.KeylessSpecPlan{}

	switch {
	case specType == credential.TypeAzureBearerToken:
		clearPresent(delta, spec, "client_secret", "secret_id")
		if spec.Get("tenant_id") == "" && current.Get("tenant_id") != "" {
			delta["tenant_id"] = current.Get("tenant_id")
		}
		if spec.Get(credential.ConfigAssertionProfile) == "" {
			delta[credential.ConfigAssertionProfile] = "minimal"
		}
		// A spec read masks secret_id (a source read does not), so the spec's
		// is named by where to find it rather than by value.
		if spec.Get("client_secret") != "" {
			app := credential.GetString(spec, "client_id", "<client_id>")
			plan.Leftovers = append(plan.Leftovers, credential.Leftover{
				Kind: "client secret", ID: "stored on the spec, of app " + app,
				WhereToDelete: fmt.Sprintf("find its key id with az ad app credential list --id %s, then "+
					"az ad app credential delete --id %s --key-id <key id>", app, app),
			})
		}
	case spec.Get("mint_method") == "secret_read":
		if inputOr(inputs, spec, "client_id") == "" {
			plan.NeedsInput = append(plan.NeedsInput, "client_id")
		}
		if spec.Get("tenant_id") == "" && current.Get("tenant_id") != "" {
			delta["tenant_id"] = current.Get("tenant_id")
		}
	}
	plan.Delta = withInputs(delta, inputs)
	return plan, nil
}

func (f *AzureDriverFactory) KeylessPrerequisites(keyless credential.Config, specs []credential.PlannedSpec, env credential.TrustEnv) []credential.Prerequisite {
	aud, _ := azureAssertionAudience(keyless)

	apps := map[string]bool{}
	if id := keyless.Get("client_id"); id != "" {
		apps[id] = true
	}
	for _, s := range specs {
		if id := s.Config.Get("client_id"); id != "" && usesWardenIdentity(s.Config) {
			apps[id] = true
		}
	}

	var prereqs []credential.Prerequisite
	for _, app := range slices.Sorted(func(yield func(string) bool) {
		for k := range apps {
			if !yield(k) {
				return
			}
		}
	}) {
		body := prettyJSON(map[string]any{
			"name":      "warden-<agent>",
			"issuer":    env.IssuerURL,
			"subject":   env.SubjectPrefix + "<mount_accessor>:<principal_id>",
			"audiences": []string{aud},
		})
		prereqs = append(prereqs, credential.Prerequisite{
			Title:  "Federated identity credential (one per agent)",
			Where:  "app registration " + app,
			Format: "json",
			Body:   body + "\n\n# az ad app federated-credential create --id " + app + " --parameters credential.json",
		})
	}
	prereqs = append(prereqs, credential.Prerequisite{
		Title:  "Notes",
		Where:  "Entra ID",
		Format: "text",
		Body: "Entra matches the subject exactly and supports no wildcard for a custom issuer, and an app holds at most " +
			"20 federated credentials. Warden's subject is per agent, so each agent needs its own credential: " +
			"spread agents across apps beyond 20.",
	})
	return append(prereqs, agentIdentityNote(specs)...)
}

// ============================================================================
// GCP
// ============================================================================

const (
	gcpChoiceKeepIdentity       = "keep-identity"
	gcpChoiceFederatedPrincipal = "federated-principal"
)

func (f *GCPDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	delta := map[string]string{"auth_method": gcpAuthMethodOIDCFederation}
	clearPresent(delta, current, "service_account_key")
	withInputs(delta, inputs)

	plan := &credential.KeylessSourcePlan{Delta: delta}
	if inputOr(inputs, current, "workload_identity_provider") == "" {
		plan.NeedsInput = append(plan.NeedsInput, "workload_identity_provider")
	}
	if key, err := parseServiceAccountKeyJSON([]byte(current.Get("service_account_key"))); err == nil {
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind: "service account key", ID: key.PrivateKeyID,
			WhereToDelete: fmt.Sprintf("gcloud iam service-accounts keys delete %s --iam-account=%s", key.PrivateKeyID, key.ClientEmail),
		})
	}
	return plan, nil
}

// PlanKeylessSpec offers two ways to move an access_token spec. A federated
// access token acts as the pool principal, not the service account the key
// belonged to; impersonating that account keeps what the token can reach.
func (f *GCPDriverFactory) PlanKeylessSpec(specType string, spec, current, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	delta := federatedSpecDelta(spec, inputs)
	plan := &credential.KeylessSpecPlan{}

	if specType == credential.TypeGCPAccessToken && spec.Get("mint_method") == "access_token" {
		plan.Choices = []string{gcpChoiceKeepIdentity, gcpChoiceFederatedPrincipal}
		switch choice := inputs[choiceInput]; choice {
		case "", gcpChoiceKeepIdentity:
			email := ""
			if key, err := parseServiceAccountKeyJSON([]byte(current.Get("service_account_key"))); err == nil {
				email = key.ClientEmail
			}
			if email == "" && inputs["target_service_account"] == "" {
				plan.NeedsInput = append(plan.NeedsInput, "target_service_account")
			}
			delta["mint_method"] = "impersonated_access_token"
			if email != "" {
				delta["target_service_account"] = email
			}
			plan.Behaviour = "tokens impersonate the service account the key belonged to, so they reach what they reached before"
		case gcpChoiceFederatedPrincipal:
			plan.Behaviour = "tokens act as the workload identity pool principal, not the service account the key belonged to; grant it the roles it needs"
		default:
			return nil, fmt.Errorf("unknown choice %q; pick %s or %s", choice, gcpChoiceKeepIdentity, gcpChoiceFederatedPrincipal)
		}
	}
	plan.Delta = withInputs(delta, inputs)
	return plan, nil
}

func (f *GCPDriverFactory) KeylessPrerequisites(keyless credential.Config, specs []credential.PlannedSpec, env credential.TrustEnv) []credential.Prerequisite {
	provider := keyless.Get("workload_identity_provider")
	project, pool, prov := parseWIFProvider(provider)

	prereqs := []credential.Prerequisite{{
		Title:  "Workload identity pool provider",
		Where:  "GCP project " + project,
		Format: "shell",
		Body: fmt.Sprintf("gcloud iam workload-identity-pools providers create-oidc %s \\\n"+
			"  --project=%s --location=global --workload-identity-pool=%s \\\n"+
			"  --issuer-uri=%q \\\n"+
			"  --attribute-mapping=\"google.subject=assertion.sub,attribute.warden_role=assertion.warden_role\" \\\n"+
			"  --attribute-condition=\"assertion.sub.startsWith('%s')\"",
			prov, project, pool, env.IssuerURL, env.SubjectPrefix),
	}}

	accounts := map[string]bool{}
	for _, s := range specs {
		if sa := s.Config.Get("target_service_account"); sa != "" && usesWardenIdentity(s.Config) {
			accounts[sa] = true
		}
	}
	for _, sa := range slices.Sorted(func(yield func(string) bool) {
		for k := range accounts {
			if !yield(k) {
				return
			}
		}
	}) {
		prereqs = append(prereqs, credential.Prerequisite{
			Title:  "Impersonation grant",
			Where:  "service account " + sa,
			Format: "shell",
			Body: fmt.Sprintf("gcloud iam service-accounts add-iam-policy-binding %s \\\n"+
				"  --role=roles/iam.workloadIdentityUser \\\n"+
				"  --member=\"principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/*\"",
				sa, project, pool),
		})
	}
	prereqs = append(prereqs, credential.Prerequisite{
		Title:  "Notes",
		Where:  "the pool provider",
		Format: "text",
		Body: "google.subject may not exceed 127 bytes, and the token exchange fails for a longer one. Warden's subject " +
			"is " + env.SubjectPrefix + "<mount_accessor>:<principal_id>; keep principal ids short enough.\n" +
			"With no --allowed-audiences the provider accepts its own resource name, which is the audience Warden derives.\n" +
			"attribute.warden_role maps a claim the minimal assertion profile does not carry; drop that mapping for specs using it.",
	})
	prereqs = append(prereqs, agentIdentityNote(specs)...)
	return append(prereqs, delegationNote(specs, env,
		"widen the attribute condition to \"assertion.sub.startsWith('"+env.SubjectPrefix+"') || "+
			"assertion.warden_namespace == '"+env.NamespaceClaim+"'\" and map attribute.warden_namespace=assertion.warden_namespace.")...)
}

// parseWIFProvider splits
// //iam.googleapis.com/projects/NUM/locations/global/workloadIdentityPools/POOL/providers/PROV.
func parseWIFProvider(p string) (project, pool, provider string) {
	project, pool, provider = "<project-number>", "<pool>", "<provider>"
	parts := strings.Split(strings.TrimPrefix(p, "//iam.googleapis.com/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		switch parts[i] {
		case "projects":
			project = parts[i+1]
		case "workloadIdentityPools":
			pool = parts[i+1]
		case "providers":
			provider = parts[i+1]
		}
	}
	return project, pool, provider
}

// ============================================================================
// Kubernetes
// ============================================================================

func (f *KubernetesDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	delta := map[string]string{"auth_method": kubernetesAuthMethodOIDCFederation}
	clearPresent(delta, current, "token", "source_service_account", "source_namespace", "source_token_ttl")
	withInputs(delta, inputs)

	plan := &credential.KeylessSourcePlan{Delta: delta}
	if inputOr(inputs, current, "audience") == "" {
		plan.NeedsInput = append(plan.NeedsInput, "audience")
	}
	id := "stored on the source"
	if sa := current.Get("source_service_account"); sa != "" {
		id = "service account " + credential.GetString(current, "source_namespace", "default") + "/" + sa
	}
	plan.Leftovers = append(plan.Leftovers, credential.Leftover{
		Kind: "service account token", ID: id,
		WhereToDelete: "delete its token Secret, or let it expire",
	})
	return plan, nil
}

func (f *KubernetesDriverFactory) PlanKeylessSpec(_ string, spec, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return &credential.KeylessSpecPlan{Delta: withInputs(federatedSpecDelta(spec, inputs), inputs)}, nil
}

func (f *KubernetesDriverFactory) KeylessPrerequisites(keyless credential.Config, specs []credential.PlannedSpec, env credential.TrustEnv) []credential.Prerequisite {
	aud := credential.GetString(keyless, "audience", "<audience>")
	body := fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1   # v1beta1 on Kubernetes 1.30 to 1.33
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: %s
    audiences: [%q]
  claimValidationRules:
  - expression: 'claims.sub.startsWith("%s")'
    message: sub must be a Warden workload identity of this namespace
  claimMappings:
    username:
      claim: sub
      prefix: "warden:"`, env.IssuerURL, aud, env.SubjectPrefix)
	return append([]credential.Prerequisite{
		{
			Title:  "Structured authentication configuration",
			Where:  "the API server (--authentication-config)",
			Format: "yaml",
			Body:   body,
		},
		{
			Title:  "Notes",
			Where:  "the API server",
			Format: "text",
			Body: "--authentication-config cannot be combined with the --oidc-* flags. Agents authenticate as users " +
				"\"warden:" + env.SubjectPrefix + "<mount_accessor>:<principal_id>\"; bind RBAC roles to those users.",
		},
	}, append(agentIdentityNote(specs), delegationNote(specs, env,
		"widen the claim validation rule to 'claims.sub.startsWith(\""+env.SubjectPrefix+"\") || "+
			"claims.warden_namespace == \""+env.NamespaceClaim+"\"'. Delegated users then authenticate as \"warden:<user id>\".")...)...)
}

// ============================================================================
// Alibaba Cloud
// ============================================================================

func (f *AlicloudDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	delta := map[string]string{"auth_method": alicloudAuthMethodOIDCFederation}
	clearPresent(delta, current, "access_key_id", "access_key_secret", "management_user_name", "activation_delay", "ram_endpoint")
	withInputs(delta, inputs)

	plan := &credential.KeylessSourcePlan{Delta: delta}
	if inputOr(inputs, current, "oidc_provider_arn") == "" {
		plan.NeedsInput = append(plan.NeedsInput, "oidc_provider_arn")
	}
	if inputOr(inputs, current, "audience") == "" {
		plan.NeedsInput = append(plan.NeedsInput, "audience")
	}
	if id := current.Get("access_key_id"); id != "" {
		where := "delete it in RAM"
		if user := current.Get("management_user_name"); user != "" {
			where = "delete it in RAM, on user " + user
		}
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{Kind: "AccessKey", ID: id, WhereToDelete: where})
	}
	return plan, nil
}

func (f *AlicloudDriverFactory) PlanKeylessSpec(_ string, spec, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return &credential.KeylessSpecPlan{Delta: withInputs(federatedSpecDelta(spec, inputs), inputs)}, nil
}

func (f *AlicloudDriverFactory) KeylessPrerequisites(keyless credential.Config, specs []credential.PlannedSpec, env credential.TrustEnv) []credential.Prerequisite {
	aud := credential.GetString(keyless, "audience", "<audience>")
	providerARN := credential.GetString(keyless, "oidc_provider_arn", "acs:ram::<account-id>:oidc-provider/<name>")

	prereqs := []credential.Prerequisite{{
		Title:  "OIDC identity provider",
		Where:  "RAM (CreateOIDCProvider)",
		Format: "json",
		Body: prettyJSON(map[string]any{
			"OIDCProviderName": providerARN[strings.LastIndex(providerARN, "/")+1:],
			"IssuerUrl":        env.IssuerURL,
			"ClientIds":        aud,
			"Fingerprints":     "<SHA-1 fingerprint of the issuer's TLS certificate>",
		}),
	}}

	roles := map[string]bool{}
	for _, s := range specs {
		if arn := s.Config.Get("role_arn"); arn != "" && usesWardenIdentity(s.Config) {
			roles[arn] = true
		}
	}
	policy := prettyJSON(map[string]any{
		"Version": "1",
		"Statement": []any{map[string]any{
			"Effect":    "Allow",
			"Principal": map[string]any{"Federated": providerARN},
			"Action":    "sts:AssumeRole",
			"Condition": map[string]any{
				"StringEquals": map[string]any{"oidc:iss": []string{env.IssuerURL}, "oidc:aud": []string{aud}},
				"StringLike":   map[string]any{"oidc:sub": []string{subjectPattern(env)}},
			},
		}},
	})
	for _, arn := range slices.Sorted(func(yield func(string) bool) {
		for k := range roles {
			if !yield(k) {
				return
			}
		}
	}) {
		prereqs = append(prereqs, credential.Prerequisite{Title: "Trust policy", Where: "RAM role " + arn, Format: "json", Body: policy})
	}
	return append(prereqs, agentIdentityNote(specs)...)
}

var (
	_ credential.KeylessPlanner = (*AWSDriverFactory)(nil)
	_ credential.KeylessPlanner = (*VaultDriverFactory)(nil)
	_ credential.KeylessPlanner = (*AzureDriverFactory)(nil)
	_ credential.KeylessPlanner = (*GCPDriverFactory)(nil)
	_ credential.KeylessPlanner = (*KubernetesDriverFactory)(nil)
	_ credential.KeylessPlanner = (*AlicloudDriverFactory)(nil)
)
