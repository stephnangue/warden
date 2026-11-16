package drivers

import (
	"fmt"

	"github.com/stephnangue/warden/credential"
)

// Keyless planners. Each source type that can hold a secret says what its
// keyless form is: federation for the cloud and Vault drivers, credential
// chaining for the rest. The deltas remove exactly the keys the type's own
// keyless-mode validation refuses; the core validates the result, so a key
// missed here shows as a blocker in the plan.

// choiceInput names the per-spec input that picks among a plan's Choices.
const choiceInput = "choice"

// clearPresent adds "" to delta for each key the config holds, so the delta
// names only what it actually removes.
func clearPresent(delta map[string]string, config credential.Config, keys ...string) {
	for _, k := range keys {
		if _, ok := config.Lookup(k); ok {
			delta[k] = ""
		}
	}
}

// withInputs merges the operator's inputs over delta, leaving out the choice
// selector, which is not a config key.
func withInputs(delta, inputs map[string]string) map[string]string {
	for k, v := range inputs {
		if k != choiceInput {
			delta[k] = v
		}
	}
	return delta
}

// inputOr returns the input, else the current config's value.
func inputOr(inputs map[string]string, config credential.Config, key string) string {
	if v := inputs[key]; v != "" {
		return v
	}
	return config.Get(key)
}

// ============================================================================
// Chaining: the source's secret moves to a spec it references
// ============================================================================

// chainedSourcePlan is the source delta every chaining driver shares: clear the
// keys its chained mode refuses, set secret_spec, and ask for one when the
// operator gave none.
func chainedSourcePlan(current credential.Config, inputs map[string]string, clear []string, leftovers []credential.Leftover) *credential.KeylessSourcePlan {
	delta := map[string]string{}
	clearPresent(delta, current, clear...)
	withInputs(delta, inputs)

	plan := &credential.KeylessSourcePlan{Delta: delta, Leftovers: leftovers}
	if inputOr(inputs, current, credential.ConfigSecretSpec) == "" {
		plan.NeedsInput = append(plan.NeedsInput, credential.ConfigSecretSpec)
	}
	return plan
}

// chainedSpecPlan leaves a spec as it is: a spec on a chained source draws the
// source's secret through the source, so nothing about it changes but the
// rotation period the core clears. Inputs still apply, for an operator who
// wants to adjust a spec in the same step.
func chainedSpecPlan(inputs map[string]string) *credential.KeylessSpecPlan {
	return &credential.KeylessSpecPlan{Delta: withInputs(map[string]string{}, inputs)}
}

// chainedPrerequisites describes the referenced secret the keyless source
// reads: which spec supplies it and which fields its payload must carry.
func chainedPrerequisites(keyless credential.Config, fields string) []credential.Prerequisite {
	return []credential.Prerequisite{{
		Title:  "Referenced secret",
		Where:  fmt.Sprintf("the secret credential spec %q reads", keyless.Get(credential.ConfigSecretSpec)),
		Format: "text",
		Body: "Store a newly issued credential there, not the one this source holds now: that one stays live " +
			"until it is deleted upstream, and nothing should depend on it.\n" +
			"The payload must carry: " + fields + ".\n" +
			"The referenced spec must set subject_token_source (warden_identity or agent_identity) and must not chain itself.",
	}}
}

// ElasticDriverFactory

func (f *ElasticDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	var leftovers []credential.Leftover
	if id := current.Get("api_key_id"); id != "" || current.Get("api_key") != "" {
		leftovers = append(leftovers, credential.Leftover{Kind: "API key", ID: orUnknown(id), WhereToDelete: "invalidate it in Elasticsearch (Security > API keys)"})
	}
	return chainedSourcePlan(current, inputs, []string{"api_key", "api_key_id", "activation_delay"}, leftovers), nil
}

func (f *ElasticDriverFactory) PlanKeylessSpec(_ string, _, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return chainedSpecPlan(inputs), nil
}

func (f *ElasticDriverFactory) KeylessPrerequisites(keyless credential.Config, _ []credential.PlannedSpec, _ credential.TrustEnv) []credential.Prerequisite {
	return chainedPrerequisites(keyless, "api_key (or encoded), and api_key_id")
}

// GrafanaDriverFactory

func (f *GrafanaDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	leftovers := []credential.Leftover{{Kind: "service account token", ID: "admin_token, stored on the source", WhereToDelete: "delete it in Grafana (Administration > Service accounts)"}}
	return chainedSourcePlan(current, inputs, []string{"admin_token"}, leftovers), nil
}

func (f *GrafanaDriverFactory) PlanKeylessSpec(_ string, _, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return chainedSpecPlan(inputs), nil
}

func (f *GrafanaDriverFactory) KeylessPrerequisites(keyless credential.Config, _ []credential.PlannedSpec, _ credential.TrustEnv) []credential.Prerequisite {
	return chainedPrerequisites(keyless, "admin_token (or api_key, or token)")
}

// IBMDriverFactory

func (f *IBMDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	leftovers := []credential.Leftover{{Kind: "IAM API key", ID: "api_key, stored on the source", WhereToDelete: "delete it in IBM Cloud IAM (API keys)"}}
	return chainedSourcePlan(current, inputs, []string{"api_key", "account_id", "activation_delay"}, leftovers), nil
}

func (f *IBMDriverFactory) PlanKeylessSpec(_ string, _, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return chainedSpecPlan(inputs), nil
}

func (f *IBMDriverFactory) KeylessPrerequisites(keyless credential.Config, _ []credential.PlannedSpec, _ credential.TrustEnv) []credential.Prerequisite {
	return chainedPrerequisites(keyless, "api_key (or apikey)")
}

// OVHDriverFactory

func (f *OVHDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	leftovers := []credential.Leftover{{Kind: "OAuth2 client", ID: orUnknown(current.Get("client_id")), WhereToDelete: "delete it in OVHcloud (IAM > service accounts)"}}
	return chainedSourcePlan(current, inputs, []string{"client_id", "client_secret"}, leftovers), nil
}

func (f *OVHDriverFactory) PlanKeylessSpec(_ string, _, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return chainedSpecPlan(inputs), nil
}

func (f *OVHDriverFactory) KeylessPrerequisites(keyless credential.Config, _ []credential.PlannedSpec, _ credential.TrustEnv) []credential.Prerequisite {
	return chainedPrerequisites(keyless, "client_id and client_secret (or secret)")
}

// ScalewayDriverFactory

func (f *ScalewayDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	leftovers := []credential.Leftover{{Kind: "IAM API key", ID: orUnknown(current.Get("management_access_key")), WhereToDelete: "delete it in Scaleway (IAM > API keys)"}}
	return chainedSourcePlan(current, inputs, []string{"management_secret_key", "management_access_key", "activation_delay"}, leftovers), nil
}

func (f *ScalewayDriverFactory) PlanKeylessSpec(_ string, _, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return chainedSpecPlan(inputs), nil
}

func (f *ScalewayDriverFactory) KeylessPrerequisites(keyless credential.Config, _ []credential.PlannedSpec, _ credential.TrustEnv) []credential.Prerequisite {
	return chainedPrerequisites(keyless, "management_secret_key (or secret_key)")
}

// GitLabDriverFactory

func (f *GitLabDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	var leftovers []credential.Leftover
	if current.Get("personal_access_token") != "" {
		leftovers = append(leftovers, credential.Leftover{Kind: "personal access token", ID: "personal_access_token, stored on the source", WhereToDelete: "revoke it in GitLab (Access tokens)"})
	}
	if current.Get("application_secret") != "" {
		leftovers = append(leftovers, credential.Leftover{Kind: "OAuth application secret", ID: orUnknown(current.Get("application_id")), WhereToDelete: "renew the application's secret in GitLab (Applications)"})
	}
	return chainedSourcePlan(current, inputs, []string{"personal_access_token", "application_id", "application_secret"}, leftovers), nil
}

func (f *GitLabDriverFactory) PlanKeylessSpec(_ string, _, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return chainedSpecPlan(inputs), nil
}

func (f *GitLabDriverFactory) KeylessPrerequisites(keyless credential.Config, _ []credential.PlannedSpec, _ credential.TrustEnv) []credential.Prerequisite {
	if credential.GetString(keyless, "auth_method", "pat") == "oauth2" {
		return chainedPrerequisites(keyless, "application_id and application_secret (or client_id and client_secret)")
	}
	return chainedPrerequisites(keyless, "personal_access_token (or pat)")
}

// OAuth2DriverFactory

func (f *OAuth2DriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	clear := []string{"client_id", "client_secret"}
	leftover := credential.Leftover{Kind: "OAuth2 client secret", ID: orUnknown(current.Get("client_id")), WhereToDelete: "rotate or delete the client's secret at the authorization server"}
	if credential.GetString(current, "client_auth", clientAuthSecretPost) == clientAuthPrivateKeyJWT {
		clear = []string{"client_id", "private_key", "client_assertion_kid"}
		leftover.Kind = "client assertion signing key"
		leftover.WhereToDelete = "retire it at the authorization server once the chained credential works"
	}
	return chainedSourcePlan(current, inputs, targetMethodClears(current, inputs, clear, "client_assertion_alg", "client_assertion_aud"), []credential.Leftover{leftover}), nil
}

// targetMethodClears adds to the keys a keyless plan clears whatever the client_auth
// the plan moves the source to refuses, so the planned config validates rather than
// carrying over settings of the method the source is leaving:
//
//   - kms_private_key_jwt reads its payload by fixed names and takes its algorithm
//     from the key, so it refuses secret_field and client_assertion_alg.
//   - a method that sends no client assertion refuses assertionKeys, the driver's
//     settings for one.
func targetMethodClears(current credential.Config, inputs map[string]string, clear []string, assertionKeys ...string) []string {
	switch inputOr(inputs, current, "client_auth") {
	case clientAuthKMSPrivateKeyJWT:
		return append(clear, "client_assertion_alg", credential.ConfigSecretField)
	case clientAuthPrivateKeyJWT:
		return clear
	default:
		return append(clear, assertionKeys...)
	}
}

// PlanKeylessSpec clears a client credential a spec carries itself: on a
// chained source the pair comes from the chain. The authorization_code flow
// needs its client credential at consent time, with no caller to fetch it as,
// so a spec using it cannot move with the source.
func (f *OAuth2DriverFactory) PlanKeylessSpec(_ string, spec, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	if spec.Get("auth_method") == oauth2AuthMethodAuthorizationCode {
		return &credential.KeylessSpecPlan{Blocker: "the authorization_code flow has no keyless form: its consent runs without a caller to fetch a chained client credential as"}, nil
	}
	delta := map[string]string{}
	clearPresent(delta, spec, "client_id", "client_secret", "private_key", "client_assertion_kid")
	plan := &credential.KeylessSpecPlan{Delta: withInputs(delta, inputs)}
	clientID := credential.GetString(spec, "client_id", "client id not recorded in the spec config")
	if spec.Get("client_secret") != "" {
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind:          "OAuth2 client secret",
			ID:            clientID,
			WhereToDelete: "rotate or delete the client's secret at the authorization server",
		})
	}
	if spec.Get("private_key") != "" {
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind:          "client assertion signing key",
			ID:            clientID,
			WhereToDelete: "retire it at the authorization server once the chained credential works",
		})
	}
	return plan, nil
}

func (f *OAuth2DriverFactory) KeylessPrerequisites(keyless credential.Config, _ []credential.PlannedSpec, _ credential.TrustEnv) []credential.Prerequisite {
	switch credential.GetString(keyless, "client_auth", clientAuthSecretPost) {
	case clientAuthPrivateKeyJWT:
		return chainedPrerequisites(keyless, "client_id and private_key (with client_assertion_kid or kid when the authorization server selects keys by id)")
	case clientAuthKMSPrivateKeyJWT:
		return chainedPrerequisites(keyless, kmsSignerPayload)
	}
	return chainedPrerequisites(keyless, "client_id and client_secret")
}

// kmsSignerPayload is what a kms_private_key_jwt source's referenced spec has to yield.
const kmsSignerPayload = "a signing capability (e.g. mint_method=transit_signer) with payload.client_id naming the client"

// TokenExchangeDriverFactory

func (f *TokenExchangeDriverFactory) PlanKeyless(current credential.Config, inputs map[string]string) (*credential.KeylessSourcePlan, error) {
	// A public client stores no client credential: there is nothing to move to
	// chaining, and secret_spec is refused for it. Planning the secret-based migration
	// would clear the client_id it may need and ask for an input it cannot take.
	//
	// With grant=id_jag a public client is not keyless but refused, since the IdP must
	// authenticate the client it issues an ID-JAG to. That is fixed by updating the
	// source to a client authentication, not by moving a credential it does not hold,
	// so the plan says so and plans nothing; given inputs, the core's validation of the
	// proposed source names what is still wrong.
	if credential.GetString(current, "client_auth", "") == clientAuthNone {
		note := "client_auth=none is already keyless: a public client stores no client credential"
		if inputOr(inputs, current, "grant") == tokenExchangeGrantIDJAG {
			note = "client_auth=none stores no client credential, but grant=id_jag cannot use it: the IdP must authenticate the client. " +
				"Update the source to a client_auth first; a secret-based one can then be planned keyless"
		}
		return &credential.KeylessSourcePlan{
			Delta: withInputs(map[string]string{}, inputs),
			Notes: []string{note},
		}, nil
	}
	clear := []string{"client_id", "client_secret"}
	kind := "OAuth2 client secret"
	if credential.GetString(current, "client_auth", clientAuthSecretPost) == clientAuthPrivateKeyJWT {
		clear = []string{"client_id", "private_key", "client_assertion_kid"}
		kind = "client assertion signing key"
	}
	leftovers := []credential.Leftover{{Kind: kind, ID: orUnknown(current.Get("client_id")), WhereToDelete: "retire it at the authorization server once the chained credential works"}}
	// The IdP client's assertion settings follow its method; resource_issuer is leg 2's,
	// which is the IdP client's only when the source names no resource client.
	assertionKeys := []string{"client_assertion_aud", "issuer"}
	var notes []string
	resource := inputOr(inputs, current, "resource_client_auth")
	if resource == "" {
		assertionKeys = append(assertionKeys, "resource_issuer")
		idpTarget := inputOr(inputs, current, "client_auth")
		if idpTarget == "" {
			idpTarget = idpClientKeys.defaultAuth
		}
		if credential.GetString(current, "grant", "") == tokenExchangeGrantIDJAG && isClientSecretMethod(idpTarget) {
			notes = append(notes, "a secret-based id_jag source needs a resource client of its own, or leg 2 sends the IdP's client secret "+
				"to the resource authorization server: pass resource_client_auth, and put that client's credential in the same payload")
		}
	} else {
		// The resource client moves into the same referenced payload, and its own
		// credential stays live at the resource authorization server until retired there.
		clear = append(clear, "resource_client_id", "resource_client_secret", "resource_private_key", "resource_client_assertion_kid")
		if isClientSecretMethod(resource) {
			// A secret carries no assertion, so nothing names an audience for it.
			clear = append(clear, "resource_client_assertion_aud", "resource_issuer")
		}
		if id := current.Get("resource_client_id"); id != "" || current.Get("resource_client_secret") != "" || current.Get("resource_private_key") != "" {
			resourceKind := "resource client secret"
			if current.Get("resource_private_key") != "" {
				resourceKind = "resource client assertion signing key"
			}
			leftovers = append(leftovers, credential.Leftover{Kind: resourceKind, ID: orUnknown(id),
				WhereToDelete: "retire it at the resource authorization server once the chained credential works"})
		}
	}
	plan := chainedSourcePlan(current, inputs, targetMethodClears(current, inputs, clear, assertionKeys...), leftovers)
	plan.Notes = append(plan.Notes, notes...)
	return plan, nil
}

func (f *TokenExchangeDriverFactory) PlanKeylessSpec(_ string, _, _, _ credential.Config, inputs map[string]string) (*credential.KeylessSpecPlan, error) {
	return chainedSpecPlan(inputs), nil
}

func (f *TokenExchangeDriverFactory) KeylessPrerequisites(keyless credential.Config, _ []credential.PlannedSpec, _ credential.TrustEnv) []credential.Prerequisite {
	// The resource client, when the source names one, travels in the same payload under
	// its own field names.
	var resource string
	switch credential.GetString(keyless, "resource_client_auth", "") {
	case clientAuthSecretBasic, clientAuthSecretPost:
		resource = "; and resource_client_id and resource_client_secret for the resource authorization server"
	case clientAuthPrivateKeyJWT:
		resource = "; and resource_client_id and resource_private_key (with resource_client_assertion_kid or resource_kid when the resource authorization server selects keys by id)"
	case clientAuthKMSPrivateKeyJWT:
		resource = ", and payload.resource_client_id naming the client at the resource authorization server, " +
			"which signs with the same key under the same kid"
	}
	switch credential.GetString(keyless, "client_auth", clientAuthSecretPost) {
	case clientAuthNone:
		return nil // no referenced secret to prepare
	case clientAuthPrivateKeyJWT:
		return chainedPrerequisites(keyless, "client_id and private_key (with client_assertion_kid or kid when the authorization server selects keys by id)"+resource)
	case clientAuthKMSPrivateKeyJWT:
		return chainedPrerequisites(keyless, kmsSignerPayload+resource)
	}
	return chainedPrerequisites(keyless, "client_id and client_secret"+resource)
}

// orUnknown shows an identifier, or says it was not recorded.
func orUnknown(id string) string {
	if id == "" {
		return "id not recorded in the source config"
	}
	return id
}

var (
	_ credential.KeylessPlanner = (*ElasticDriverFactory)(nil)
	_ credential.KeylessPlanner = (*GrafanaDriverFactory)(nil)
	_ credential.KeylessPlanner = (*IBMDriverFactory)(nil)
	_ credential.KeylessPlanner = (*OVHDriverFactory)(nil)
	_ credential.KeylessPlanner = (*ScalewayDriverFactory)(nil)
	_ credential.KeylessPlanner = (*GitLabDriverFactory)(nil)
	_ credential.KeylessPlanner = (*OAuth2DriverFactory)(nil)
	_ credential.KeylessPlanner = (*TokenExchangeDriverFactory)(nil)
)
