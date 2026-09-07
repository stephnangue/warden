//go:build e2e

package fullchain

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Credential chaining with an AWS source. The suite alongside this one drives the
// same shape over a Vault KV read; this one exists because until recently no other
// kind of source could be a chaining source at all — key_value refused everything
// but hvault, so the machinery's driver-independence was true in principle and
// untested in fact.
//
// What only a full chain shows: the reference resolving to a real federated
// assume-role and a real stored-secret read, the payload reaching MintFromSecret,
// the source's declaration surviving Parse, and the declared field arriving as an
// upstream header. Each of those is covered alone in the driver and store tests.
//
// Why the source must be keyless: a referenced spec is minted as the session-pinned
// caller, which forces the exchange path, which an aws source serves only under
// auth_method=oidc_federation. That is the same constraint the hvault suite works
// around with its own federated source.
//
// Both subject sources are driven, because they are different code paths and only
// one of them mints anything. Under agent_identity the agent's own inbound JWT is
// forwarded as the web identity token and Warden signs nothing; under
// warden_identity Warden mints an assertion, which is the only path on which the
// audience and resource claims are derived at all.

const (
	// The secret the stub holds. Nothing in any spec config carries these values —
	// they exist only inside the stub's payload — so an assertion on them can only
	// pass if the whole chain ran.
	awsChainSecretID = "e2e/datadog-keys"
	awsChainAPIKey   = "e2e-dd-aws-not-a-real-key"
	awsChainAppKey   = "e2e-dd-aws-not-a-real-app-key"

	// Every resource here is test-local, the sources included, for the reason the
	// hvault suite documents: a killed run skips t.Cleanup, and a leftover consumer
	// spec would block its source from being deleted, which the next run's setup
	// cannot recover from. Test-local resources can only ever strand themselves.
	awsChainAWSSource = "fc-aws-chain-fed"
	awsChainSource    = "fc-aws-chain-src"

	// The declaring chain, per subject source.
	awsChainAgentSecretSpec = "fc-aws-chain-keys-agent"
	awsChainAgentSpec       = "fc-aws-chain-cred-agent"
	awsChainAgentRole       = "fc-aws-chain-role-agent"

	awsChainWardenSecretSpec = "fc-aws-chain-keys-warden"
	awsChainWardenSpec       = "fc-aws-chain-cred-warden"
	awsChainWardenRole       = "fc-aws-chain-role-warden"

	// The control: same stub secret, same referenced spec, a source declaring
	// nothing.
	awsChainNoDeclSource = "fc-aws-nodecl-src"
	awsChainNoDeclSpec   = "fc-aws-nodecl-cred"
	awsChainNoDeclRole   = "fc-aws-nodecl-role"

	// The per-agent row. The stub answers for whatever id it is asked for, so the
	// resolved coordinate does not have to be seeded in advance.
	awsChainTemplatedPrefix = "e2e/per-agent"
	awsChainTemplatedSecret = "fc-aws-tmpl-keys"
	awsChainTemplatedSpec   = "fc-aws-tmpl-cred"
	awsChainTemplatedRole   = "fc-aws-tmpl-role"

	// The subject the default JWT carries, and so what {{agent.sub}} must resolve to.
	awsChainAgentSub = "e2e-agent"

	// What a federated aws source asks its assertions be addressed to, absent an
	// explicit audience on the source.
	awsChainDefaultAudience = "sts.amazonaws.com"
)

// awsStub stands in for STS and Secrets Manager. Both endpoints are overridable in
// aws source config, so one in-process listener serves the whole federated fetch:
// AssumeRoleWithWebIdentity, then GetSecretValue signed with what it returned.
//
// It is a stub rather than a real account because the alternative is no coverage:
// the driver's own tests reach it the same way, and nothing else in this tree talks
// to AWS at all.
var awsStub *httptest.Server

var (
	awsStubOnce sync.Once
	awsStubMu   sync.Mutex
	awsStubIDs  []string // SecretIds seen, in order
	awsStubToks []string // WebIdentityTokens seen, in order
)

func awsStubSeen() (ids, tokens []string) {
	awsStubMu.Lock()
	defer awsStubMu.Unlock()
	return append([]string(nil), awsStubIDs...), append([]string(nil), awsStubToks...)
}

func startAWSStub() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Secrets Manager speaks JSON with a target header; STS speaks form-encoded
		// query with an Action. That is the whole routing.
		if strings.Contains(r.Header.Get("X-Amz-Target"), "GetSecretValue") {
			var body struct {
				SecretId string `json:"SecretId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)

			awsStubMu.Lock()
			awsStubIDs = append(awsStubIDs, body.SecretId)
			awsStubMu.Unlock()

			// The fixed secret carries the values the declared-field rows assert.
			// Any other id — the templated row — gets a payload derived from it, so
			// the header arriving upstream names the secret actually read.
			apiKey, appKey := awsChainAPIKey, awsChainAppKey
			if body.SecretId != awsChainSecretID {
				apiKey, appKey = "k-for-"+body.SecretId, "app-for-"+body.SecretId
			}
			payload, _ := json.Marshal(map[string]string{"api_key": apiKey, "application_key": appKey})
			out, _ := json.Marshal(map[string]string{"Name": body.SecretId, "SecretString": string(payload)})
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_, _ = w.Write(out)
			return
		}

		_ = r.ParseForm()
		if action := r.Form.Get("Action"); action != "AssumeRoleWithWebIdentity" {
			http.Error(w, "unexpected STS action "+action, http.StatusBadRequest)
			return
		}
		// The caller's token has to arrive as the web identity token; without it the
		// federation leg is not being exercised at all. Recorded so the
		// warden_identity row can check what was actually presented.
		token := r.Form.Get("WebIdentityToken")
		if token == "" {
			http.Error(w, "missing WebIdentityToken", http.StatusBadRequest)
			return
		}
		awsStubMu.Lock()
		awsStubToks = append(awsStubToks, token)
		awsStubMu.Unlock()

		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAE2EEXAMPLE</AccessKeyId>
      <SecretAccessKey>e2e-session-secret</SecretAccessKey>
      <SessionToken>e2e-session-token</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/WardenSecretsReader/e2e</Arn>
      <AssumedRoleId>AROAE2EEXAMPLE:e2e</AssumedRoleId>
    </AssumedRoleUser>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
}

// ensureAWSStub starts the listener on first use and clears what it recorded, so
// each row counts only its own traffic. Unlike the provider stubs it is not needed
// to build an env — the source naming it is created per test — so it stays out of
// ensureEnv.
func ensureAWSStub(t *testing.T) {
	t.Helper()
	awsStubOnce.Do(func() { awsStub = startAWSStub() })
	awsStubMu.Lock()
	defer awsStubMu.Unlock()
	awsStubIDs, awsStubToks = nil, nil
}

// setupAWSChainedSpecs builds every chain this file drives over one stub: a
// declaring consumer per subject source, an undeclaring control, and a per-agent
// templated row. All drive the datadog mount, whose extractor turns each carried
// field into its own header.
//
// Order is load-bearing both ways. A spec naming a secret_spec that does not exist
// is refused at create, and a referenced spec cannot be deleted while a consumer
// names it, so cleanup runs consumer-first — which also clears anything a killed
// run left behind.
func setupAWSChainedSpecs(t *testing.T) {
	t.Helper()

	mustWrite := func(method, path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	clear := func() {
		for _, role := range []string{awsChainAgentRole, awsChainWardenRole, awsChainNoDeclRole, awsChainTemplatedRole} {
			h.APIRequest(t, "DELETE", "auth/jwt/role/"+role, leaderPort, "")
		}
		for _, spec := range []string{awsChainAgentSpec, awsChainWardenSpec, awsChainNoDeclSpec, awsChainTemplatedSpec} {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		}
		for _, spec := range []string{awsChainAgentSecretSpec, awsChainWardenSecretSpec, awsChainTemplatedSecret} {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		}
		for _, src := range []string{awsChainSource, awsChainNoDeclSource, awsChainAWSSource} {
			h.APIRequest(t, "DELETE", "sys/cred/sources/"+src, leaderPort, "")
		}
	}
	clear()
	t.Cleanup(clear)

	// The keyless source. Both endpoint overrides point at the stub: the federation
	// leg and the fetch leg are separate clients, and a source redirecting only one
	// would reach the real service for the other.
	mustWrite("POST", "sys/cred/sources/"+awsChainAWSSource, `{
		"type":"aws","config":{
			"auth_method":"oidc_federation","region":"eu-west-1",
			"sts_endpoint":"`+awsStub.URL+`","secretsmanager_endpoint":"`+awsStub.URL+`"}}`,
		"create the keyless aws source")

	// The referenced specs: the whole credential, read from one stored secret, once
	// per subject source. subject_token_source is not optional — a chained secret is
	// minted as the caller, and the store refuses the reference otherwise.
	for _, ref := range []struct{ name, subject string }{
		{awsChainAgentSecretSpec, "agent_identity"},
		{awsChainWardenSecretSpec, "warden_identity"},
	} {
		mustWrite("POST", "sys/cred/specs/"+ref.name, `{
			"type":"key_value","source":"`+awsChainAWSSource+`","config":{
				"mint_method":"secret_read","secret_id":"`+awsChainSecretID+`",
				"role_arn":"arn:aws:iam::123456789012:role/WardenSecretsReader",
				"subject_token_source":"`+ref.subject+`"}}`,
			"create the referenced secret spec for "+ref.subject)
	}

	// The declaring source. api_key travels because it is the credential; the
	// application key travels because this names it.
	mustWrite("POST", "sys/cred/sources/"+awsChainSource,
		`{"type":"apikey","config":{"credential_fields":"application_key"}}`,
		"create the declaring source")

	for _, row := range []struct{ spec, secretSpec, role string }{
		{awsChainAgentSpec, awsChainAgentSecretSpec, awsChainAgentRole},
		{awsChainWardenSpec, awsChainWardenSecretSpec, awsChainWardenRole},
	} {
		// The consuming spec holds no api_key: it is mutually exclusive with
		// secret_spec. secret_field is explicit — the fallback would find api_key by
		// name anyway, but a test should not lean on a fallback to choose the secret.
		mustWrite("POST", "sys/cred/specs/"+row.spec, `{
			"type":"api_key","source":"`+awsChainSource+`","config":{
				"secret_spec":"`+row.secretSpec+`","secret_field":"api_key"}}`,
			"create the chained consuming spec "+row.spec)

		// The mount's own JWT agent role binds its default spec, so each row needs
		// one bound to its own chained spec instead.
		mustWrite("POST", "auth/jwt/role/"+row.role, `{
			"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+row.spec+`",
			"user_claim":"sub","token_ttl":3600}`,
			"create the agent role "+row.role)
	}

	// The control source, identical but for the missing declaration.
	mustWrite("POST", "sys/cred/sources/"+awsChainNoDeclSource,
		`{"type":"apikey","config":{}}`,
		"create the undeclaring source")

	mustWrite("POST", "sys/cred/specs/"+awsChainNoDeclSpec, `{
		"type":"api_key","source":"`+awsChainNoDeclSource+`","config":{
			"secret_spec":"`+awsChainAgentSecretSpec+`","secret_field":"api_key"}}`,
		"create the chained spec on the undeclaring source")

	mustWrite("POST", "auth/jwt/role/"+awsChainNoDeclRole, `{
		"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+awsChainNoDeclSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the undeclared agent role")

	// The per-agent row. {{agent.sub}} needs no assertion_metadata_claims entry —
	// the principal is not an opt-in disclosure, and it is already inside the cache
	// identity, so nothing can be served across agents.
	mustWrite("POST", "sys/cred/specs/"+awsChainTemplatedSecret, `{
		"type":"key_value","source":"`+awsChainAWSSource+`","config":{
			"mint_method":"secret_read","secret_id":"`+awsChainTemplatedPrefix+`/{{agent.sub}}",
			"role_arn":"arn:aws:iam::123456789012:role/WardenSecretsReader",
			"subject_token_source":"agent_identity"}}`,
		"create the templated secret spec")

	mustWrite("POST", "sys/cred/specs/"+awsChainTemplatedSpec, `{
		"type":"api_key","source":"`+awsChainSource+`","config":{
			"secret_spec":"`+awsChainTemplatedSecret+`","secret_field":"api_key"}}`,
		"create the templated consuming spec")

	mustWrite("POST", "auth/jwt/role/"+awsChainTemplatedRole, `{
		"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+awsChainTemplatedSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the templated agent role")
}

// TestAWSSecretRead_ChainedCredentialCarriesItsDeclaredField is the row this file
// exists for: two secrets living in one stored payload, arriving as two upstream
// headers, with an aws source at the far end of the chain.
//
// Both asserted values appear in no spec config anywhere, so the row fails if any
// link breaks: the federated assume-role, the stored-secret read, the material
// reaching the consuming driver, the declaration surviving Parse, or the extractor.
//
// A JWT agent leg rather than the usual certificate, because agent_identity
// forwards the agent's own inbound JWT as the exchange subject and fails closed on
// a cert-authenticated request. warden_identity would tolerate a cert leg, but it
// shares this mount and the leg is per-mount.
func TestAWSSecretRead_ChainedCredentialCarriesItsDeclaredField(t *testing.T) {
	for _, tc := range []struct{ name, role string }{
		{"agent_identity", awsChainAgentRole},
		{"warden_identity", awsChainWardenRole},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Per subtest, not once for the pair: ensureEnv also clears the
			// upstream recorder, and an exact call count is what these rows assert.
			ensureEnv(t)
			useJWTAgentLeg(t, datadogEnv)
			ensureAWSStub(t)
			setupAWSChainedSpecs(t)

			status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
				AgentToken: h.GetDefaultJWT(t),
				Role:       tc.role,
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status: 200,
				Injected: map[string]string{
					"DD-API-KEY":         awsChainAPIKey,
					"DD-APPLICATION-KEY": awsChainAppKey,
				},
				Absent:        h.AlwaysAbsent("Authorization"),
				UpstreamCalls: 1,
			})

			ids, _ := awsStubSeen()
			if len(ids) != 1 || ids[0] != awsChainSecretID {
				t.Errorf("stored-secret reads = %v, want exactly [%s]", ids, awsChainSecretID)
			}
		})
	}
}

// TestAWSSecretRead_WardenIdentityPresentsAMintedAssertion checks what the subject
// source actually changes, which the row above cannot see: under warden_identity
// the token presented to the exchange is one Warden signed, not the agent's inbound
// JWT, and its claims are derived from the spec.
//
// The audience and the resource claim are the two the aws driver derives, and the
// resource is the reason this row exists at all — a stored-secret read only names
// its resource on this path, so nothing else here exercises that derivation.
//
// The assertion is verified against the published JWKS rather than merely decoded:
// an upstream that could not verify it would reject it, so decoding alone could
// pass on a token no real account would accept.
func TestAWSSecretRead_WardenIdentityPresentsAMintedAssertion(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	ensureAWSStub(t)
	setupAWSChainedSpecs(t)

	agentJWT := h.GetDefaultJWT(t)
	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: agentJWT,
		Role:       awsChainWardenRole,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": awsChainAPIKey},
		UpstreamCalls: 1,
	})

	_, tokens := awsStubSeen()
	if len(tokens) != 1 {
		t.Fatalf("web identity tokens presented = %d, want 1", len(tokens))
	}
	if tokens[0] == agentJWT {
		t.Fatal("warden_identity must present an assertion Warden minted, not the agent's inbound token")
	}

	claims := h.VerifyAssertion(t, leaderPort, tokens[0])
	if got := claims["aud"]; got != awsChainDefaultAudience {
		t.Errorf("assertion aud = %v, want %s", got, awsChainDefaultAudience)
	}
	// The resource names the spec's coordinate, so an operator can bind a role's
	// trust policy to the secret a spec reads rather than to the spec's name.
	if got, want := claims["warden_resource"], "aws-secretsmanager:"+awsChainSecretID; got != want {
		t.Errorf("assertion warden_resource = %v, want %s", got, want)
	}
}

// TestAWSSecretRead_ReferencedSecretCannotBeDeletedWhileConsumed pins the
// protection this file's own cleanup order depends on — and, since the reference
// check is type-blind, that it covers an aws-backed secret spec exactly as it does
// a Vault-backed one.
func TestAWSSecretRead_ReferencedSecretCannotBeDeletedWhileConsumed(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	ensureAWSStub(t)
	setupAWSChainedSpecs(t)

	status, body := h.APIRequest(t, "DELETE", "sys/cred/specs/"+awsChainAgentSecretSpec, leaderPort, "")
	if status < 400 {
		t.Fatalf("deleting a referenced secret spec: got status %d, want a failure (body: %s)", status, body)
	}
	if !strings.Contains(string(body), "referenced") {
		t.Errorf("the error should say the spec is still referenced, got: %s", body)
	}

	// Still mintable afterwards — the refusal left the chain intact rather than
	// half-deleted.
	reqStatus, reqBody, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       awsChainAgentRole,
	})
	h.AssertChain(t, upstream, reqStatus, reqBody, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": awsChainAPIKey},
		UpstreamCalls: 1,
	})
}

// TestAWSSecretRead_UndeclaredPayloadFieldStaysInAWS is what makes the first row
// mean something.
//
// It drives the identical chain — same stored secret, same referenced spec, same
// mount — through a source that declares nothing. The application key is right
// there in the payload and must not travel: a fetched secret is a shared blob an
// operator may keep notes, owners or rotation timestamps in, and copying it
// wholesale would send whichever of them a provider happens to read.
//
// The assertion is on DD-APPLICATION-KEY rather than some inert extra key,
// deliberately. An undeclared field no extractor maps could never appear in a
// header whatever carriage did, so a row asserting that absence would pass against
// any implementation — including one that copies the whole payload.
func TestAWSSecretRead_UndeclaredPayloadFieldStaysInAWS(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	ensureAWSStub(t)
	setupAWSChainedSpecs(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       awsChainNoDeclRole,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": awsChainAPIKey},
		Absent:        h.AlwaysAbsent("Authorization", "DD-APPLICATION-KEY"),
		UpstreamCalls: 1,
	})
}

// TestAWSSecretRead_TemplatedSecretIDResolvesPerAgent is what {{agent.sub}} on a
// stored-secret id exists for: one spec, holding one coordinate, reaching a
// different secret for each agent that mints through it.
//
// The stub answers for whatever id it is asked for and derives the payload from it,
// so the header arriving upstream names the secret actually read. A template that
// failed to resolve could not produce that value — it would either fail closed or
// ask for a literal "{{agent.sub}}", and both are asserted against.
func TestAWSSecretRead_TemplatedSecretIDResolvesPerAgent(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	ensureAWSStub(t)
	setupAWSChainedSpecs(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       awsChainTemplatedRole,
	})

	resolved := awsChainTemplatedPrefix + "/" + awsChainAgentSub
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": "k-for-" + resolved},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})

	ids, _ := awsStubSeen()
	if len(ids) != 1 || ids[0] != resolved {
		t.Errorf("stored-secret reads = %v, want exactly [%s]", ids, resolved)
	}
}
