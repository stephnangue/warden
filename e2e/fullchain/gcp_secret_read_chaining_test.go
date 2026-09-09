//go:build e2e

package fullchain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Credential chaining with a GCP source. The aws suite alongside this one drives the
// same shape over Secrets Manager; this one exists because Secret Manager reads
// through a different leg entirely — an STS token exchange rather than an assume-role
// — and because its payload has no fixed shape, so what the store holds decides how
// the credential is vended.
//
// What only a full chain shows: the reference resolving to a real token exchange and a
// real secret read, the payload reaching MintFromSecret, the source's declaration
// surviving Parse, and the declared field arriving as an upstream header. Each is
// covered alone in the driver and store tests.
//
// Why the chaining source must be keyless: a referenced spec is minted as the
// session-pinned caller, which forces the exchange path, which a gcp source serves
// only under auth_method=oidc_federation.
//
// Both subject sources are driven, because they are different code paths and only one
// of them mints anything. Under agent_identity the agent's own inbound JWT is
// exchanged at STS and Warden signs nothing; under warden_identity Warden mints an
// assertion, which is the only path on which the audience and resource claims are
// derived at all.
//
// The static path is driven too, on its own source. It can never be a chaining source
// — the store refuses a reference whose spec sets no subject_token_source — so it is
// exercised where it is actually reachable: the test-mint a spec write performs, which
// runs the whole path through the server against the stub.

const (
	// The secret the stub holds. Nothing in any spec config carries these values —
	// they exist only inside the stub's payload — so an assertion on them can only
	// pass if the whole chain ran.
	gcpChainSecretName = "e2e-datadog-keys"
	gcpChainProject    = "e2e-proj"
	gcpChainAPIKey     = "e2e-dd-gcp-not-a-real-key"
	gcpChainAppKey     = "e2e-dd-gcp-not-a-real-app-key"

	// Every resource here is test-local, the sources included: a killed run skips
	// t.Cleanup, and a leftover consumer spec would block its source from being
	// deleted, which the next run's setup cannot recover from. Test-local resources
	// can only ever strand themselves.
	gcpChainGCPSource = "fc-gcp-chain-fed"
	gcpChainSource    = "fc-gcp-chain-src"

	// The declaring chain, per subject source.
	gcpChainAgentSecretSpec = "fc-gcp-chain-keys-agent"
	gcpChainAgentSpec       = "fc-gcp-chain-cred-agent"
	gcpChainAgentRole       = "fc-gcp-chain-role-agent"

	gcpChainWardenSecretSpec = "fc-gcp-chain-keys-warden"
	gcpChainWardenSpec       = "fc-gcp-chain-cred-warden"
	gcpChainWardenRole       = "fc-gcp-chain-role-warden"

	// The control: same stub secret, same referenced spec, a source declaring nothing.
	gcpChainNoDeclSource = "fc-gcp-nodecl-src"
	gcpChainNoDeclSpec   = "fc-gcp-nodecl-cred"
	gcpChainNoDeclRole   = "fc-gcp-nodecl-role"

	// The per-agent row. The stub answers for whatever name it is asked for, so the
	// resolved coordinate does not have to be seeded in advance. No slash: a GCP
	// secret id admits only letters, digits, underscores and hyphens.
	gcpChainTemplatedPrefix = "e2e-per-agent"
	gcpChainTemplatedSecret = "fc-gcp-tmpl-keys"
	gcpChainTemplatedSpec   = "fc-gcp-tmpl-cred"
	gcpChainTemplatedRole   = "fc-gcp-tmpl-role"

	// The static path, which reads as the source itself rather than as the caller.
	gcpStaticSource     = "fc-gcp-static-src"
	gcpStaticSpec       = "fc-gcp-static-keys"
	gcpStaticSA         = "warden-e2e@e2e-proj.iam.gserviceaccount.com"
	gcpStaticSecretName = "e2e-static-keys"

	// The subject the default JWT carries, and so what {{agent.sub}} must resolve to.
	gcpChainAgentSub = "e2e-agent"

	// The WIF provider the federated source names. The assertion audience is derived
	// from it, which the warden_identity row asserts.
	gcpChainWIFProvider = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/e2e/providers/warden-oidc"
	gcpChainAudience    = "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/e2e/providers/warden-oidc"
)

// gcpStub stands in for STS, Secret Manager and the OAuth2 token grant. All three
// endpoints are overridable in gcp source config, so one in-process listener serves
// the whole fetch: the token exchange, then the secret read authorized with what it
// returned.
//
// It is a stub rather than a real project because the alternative is no coverage: the
// driver's own tests reach it the same way, and nothing else in this tree talks to GCP.
var gcpStub *httptest.Server

var (
	gcpStubOnce  sync.Once
	gcpStubMu    sync.Mutex
	gcpStubPaths []string // secret version resources read, in order
	gcpStubToks  []string // subject tokens presented at STS, in order
	gcpStubAuds  []string // audiences presented at STS, in order
	gcpStubReads []string // bearer token used for each secret read, in order
)

func gcpStubSeen() (paths, tokens, auds, readers []string) {
	gcpStubMu.Lock()
	defer gcpStubMu.Unlock()
	return append([]string(nil), gcpStubPaths...),
		append([]string(nil), gcpStubToks...),
		append([]string(nil), gcpStubAuds...),
		append([]string(nil), gcpStubReads...)
}

// gcpSecretPayload is what the stub holds for a given secret. The fixed name carries
// the values the declared-field rows assert; any other name — the templated row —
// gets a payload derived from it, so the header arriving upstream names the secret
// actually read.
func gcpSecretPayload(name string) string {
	apiKey, appKey := gcpChainAPIKey, gcpChainAppKey
	if name != gcpChainSecretName {
		apiKey, appKey = "k-for-"+name, "app-for-"+name
	}
	out, _ := json.Marshal(map[string]string{"api_key": apiKey, "application_key": appKey})
	return string(out)
}

func startGCPStub() *httptest.Server {
	mux := http.NewServeMux()

	// The OAuth2 JWT-bearer grant a static source makes against its key's token_uri.
	// The assertion is signed by a key this test generated, so there is nothing to
	// verify — recording that the grant happened is the point.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "e2e-static-source-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// The STS token exchange a federated source makes. The caller's token has to
	// arrive as the subject token; without it the federation leg is not being
	// exercised at all. Recorded so the warden_identity row can check what was
	// actually presented.
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		subject := r.PostForm.Get("subject_token")
		if subject == "" {
			http.Error(w, "missing subject_token", http.StatusBadRequest)
			return
		}

		gcpStubMu.Lock()
		gcpStubToks = append(gcpStubToks, subject)
		gcpStubAuds = append(gcpStubAuds, r.PostForm.Get("audience"))
		gcpStubMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "e2e-federated-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// Secret Manager. Everything else 400s, so a call reaching an endpoint this test
	// did not mean to exercise fails loudly rather than being absorbed.
	mux.HandleFunc("/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ":access") {
			http.Error(w, "unexpected call "+r.URL.Path, http.StatusBadRequest)
			return
		}
		versionPath := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/"), ":access")

		gcpStubMu.Lock()
		gcpStubPaths = append(gcpStubPaths, versionPath)
		gcpStubReads = append(gcpStubReads, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		gcpStubMu.Unlock()

		// projects/<p>/secrets/<name>/versions/<v>
		parts := strings.Split(versionPath, "/")
		if len(parts) != 6 {
			http.Error(w, "malformed resource "+versionPath, http.StatusBadRequest)
			return
		}
		payload := []byte(gcpSecretPayload(parts[3]))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"name": versionPath,
			"payload": map[string]string{
				"data": base64.StdEncoding.EncodeToString(payload),
				"dataCrc32c": strconv.FormatUint(
					uint64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli))), 10),
			},
		})
	})

	return httptest.NewServer(mux)
}

// ensureGCPStub starts the listener on first use and clears what it recorded, so each
// row counts only its own traffic. Unlike the provider stubs it is not needed to build
// an env — the source naming it is created per test — so it stays out of ensureEnv.
func ensureGCPStub(t *testing.T) {
	t.Helper()
	gcpStubOnce.Do(func() { gcpStub = startGCPStub() })
	gcpStubMu.Lock()
	defer gcpStubMu.Unlock()
	gcpStubPaths, gcpStubToks, gcpStubAuds, gcpStubReads = nil, nil, nil, nil
}

// newGCPServiceAccountKey builds a usable service-account key whose token_uri points
// at the stub, so the server performs a real signed JWT exchange against it when the
// static source is written.
func newGCPServiceAccountKey(t *testing.T, tokenURI string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal RSA key: %v", err)
	}

	encoded, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     gcpChainProject,
		"private_key_id": "e2e-key-id",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   gcpStaticSA,
		"token_uri":      tokenURI,
	})
	if err != nil {
		t.Fatalf("marshal SA key: %v", err)
	}
	return string(encoded)
}

// setupGCPChainedSpecs builds every chain this file drives over one stub: a declaring
// consumer per subject source, an undeclaring control, and a per-agent templated row.
// All drive the datadog mount, whose extractor turns each carried field into its own
// header.
//
// Order is load-bearing both ways. A spec naming a secret_spec that does not exist is
// refused at create, and a referenced spec cannot be deleted while a consumer names
// it, so cleanup runs consumer-first — which also clears anything a killed run left
// behind.
func setupGCPChainedSpecs(t *testing.T) {
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
		for _, role := range []string{gcpChainAgentRole, gcpChainWardenRole, gcpChainNoDeclRole, gcpChainTemplatedRole} {
			h.APIRequest(t, "DELETE", "auth/jwt/role/"+role, leaderPort, "")
		}
		for _, spec := range []string{gcpChainAgentSpec, gcpChainWardenSpec, gcpChainNoDeclSpec, gcpChainTemplatedSpec} {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		}
		for _, spec := range []string{gcpChainAgentSecretSpec, gcpChainWardenSecretSpec, gcpChainTemplatedSecret} {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		}
		for _, src := range []string{gcpChainSource, gcpChainNoDeclSource, gcpChainGCPSource} {
			h.APIRequest(t, "DELETE", "sys/cred/sources/"+src, leaderPort, "")
		}
	}
	clear()
	t.Cleanup(clear)

	// The keyless source. Both endpoint overrides point at the stub: the federation
	// leg and the fetch leg are separate calls, and a source redirecting only one
	// would reach the real service for the other.
	mustWrite("POST", "sys/cred/sources/"+gcpChainGCPSource, `{
		"type":"gcp","config":{
			"auth_method":"oidc_federation",
			"workload_identity_provider":"`+gcpChainWIFProvider+`",
			"sts_endpoint":"`+gcpStub.URL+`","secretmanager_endpoint":"`+gcpStub.URL+`"}}`,
		"create the keyless gcp source")

	// The referenced specs: the whole credential, read from one stored secret, once
	// per subject source. subject_token_source is not optional — a chained secret is
	// minted as the caller, and the store refuses the reference otherwise.
	for _, ref := range []struct{ name, subject string }{
		{gcpChainAgentSecretSpec, "agent_identity"},
		{gcpChainWardenSecretSpec, "warden_identity"},
	} {
		mustWrite("POST", "sys/cred/specs/"+ref.name, `{
			"type":"key_value","source":"`+gcpChainGCPSource+`","config":{
				"mint_method":"secret_read","secret_name":"`+gcpChainSecretName+`",
				"project":"`+gcpChainProject+`",
				"subject_token_source":"`+ref.subject+`"}}`,
			"create the referenced secret spec for "+ref.subject)
	}

	// The declaring source. api_key travels because it is the credential; the
	// application key travels because this names it.
	mustWrite("POST", "sys/cred/sources/"+gcpChainSource,
		`{"type":"apikey","config":{"credential_fields":"application_key"}}`,
		"create the declaring source")

	for _, row := range []struct{ spec, secretSpec, role string }{
		{gcpChainAgentSpec, gcpChainAgentSecretSpec, gcpChainAgentRole},
		{gcpChainWardenSpec, gcpChainWardenSecretSpec, gcpChainWardenRole},
	} {
		// The consuming spec holds no api_key: it is mutually exclusive with
		// secret_spec. secret_field is explicit — the fallback would find api_key by
		// name anyway, but a test should not lean on a fallback to choose the secret.
		mustWrite("POST", "sys/cred/specs/"+row.spec, `{
			"type":"api_key","source":"`+gcpChainSource+`","config":{
				"secret_spec":"`+row.secretSpec+`","secret_field":"api_key"}}`,
			"create the chained consuming spec "+row.spec)

		// The mount's own JWT agent role binds its default spec, so each row needs one
		// bound to its own chained spec instead.
		mustWrite("POST", "auth/jwt/role/"+row.role, `{
			"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+row.spec+`",
			"user_claim":"sub","token_ttl":3600}`,
			"create the agent role "+row.role)
	}

	// The control source, identical but for the missing declaration.
	mustWrite("POST", "sys/cred/sources/"+gcpChainNoDeclSource,
		`{"type":"apikey","config":{}}`,
		"create the undeclaring source")

	mustWrite("POST", "sys/cred/specs/"+gcpChainNoDeclSpec, `{
		"type":"api_key","source":"`+gcpChainNoDeclSource+`","config":{
			"secret_spec":"`+gcpChainAgentSecretSpec+`","secret_field":"api_key"}}`,
		"create the chained spec on the undeclaring source")

	mustWrite("POST", "auth/jwt/role/"+gcpChainNoDeclRole, `{
		"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+gcpChainNoDeclSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the undeclared agent role")

	// The per-agent row. {{agent.sub}} needs no assertion_metadata_claims entry — the
	// principal is not an opt-in disclosure, and it is already inside the cache
	// identity, so nothing can be served across agents.
	mustWrite("POST", "sys/cred/specs/"+gcpChainTemplatedSecret, `{
		"type":"key_value","source":"`+gcpChainGCPSource+`","config":{
			"mint_method":"secret_read","secret_name":"`+gcpChainTemplatedPrefix+`-{{agent.sub}}",
			"project":"`+gcpChainProject+`",
			"subject_token_source":"agent_identity"}}`,
		"create the templated secret spec")

	mustWrite("POST", "sys/cred/specs/"+gcpChainTemplatedSpec, `{
		"type":"api_key","source":"`+gcpChainSource+`","config":{
			"secret_spec":"`+gcpChainTemplatedSecret+`","secret_field":"api_key"}}`,
		"create the templated consuming spec")

	mustWrite("POST", "auth/jwt/role/"+gcpChainTemplatedRole, `{
		"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+gcpChainTemplatedSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the templated agent role")
}

// TestGCPSecretRead_ChainedCredentialCarriesItsDeclaredField is the row this file
// exists for: two secrets living in one stored payload, arriving as two upstream
// headers, with a gcp source at the far end of the chain.
//
// Both asserted values appear in no spec config anywhere, so the row fails if any link
// breaks: the token exchange, the secret read, the material reaching the consuming
// driver, the declaration surviving Parse, or the extractor.
func TestGCPSecretRead_ChainedCredentialCarriesItsDeclaredField(t *testing.T) {
	// A JWT agent leg rather than the usual certificate, because agent_identity
	// forwards the agent's own inbound token and there is none to forward on a
	// cert-authenticated request. warden_identity would tolerate a cert leg, but the
	// leg is per-mount, so both rows take the JWT one.
	for _, tc := range []struct{ subject, role string }{
		{"agent_identity", gcpChainAgentRole},
		{"warden_identity", gcpChainWardenRole},
	} {
		t.Run(tc.subject, func(t *testing.T) {
			ensureEnv(t)
			useJWTAgentLeg(t, datadogEnv)
			ensureGCPStub(t)
			setupGCPChainedSpecs(t)

			status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
				AgentToken: h.GetDefaultJWT(t),
				Role:       tc.role,
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status: 200,
				Injected: map[string]string{
					"DD-API-KEY":         gcpChainAPIKey,
					"DD-APPLICATION-KEY": gcpChainAppKey,
				},
				Absent:        h.AlwaysAbsent("Authorization"),
				UpstreamCalls: 1,
			})

			// The version default is part of the contract: an unpinned spec follows
			// rotation of the secret it names, which only shows as /versions/latest.
			paths, _, _, readers := gcpStubSeen()
			want := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", gcpChainProject, gcpChainSecretName)
			if len(paths) != 1 || paths[0] != want {
				t.Errorf("secret reads = %v, want exactly [%s]", paths, want)
			}
			// The read must be authorized by what the exchange returned, not by any
			// standing credential — a federated source holds none.
			if len(readers) != 1 || readers[0] != "e2e-federated-token" {
				t.Errorf("secret read authorized with %v, want the federated token", readers)
			}
		})
	}
}

// TestGCPSecretRead_WardenIdentityPresentsAMintedAssertion is the assertion-shape row.
// Under agent_identity the inbound JWT is forwarded untouched; under warden_identity
// Warden signs its own, and that is the only path where the audience and resource
// claims are derived at all.
func TestGCPSecretRead_WardenIdentityPresentsAMintedAssertion(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	ensureGCPStub(t)
	setupGCPChainedSpecs(t)

	agentJWT := h.GetDefaultJWT(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: agentJWT,
		Role:       gcpChainWardenRole,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": gcpChainAPIKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})

	_, tokens, auds, _ := gcpStubSeen()
	if len(tokens) != 1 {
		t.Fatalf("token exchanges = %d, want 1", len(tokens))
	}
	if tokens[0] == agentJWT {
		t.Fatal("warden_identity must present an assertion Warden minted, not the agent's inbound token")
	}

	claims := h.VerifyAssertion(t, leaderPort, tokens[0])
	if got := claims["aud"]; got != gcpChainAudience {
		t.Errorf("assertion aud = %v, want %s", got, gcpChainAudience)
	}
	if got, want := claims["warden_resource"], "gcp-secretmanager:"+gcpChainSecretName; got != want {
		t.Errorf("assertion warden_resource = %v, want %s", got, want)
	}

	// GCP spells the provider two ways: the assertion is addressed to the https form,
	// while STS is asked for the scheme-relative one. Only a full chain sees both
	// together, so only here can they be checked against each other.
	if len(auds) != 1 || auds[0] != gcpChainWIFProvider {
		t.Errorf("STS audience = %v, want %s", auds, gcpChainWIFProvider)
	}
}

// TestGCPSecretRead_ReferencedSecretCannotBeDeletedWhileConsumed pins the reference
// guard: the chain is only as good as the store's refusal to break it.
func TestGCPSecretRead_ReferencedSecretCannotBeDeletedWhileConsumed(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	ensureGCPStub(t)
	setupGCPChainedSpecs(t)

	status, resp := h.APIRequest(t, "DELETE", "sys/cred/specs/"+gcpChainAgentSecretSpec, leaderPort, "")
	if status < 400 {
		t.Fatalf("deleting a referenced secret spec returned %d, want a refusal", status)
	}
	if !strings.Contains(string(resp), "referenced") {
		t.Errorf("refusal should say the spec is referenced, got: %s", resp)
	}

	// The refusal must leave the chain intact, not half-dismantled.
	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       gcpChainAgentRole,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": gcpChainAPIKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}

// TestGCPSecretRead_UndeclaredPayloadFieldStaysInGCP is the control for the declared
// field. The same stored payload reaches the same extractor; only the source's
// declaration differs, so the application key must not travel.
func TestGCPSecretRead_UndeclaredPayloadFieldStaysInGCP(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	ensureGCPStub(t)
	setupGCPChainedSpecs(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       gcpChainNoDeclRole,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": gcpChainAPIKey},
		Absent:        h.AlwaysAbsent("Authorization", "DD-APPLICATION-KEY"),
		UpstreamCalls: 1,
	})
}

// TestGCPSecretRead_TemplatedSecretNameResolvesPerAgent drives a spec whose secret is
// named per caller. The stub derives its payload from the name it is asked for, so the
// header arriving upstream names the secret actually read — a template resolved to the
// wrong principal, or left unresolved, cannot produce this value.
func TestGCPSecretRead_TemplatedSecretNameResolvesPerAgent(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	ensureGCPStub(t)
	setupGCPChainedSpecs(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       gcpChainTemplatedRole,
	})

	resolved := gcpChainTemplatedPrefix + "-" + gcpChainAgentSub
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": "k-for-" + resolved},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})

	paths, _, _, _ := gcpStubSeen()
	want := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", gcpChainProject, resolved)
	if len(paths) != 1 || paths[0] != want {
		t.Errorf("secret reads = %v, want exactly [%s]", paths, want)
	}
}

// TestGCPSecretRead_StaticSourceReadsAsItself drives the other authentication mode.
//
// A static source can never be a chaining source — the store refuses a reference whose
// spec sets no subject_token_source — so this exercises it where it is actually
// reachable: writing the spec runs a real mint through the server, against the stub,
// with the source's own key. That covers the whole static path end to end, which
// nothing else here does.
func TestGCPSecretRead_StaticSourceReadsAsItself(t *testing.T) {
	ensureEnv(t)
	ensureGCPStub(t)

	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+gcpStaticSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+gcpStaticSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	saKey, err := json.Marshal(newGCPServiceAccountKey(t, gcpStub.URL+"/token"))
	if err != nil {
		t.Fatalf("encode SA key: %v", err)
	}

	// Writing the source performs its own credential probe against the stub's token
	// endpoint, so a source that could not authenticate would never be created.
	status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+gcpStaticSource, leaderPort, `{
		"type":"gcp","config":{
			"auth_method":"static",
			"service_account_key":`+string(saKey)+`,
			"secretmanager_endpoint":"`+gcpStub.URL+`"}}`)
	if status < 200 || status > 299 {
		t.Fatalf("create the static gcp source (status %d): %s", status, resp)
	}

	// Writing the spec test-mints it, which is the read this row is about.
	status, resp = h.APIRequest(t, "POST", "sys/cred/specs/"+gcpStaticSpec, leaderPort, `{
		"type":"key_value","source":"`+gcpStaticSource+`","config":{
			"mint_method":"secret_read","secret_name":"`+gcpStaticSecretName+`",
			"project":"`+gcpChainProject+`"}}`)
	if status < 200 || status > 299 {
		t.Fatalf("create the static secret spec (status %d): %s", status, resp)
	}

	paths, tokens, _, readers := gcpStubSeen()
	want := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", gcpChainProject, gcpStaticSecretName)
	if len(paths) != 1 || paths[0] != want {
		t.Fatalf("secret reads = %v, want exactly [%s]", paths, want)
	}
	// The whole point of the static mode: it reads as the source, with the token its
	// own key obtained, and never exchanges anything.
	if len(readers) != 1 || readers[0] != "e2e-static-source-token" {
		t.Errorf("secret read authorized with %v, want the source's own token", readers)
	}
	if len(tokens) != 0 {
		t.Errorf("a static source must not exchange a caller assertion, saw %d exchanges", len(tokens))
	}
}

// TestGCPSecretRead_StaticSourceRefusesImpersonation is the negative for the row
// above. Impersonation is authorized by the caller's own assertion, which a static
// source does not have; reading as the source instead would vend the secret under an
// authority the operator did not name, so the spec is refused when it is written.
func TestGCPSecretRead_StaticSourceRefusesImpersonation(t *testing.T) {
	ensureEnv(t)
	ensureGCPStub(t)

	const staticImpersonationSpec = "fc-gcp-static-impersonation"

	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+staticImpersonationSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+gcpStaticSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	saKey, err := json.Marshal(newGCPServiceAccountKey(t, gcpStub.URL+"/token"))
	if err != nil {
		t.Fatalf("encode SA key: %v", err)
	}

	status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+gcpStaticSource, leaderPort, `{
		"type":"gcp","config":{
			"auth_method":"static",
			"service_account_key":`+string(saKey)+`,
			"secretmanager_endpoint":"`+gcpStub.URL+`"}}`)
	if status < 200 || status > 299 {
		t.Fatalf("create the static gcp source (status %d): %s", status, resp)
	}

	status, resp = h.APIRequest(t, "POST", "sys/cred/specs/"+staticImpersonationSpec, leaderPort, `{
		"type":"key_value","source":"`+gcpStaticSource+`","config":{
			"mint_method":"secret_read","secret_name":"`+gcpStaticSecretName+`",
			"project":"`+gcpChainProject+`",
			"target_service_account":"reader@e2e-proj.iam.gserviceaccount.com"}}`)
	if status < 400 {
		t.Fatalf("a static spec naming target_service_account returned %d, want a refusal", status)
	}
	if !strings.Contains(string(resp), "target_service_account") {
		t.Errorf("refusal should name target_service_account, got: %s", resp)
	}
}
