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

// Credential chaining with an Azure source. The aws and gcp suites alongside this one
// drive the same shape over Secrets Manager and Secret Manager; this one exists
// because Key Vault reads through a leg of its own — an Entra client_assertion grant
// for a Key Vault token — and because the vault is the request's host, so what the
// spec names decides where the token goes.
//
// What only a full chain shows: the reference resolving to a real token grant and a
// real secret read, the payload reaching MintFromSecret, the source's declaration
// surviving Parse, and the declared field arriving as an upstream header. Each is
// covered alone in the driver and store tests.
//
// Why the chaining source must be keyless: a referenced spec is minted as the
// session-pinned caller, which forces the exchange path, which an azure source
// serves only under auth_method=oidc_federation.
//
// Both subject sources are driven. Under agent_identity the agent's own inbound JWT
// is presented to Entra and Warden signs nothing; under warden_identity Warden mints
// an assertion, and a new azure spec that does so is stored with
// assertion_profile=minimal — the registered claims only, since Entra binds iss/sub/aud
// and nothing else. Both shapes are checked: the defaulted minimal, and default as
// the opt-out.
//
// The static path is driven too, on its own source. It can never be a chaining source
// — the store refuses a reference whose spec sets no subject_token_source — so it is
// exercised where it is actually reachable: the test-mint a spec write performs.

const (
	// The secret the stub holds. Nothing in any spec config carries these values —
	// they exist only inside the stub's payload — so an assertion on them can only
	// pass if the whole chain ran.
	azkvSecretName = "e2e-datadog-keys"
	azkvAPIKey     = "e2e-dd-azure-not-a-real-key"
	azkvAppKey     = "e2e-dd-azure-not-a-real-app-key"
	azkvVersion    = "0123456789abcdef0123456789abcdef"
	azkvForbidden  = "e2e-forbidden"

	// The vault the specs name. With the endpoint override every read reaches the
	// stub, but the name is still validated and still named in warden_resource.
	azkvVault = "e2e-kv"

	// Deliberately not shaped like real Entra identifiers beyond what validation
	// demands, so a secret scanner has nothing to catch.
	azkvTenant       = "00000000-0000-0000-0000-0000000000e2"
	azkvClient       = "11111111-1111-1111-1111-1111111111e2"
	azkvStaticClient = "22222222-2222-2222-2222-2222222222e2"
	azkvStaticKeyID  = "33333333-3333-3333-3333-3333333333e2"
	azkvStaticSecret = "e2e-azure-not-a-real-client-secret"

	// Every resource here is test-local, the sources included: a killed run skips
	// t.Cleanup, and a leftover consumer spec would block its source from being
	// deleted, which the next run's setup cannot recover from.
	azkvFedSource    = "fc-azkv-fed"
	azkvChainSource  = "fc-azkv-chain-src"
	azkvNoDeclSource = "fc-azkv-nodecl-src"

	// The declaring chain, per subject source and profile.
	azkvAgentSecretSpec   = "fc-azkv-keys-agent"
	azkvAgentSpec         = "fc-azkv-cred-agent"
	azkvAgentRole         = "fc-azkv-role-agent"
	azkvWardenSecretSpec  = "fc-azkv-keys-warden"
	azkvWardenSpec        = "fc-azkv-cred-warden"
	azkvWardenRole        = "fc-azkv-role-warden"
	azkvDefaultSecretSpec = "fc-azkv-keys-default"
	azkvDefaultSpec       = "fc-azkv-cred-default"
	azkvDefaultRole       = "fc-azkv-role-default"

	// The control: same stub secret, same referenced spec, a source declaring nothing.
	azkvNoDeclSpec = "fc-azkv-nodecl-cred"
	azkvNoDeclRole = "fc-azkv-nodecl-role"

	// The per-agent row. No underscore or dot in the prefix: a Key Vault secret name
	// admits only letters, digits and hyphens.
	azkvTemplatedPrefix = "e2e-per-agent"
	azkvTemplatedSecret = "fc-azkv-tmpl-keys"
	azkvTemplatedSpec   = "fc-azkv-tmpl-cred"
	azkvTemplatedRole   = "fc-azkv-tmpl-role"

	// The pinned-version and upstream-refusal rows.
	azkvPinnedSecret    = "fc-azkv-pinned-keys"
	azkvPinnedSpec      = "fc-azkv-pinned-cred"
	azkvPinnedRole      = "fc-azkv-pinned-role"
	azkvForbiddenSecret = "fc-azkv-forbidden-keys"
	azkvForbiddenSpec   = "fc-azkv-forbidden-cred"
	azkvForbiddenRole   = "fc-azkv-forbidden-role"

	// The static path.
	azkvStaticSource = "fc-azkv-static-src"
	azkvStaticSpec   = "fc-azkv-static-keys"

	// The subject the default JWT carries, and so what {{agent.sub}} resolves to.
	azkvAgentSub = "e2e-agent"

	// The audience an Entra federated identity credential expects, which the
	// assertion is minted with when the source names none.
	azkvAudience = "api://AzureADTokenExchange"
)

// azkvStub stands in for Entra's token endpoint and Key Vault. Both are overridable
// in azure source config (login_endpoint, key_vault_endpoint), so one in-process
// listener serves the whole read: the token grant, then the secret GET authorized
// with what it returned.
var azkvStub *httptest.Server

// azkvGrant is one recorded token request.
type azkvGrant struct {
	Tenant       string
	ClientID     string
	Scope        string
	Assertion    string
	AssertionTyp string
	HasSecret    bool
}

// azkvRead is one recorded secret read.
type azkvRead struct {
	Path       string
	APIVersion string
	Bearer     string
}

var (
	azkvStubOnce sync.Once
	azkvStubMu   sync.Mutex
	azkvGrants   []azkvGrant
	azkvReads    []azkvRead
)

func azkvSeen() ([]azkvGrant, []azkvRead) {
	azkvStubMu.Lock()
	defer azkvStubMu.Unlock()
	return append([]azkvGrant(nil), azkvGrants...), append([]azkvRead(nil), azkvReads...)
}

// azkvSecretValue is what the stub holds for a secret. The fixed name carries the
// values the declared-field rows assert; any other name — the templated row — gets a
// payload derived from it, so the header arriving upstream names the secret read.
func azkvSecretValue(name string) string {
	apiKey, appKey := azkvAPIKey, azkvAppKey
	if name != azkvSecretName {
		apiKey, appKey = "k-for-"+name, "app-for-"+name
	}
	out, _ := json.Marshal(map[string]string{"api_key": apiKey, "application_key": appKey})
	return string(out)
}

func startAzureKeyVaultStub() *httptest.Server {
	mux := http.NewServeMux()

	// The Entra token endpoint, /{tenant}/oauth2/v2.0/token. A federated grant
	// presents a client_assertion; a static one a client_secret. Which arrived is
	// recorded, and answered with a token that says so, so a read can be traced
	// back to the grant that authorized it.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tenant, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if !ok || rest != "oauth2/v2.0/token" || r.Method != http.MethodPost {
			http.Error(w, "unexpected call "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		grant := azkvGrant{
			Tenant:       tenant,
			ClientID:     r.PostForm.Get("client_id"),
			Scope:        r.PostForm.Get("scope"),
			Assertion:    r.PostForm.Get("client_assertion"),
			AssertionTyp: r.PostForm.Get("client_assertion_type"),
			HasSecret:    r.PostForm.Has("client_secret"),
		}
		azkvStubMu.Lock()
		azkvGrants = append(azkvGrants, grant)
		azkvStubMu.Unlock()

		token := "e2e-static-source-token"
		if grant.Assertion != "" {
			token = "e2e-federated-token"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
	})

	// Key Vault: GET /secrets/{name}[/{version}]. Everything else 400s, so a call
	// reaching an endpoint this test did not mean to exercise fails loudly.
	mux.HandleFunc("/secrets/", func(w http.ResponseWriter, r *http.Request) {
		azkvStubMu.Lock()
		azkvReads = append(azkvReads, azkvRead{
			Path:       r.URL.Path,
			APIVersion: r.URL.Query().Get("api-version"),
			Bearer:     strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		})
		azkvStubMu.Unlock()

		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/secrets/"), "/")
		if r.Method != http.MethodGet || len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
			http.Error(w, "malformed secret path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		name := parts[0]
		if name == azkvForbidden {
			http.Error(w, `{"error":{"code":"Forbidden","message":"The user, group or application does not have secrets get permission"}}`, http.StatusForbidden)
			return
		}
		version := azkvVersion
		if len(parts) == 2 {
			version = parts[1]
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value":      azkvSecretValue(name),
			"id":         "https://" + azkvVault + ".vault.azure.net/secrets/" + name + "/" + version,
			"attributes": map[string]any{"enabled": true},
		})
	})

	return httptest.NewServer(mux)
}

// ensureAzureKeyVaultStub starts the listener on first use and clears what it
// recorded, so each row counts only its own traffic.
func ensureAzureKeyVaultStub(t *testing.T) {
	t.Helper()
	azkvStubOnce.Do(func() { azkvStub = startAzureKeyVaultStub() })
	azkvStubMu.Lock()
	defer azkvStubMu.Unlock()
	azkvGrants, azkvReads = nil, nil
}

// setupAzureKeyVaultChainedSpecs builds every chain this file drives over one stub,
// all on the datadog mount, whose extractor turns each carried field into its own
// header.
//
// Order is load-bearing both ways. A spec naming a secret_spec that does not exist is
// refused at create, and a referenced spec cannot be deleted while a consumer names
// it, so cleanup runs consumer-first — which also clears anything a killed run left
// behind.
func setupAzureKeyVaultChainedSpecs(t *testing.T) {
	t.Helper()

	mustWrite := func(method, path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	roles := []string{azkvAgentRole, azkvWardenRole, azkvDefaultRole, azkvNoDeclRole, azkvTemplatedRole, azkvPinnedRole, azkvForbiddenRole}
	consumers := []string{azkvAgentSpec, azkvWardenSpec, azkvDefaultSpec, azkvNoDeclSpec, azkvTemplatedSpec, azkvPinnedSpec, azkvForbiddenSpec}
	referenced := []string{azkvAgentSecretSpec, azkvWardenSecretSpec, azkvDefaultSecretSpec, azkvTemplatedSecret, azkvPinnedSecret, azkvForbiddenSecret}
	clear := func() {
		for _, role := range roles {
			h.APIRequest(t, "DELETE", "auth/jwt/role/"+role, leaderPort, "")
		}
		for _, spec := range append(append([]string{}, consumers...), referenced...) {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		}
		for _, src := range []string{azkvChainSource, azkvNoDeclSource, azkvFedSource} {
			h.APIRequest(t, "DELETE", "sys/cred/sources/"+src, leaderPort, "")
		}
	}
	clear()
	t.Cleanup(clear)

	// The keyless source. Both overrides point at the stub: the token grant and the
	// secret read are separate calls, and a source redirecting only one would reach
	// the real service for the other.
	mustWrite("POST", "sys/cred/sources/"+azkvFedSource, `{
		"type":"azure","config":{
			"auth_method":"oidc_federation",
			"login_endpoint":"`+azkvStub.URL+`","key_vault_endpoint":"`+azkvStub.URL+`"}}`,
		"create the keyless azure source")

	// The referenced specs: the whole credential, read from one stored secret.
	// subject_token_source is not optional — a chained secret is minted as the
	// caller, and the store refuses the reference otherwise. The warden_identity row
	// names no assertion_profile, so it is stored with the defaulted minimal; the
	// default row opts out explicitly.
	for _, ref := range []struct{ name, secret, subject, extra string }{
		{azkvAgentSecretSpec, azkvSecretName, "agent_identity", ""},
		{azkvWardenSecretSpec, azkvSecretName, "warden_identity", ""},
		{azkvDefaultSecretSpec, azkvSecretName, "warden_identity", `,"assertion_profile":"default"`},
		{azkvTemplatedSecret, azkvTemplatedPrefix + "-{{agent.sub}}", "agent_identity", ""},
		{azkvPinnedSecret, azkvSecretName, "agent_identity", `,"secret_version":"` + azkvVersion + `"`},
		{azkvForbiddenSecret, azkvForbidden, "agent_identity", ""},
	} {
		mustWrite("POST", "sys/cred/specs/"+ref.name, `{
			"type":"key_value","source":"`+azkvFedSource+`","config":{
				"mint_method":"secret_read","vault_name":"`+azkvVault+`",
				"secret_name":"`+ref.secret+`",
				"tenant_id":"`+azkvTenant+`","client_id":"`+azkvClient+`",
				"subject_token_source":"`+ref.subject+`"`+ref.extra+`}}`,
			"create the referenced secret spec "+ref.name)
	}

	// The declaring source. api_key travels because it is the credential; the
	// application key travels because this names it.
	mustWrite("POST", "sys/cred/sources/"+azkvChainSource,
		`{"type":"apikey","config":{"credential_fields":"application_key"}}`,
		"create the declaring source")
	mustWrite("POST", "sys/cred/sources/"+azkvNoDeclSource,
		`{"type":"apikey","config":{}}`,
		"create the undeclaring source")

	for _, row := range []struct{ spec, secretSpec, source, role string }{
		{azkvAgentSpec, azkvAgentSecretSpec, azkvChainSource, azkvAgentRole},
		{azkvWardenSpec, azkvWardenSecretSpec, azkvChainSource, azkvWardenRole},
		{azkvDefaultSpec, azkvDefaultSecretSpec, azkvChainSource, azkvDefaultRole},
		{azkvNoDeclSpec, azkvAgentSecretSpec, azkvNoDeclSource, azkvNoDeclRole},
		{azkvTemplatedSpec, azkvTemplatedSecret, azkvChainSource, azkvTemplatedRole},
		{azkvPinnedSpec, azkvPinnedSecret, azkvChainSource, azkvPinnedRole},
		{azkvForbiddenSpec, azkvForbiddenSecret, azkvChainSource, azkvForbiddenRole},
	} {
		// The consuming spec holds no api_key: it is mutually exclusive with
		// secret_spec. secret_field is explicit rather than left to the fallback.
		mustWrite("POST", "sys/cred/specs/"+row.spec, `{
			"type":"api_key","source":"`+row.source+`","config":{
				"secret_spec":"`+row.secretSpec+`","secret_field":"api_key"}}`,
			"create the chained consuming spec "+row.spec)

		// The mount's own JWT agent role binds its default spec, so each row needs
		// one bound to its own chained spec instead.
		mustWrite("POST", "auth/jwt/role/"+row.role, `{
			"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+row.spec+`",
			"user_claim":"sub","token_ttl":3600}`,
			"create the agent role "+row.role)
	}
}

// azkvChain drives one request through the datadog mount under role.
func azkvChain(t *testing.T, role string) (int, []byte) {
	t.Helper()
	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       role,
	})
	return status, body
}

func azkvSetup(t *testing.T) {
	t.Helper()
	ensureEnv(t)
	// A JWT agent leg rather than the usual certificate: agent_identity forwards the
	// agent's own inbound token, and there is none on a cert-authenticated request.
	useJWTAgentLeg(t, datadogEnv)
	ensureAzureKeyVaultStub(t)
	setupAzureKeyVaultChainedSpecs(t)
}

// TestAzureKeyVault_ChainedCredentialCarriesItsDeclaredField is the row this file
// exists for: two secrets living in one Key Vault payload, arriving as two upstream
// headers, with an azure source at the far end of the chain.
func TestAzureKeyVault_ChainedCredentialCarriesItsDeclaredField(t *testing.T) {
	for _, tc := range []struct{ subject, role string }{
		{"agent_identity", azkvAgentRole},
		{"warden_identity", azkvWardenRole},
	} {
		t.Run(tc.subject, func(t *testing.T) {
			azkvSetup(t)

			agentJWT := h.GetDefaultJWT(t)
			status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{AgentToken: agentJWT, Role: tc.role})
			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status: 200,
				Injected: map[string]string{
					"DD-API-KEY":         azkvAPIKey,
					"DD-APPLICATION-KEY": azkvAppKey,
				},
				Absent:        h.AlwaysAbsent("Authorization"),
				UpstreamCalls: 1,
			})

			grants, reads := azkvSeen()
			if len(reads) != 1 || reads[0].Path != "/secrets/"+azkvSecretName || reads[0].APIVersion != "7.4" {
				t.Errorf("secret reads = %+v, want exactly one unpinned read of %s at api-version 7.4", reads, azkvSecretName)
			}
			// The read must be authorized by what the grant returned, not by any
			// standing credential — a federated source holds none.
			if len(reads) == 1 && reads[0].Bearer != "e2e-federated-token" {
				t.Errorf("secret read authorized with %q, want the federated token", reads[0].Bearer)
			}
			if len(grants) != 1 {
				t.Fatalf("token grants = %d, want 1", len(grants))
			}
			g := grants[0]
			if g.HasSecret || g.Assertion == "" || g.AssertionTyp != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
				t.Errorf("grant must present a client_assertion and no client_secret, got %+v", g)
			}
			if g.Tenant != azkvTenant || g.ClientID != azkvClient || g.Scope != "https://vault.azure.net/.default" {
				t.Errorf("grant = %+v, want the spec's tenant and app, for the Key Vault scope", g)
			}
			// agent_identity forwards the agent's own token untouched; warden_identity
			// presents one Warden minted, checked in the assertion-shape row.
			if tc.subject == "agent_identity" && g.Assertion != agentJWT {
				t.Error("agent_identity must present the agent's own inbound JWT as the client_assertion")
			}
			if tc.subject == "warden_identity" && g.Assertion == agentJWT {
				t.Error("warden_identity must present an assertion Warden minted, not the agent's inbound token")
			}
		})
	}
}

// TestAzureKeyVault_WardenIdentityPresentsAMintedAssertion is the assertion-shape row.
// A new azure spec minting an assertion is stored with assertion_profile=minimal, and
// presents the registered claims only; a spec opting out with default presents the
// warden_* claims, warden_resource naming the vault and secret among them.
func TestAzureKeyVault_WardenIdentityPresentsAMintedAssertion(t *testing.T) {
	t.Run("minimal (defaulted)", func(t *testing.T) {
		azkvSetup(t)

		status, resp := h.APIRequest(t, "GET", "sys/cred/specs/"+azkvWardenSecretSpec, leaderPort, "")
		if status != 200 {
			t.Fatalf("read the referenced spec (status %d): %s", status, resp)
		}
		if got := h.JSONPath(h.ParseJSON(t, resp), "data.config.assertion_profile"); got != "minimal" {
			t.Errorf("stored assertion_profile = %v, want the defaulted minimal", got)
		}

		agentJWT := h.GetDefaultJWT(t)
		status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{AgentToken: agentJWT, Role: azkvWardenRole})
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"DD-API-KEY": azkvAPIKey},
			Absent:        h.AlwaysAbsent("Authorization"),
			UpstreamCalls: 1,
		})

		grants, _ := azkvSeen()
		if len(grants) != 1 {
			t.Fatalf("token grants = %d, want 1", len(grants))
		}
		if grants[0].Assertion == agentJWT {
			t.Fatal("warden_identity must present an assertion Warden minted, not the agent's inbound token")
		}

		claims := h.VerifyAssertion(t, leaderPort, grants[0].Assertion)
		if got := claims["aud"]; got != azkvAudience {
			t.Errorf("assertion aud = %v, want %s", got, azkvAudience)
		}
		if sub, _ := claims["sub"].(string); !strings.HasPrefix(sub, "wid:") {
			t.Errorf("assertion sub = %v, want the composite wid: subject", claims["sub"])
		}
		want := map[string]bool{"iss": true, "sub": true, "aud": true, "iat": true, "nbf": true, "exp": true, "jti": true}
		for claim := range claims {
			if !want[claim] {
				t.Errorf("minimal assertion carries %q; it must carry the registered claims only", claim)
			}
		}
		if len(claims) != len(want) {
			t.Errorf("minimal assertion has %d claims, want %d", len(claims), len(want))
		}
	})

	t.Run("default (opt-out)", func(t *testing.T) {
		azkvSetup(t)

		status, body := azkvChain(t, azkvDefaultRole)
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"DD-API-KEY": azkvAPIKey},
			Absent:        h.AlwaysAbsent("Authorization"),
			UpstreamCalls: 1,
		})

		grants, _ := azkvSeen()
		if len(grants) != 1 {
			t.Fatalf("token grants = %d, want 1", len(grants))
		}
		claims := h.VerifyAssertion(t, leaderPort, grants[0].Assertion)
		if got, want := claims["warden_resource"], "azure-keyvault:"+azkvVault+"/"+azkvSecretName; got != want {
			t.Errorf("assertion warden_resource = %v, want %s", got, want)
		}
		if _, ok := claims["warden_sub"]; !ok {
			t.Error("the default profile must still carry the warden_* claims")
		}
	})
}

// TestAzureKeyVault_ReferencedSecretCannotBeDeletedWhileConsumed pins the reference
// guard: the chain is only as good as the store's refusal to break it.
func TestAzureKeyVault_ReferencedSecretCannotBeDeletedWhileConsumed(t *testing.T) {
	azkvSetup(t)

	status, resp := h.APIRequest(t, "DELETE", "sys/cred/specs/"+azkvAgentSecretSpec, leaderPort, "")
	if status < 400 {
		t.Fatalf("deleting a referenced secret spec returned %d, want a refusal", status)
	}
	if !strings.Contains(string(resp), "referenced") {
		t.Errorf("refusal should say the spec is referenced, got: %s", resp)
	}

	status, body := azkvChain(t, azkvAgentRole)
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": azkvAPIKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}

// TestAzureKeyVault_UndeclaredPayloadFieldStaysInKeyVault is the control for the
// declared field: the same payload reaches the same extractor, only the source's
// declaration differs, so the application key must not travel.
func TestAzureKeyVault_UndeclaredPayloadFieldStaysInKeyVault(t *testing.T) {
	azkvSetup(t)

	status, body := azkvChain(t, azkvNoDeclRole)
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": azkvAPIKey},
		Absent:        h.AlwaysAbsent("Authorization", "DD-APPLICATION-KEY"),
		UpstreamCalls: 1,
	})
}

// TestAzureKeyVault_TemplatedSecretNameResolvesPerAgent drives a spec whose secret is
// named per caller. The stub derives its payload from the name it is asked for, so a
// template resolved to the wrong principal, or left unresolved, cannot produce the
// value that arrives upstream.
func TestAzureKeyVault_TemplatedSecretNameResolvesPerAgent(t *testing.T) {
	azkvSetup(t)

	status, body := azkvChain(t, azkvTemplatedRole)
	resolved := azkvTemplatedPrefix + "-" + azkvAgentSub
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": "k-for-" + resolved},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})

	_, reads := azkvSeen()
	if len(reads) != 1 || reads[0].Path != "/secrets/"+resolved {
		t.Errorf("secret reads = %+v, want exactly /secrets/%s", reads, resolved)
	}
}

// TestAzureKeyVault_PinnedVersionReadsThatVersion: a pinned spec reads the version it
// names rather than following the current one.
func TestAzureKeyVault_PinnedVersionReadsThatVersion(t *testing.T) {
	azkvSetup(t)

	status, body := azkvChain(t, azkvPinnedRole)
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": azkvAPIKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})

	_, reads := azkvSeen()
	if want := "/secrets/" + azkvSecretName + "/" + azkvVersion; len(reads) != 1 || reads[0].Path != want {
		t.Errorf("secret reads = %+v, want exactly %s", reads, want)
	}
}

// TestAzureKeyVault_UpstreamRefusalAnswers403: Key Vault refusing the read stops the
// chain before the upstream, and the caller is told it was refused — a 403, as for
// any mint the upstream refuses — rather than a generic server error. The status
// survives two layers of wrapping: the Key Vault read, then the chained fetch.
func TestAzureKeyVault_UpstreamRefusalAnswers403(t *testing.T) {
	azkvSetup(t)

	status, body := azkvChain(t, azkvForbiddenRole)
	if status != http.StatusForbidden {
		t.Fatalf("a refused Key Vault read answered %d, want 403 (body: %s)", status, body)
	}
	if calls := len(upstream.Requests()); calls != 0 {
		t.Errorf("upstream received %d requests after a refused read, want 0", calls)
	}
	// A 403 alone would also come from Entra refusing the grant, or a policy
	// denial. Pin that it was Key Vault's refusal: one grant, then the refused read.
	grants, reads := azkvSeen()
	if len(grants) != 1 || len(reads) != 1 || reads[0].Path != "/secrets/"+azkvForbidden {
		t.Errorf("grants=%+v reads=%+v, want one grant and one refused read of %s", grants, reads, azkvForbidden)
	}
}

// TestAzureKeyVault_StaticSourceReadsAsItself drives the other authentication mode.
//
// A static source can never be a chaining source — the store refuses a reference
// whose spec sets no subject_token_source — so this exercises it where it is
// reachable: writing the source probes the stub's token endpoint, and writing the spec
// test-mints it, running the whole read through the server with the source's own
// credentials.
func TestAzureKeyVault_StaticSourceReadsAsItself(t *testing.T) {
	ensureEnv(t)
	ensureAzureKeyVaultStub(t)

	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+azkvStaticSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+azkvStaticSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+azkvStaticSource, leaderPort, `{
		"type":"azure","config":{
			"auth_method":"static",
			"tenant_id":"`+azkvTenant+`","client_id":"`+azkvStaticClient+`",
			"client_secret":"`+azkvStaticSecret+`","secret_id":"`+azkvStaticKeyID+`",
			"login_endpoint":"`+azkvStub.URL+`","key_vault_endpoint":"`+azkvStub.URL+`"}}`)
	if status < 200 || status > 299 {
		t.Fatalf("create the static azure source (status %d): %s", status, resp)
	}

	status, resp = h.APIRequest(t, "POST", "sys/cred/specs/"+azkvStaticSpec, leaderPort, `{
		"type":"key_value","source":"`+azkvStaticSource+`","config":{
			"mint_method":"secret_read","vault_name":"`+azkvVault+`","secret_name":"`+azkvSecretName+`"}}`)
	if status < 200 || status > 299 {
		t.Fatalf("create the static secret spec (status %d): %s", status, resp)
	}

	grants, reads := azkvSeen()
	if len(reads) != 1 || reads[0].Path != "/secrets/"+azkvSecretName {
		t.Fatalf("secret reads = %+v, want exactly one read of %s", reads, azkvSecretName)
	}
	// The whole point of the static mode: it reads as the source, with the token its
	// own secret obtained, and never presents an assertion.
	if reads[0].Bearer != "e2e-static-source-token" {
		t.Errorf("secret read authorized with %q, want the source's own token", reads[0].Bearer)
	}
	// Every driver built for the source probes for a management token when it is
	// created — the source write builds one, the spec's test-mint another — so the
	// probe count is the server's business. What this row pins is one Key Vault
	// grant, and that every grant, probe or read, is the source's own secret.
	var kvGrants int
	for _, g := range grants {
		if g.Assertion != "" || !g.HasSecret || g.ClientID != azkvStaticClient {
			t.Errorf("a static source must grant with its own client_secret only, got %+v", g)
		}
		switch g.Scope {
		case "https://vault.azure.net/.default":
			kvGrants++
		case "https://management.azure.com/.default":
		default:
			t.Errorf("unexpected grant scope %q", g.Scope)
		}
	}
	if kvGrants != 1 {
		t.Errorf("Key Vault-scope grants = %d, want exactly 1 (grants: %+v)", kvGrants, grants)
	}
}

// TestAzureKeyVault_StaticSpecRefusesFederationIdentity is the negative for the row
// above. A static source reads as itself; an app named on its spec would be accepted
// and never used — a spec that appears to read as one identity while reading as
// another — so it is refused where it is written.
func TestAzureKeyVault_StaticSpecRefusesFederationIdentity(t *testing.T) {
	ensureEnv(t)
	ensureAzureKeyVaultStub(t)

	const staticIdentitySpec = "fc-azkv-static-identity"
	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+staticIdentitySpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+azkvStaticSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+azkvStaticSource, leaderPort, `{
		"type":"azure","config":{
			"auth_method":"static",
			"tenant_id":"`+azkvTenant+`","client_id":"`+azkvStaticClient+`",
			"client_secret":"`+azkvStaticSecret+`","secret_id":"`+azkvStaticKeyID+`",
			"login_endpoint":"`+azkvStub.URL+`","key_vault_endpoint":"`+azkvStub.URL+`"}}`)
	if status < 200 || status > 299 {
		t.Fatalf("create the static azure source (status %d): %s", status, resp)
	}

	status, resp = h.APIRequest(t, "POST", "sys/cred/specs/"+staticIdentitySpec, leaderPort, `{
		"type":"key_value","source":"`+azkvStaticSource+`","config":{
			"mint_method":"secret_read","vault_name":"`+azkvVault+`","secret_name":"`+azkvSecretName+`",
			"client_id":"`+azkvClient+`"}}`)
	if status < 400 {
		t.Fatalf("a static spec naming client_id returned %d, want a refusal", status)
	}
	if !strings.Contains(string(resp), "a static source reads as itself") {
		t.Errorf("refusal should explain the static source reads as itself, got: %s", resp)
	}
	if _, reads := azkvSeen(); len(reads) != 0 {
		t.Errorf("a refused spec must not read anything, saw %+v", reads)
	}
}

// TestAzureKeyVault_WriteTimeRefusals pins the configurations refused where they are
// written, each naming what is wrong. Every one would otherwise be accepted and then
// fail at mint — or, for the hostile vault name, send a Key Vault token elsewhere.
func TestAzureKeyVault_WriteTimeRefusals(t *testing.T) {
	ensureEnv(t)
	ensureAzureKeyVaultStub(t)

	const (
		refusalSource = "fc-azkv-refusal-src"
		refusalSpec   = "fc-azkv-refusal-spec"
		refusalStatic = "fc-azkv-refusal-static"
	)
	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+refusalSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+refusalSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+refusalStatic, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	if status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+refusalSource, leaderPort, `{
		"type":"azure","config":{"auth_method":"oidc_federation",
			"login_endpoint":"`+azkvStub.URL+`","key_vault_endpoint":"`+azkvStub.URL+`"}}`); status < 200 || status > 299 {
		t.Fatalf("create the refusal source (status %d): %s", status, resp)
	}

	fedKV := func(extra string) string {
		return `{"type":"key_value","source":"` + refusalSource + `","config":{
			"mint_method":"secret_read","vault_name":"` + azkvVault + `","secret_name":"` + azkvSecretName + `",
			"tenant_id":"` + azkvTenant + `","client_id":"` + azkvClient + `",
			"subject_token_source":"agent_identity"` + extra + `}}`
	}
	fedBearer := func(extra string) string {
		return `{"type":"azure_bearer_token","source":"` + refusalSource + `","config":{
			"mint_method":"bearer_token","tenant_id":"` + azkvTenant + `","client_id":"` + azkvClient + `",
			"subject_token_source":"warden_identity"` + extra + `}}`
	}

	for _, tc := range []struct {
		name, body, want string
	}{
		{"hostile vault name", strings.Replace(fedKV(""), `"vault_name":"`+azkvVault+`"`, `"vault_name":"evil.example/x#"`, 1), "vault_name"},
		{"templated vault name", strings.Replace(fedKV(""), `"vault_name":"`+azkvVault+`"`, `"vault_name":"kv-{{agent.sub}}"`, 1), "does not support claim templates"},
		{"secret name outside Key Vault's charset", strings.Replace(fedKV(""), `"secret_name":"`+azkvSecretName+`"`, `"secret_name":"a/b"`, 1), "secret_name"},
		{"client_secret on a key_value spec", fedKV(`,"client_secret":"s"`), "client_secret"},
		{"secret_version that is not a Key Vault version", fedKV(`,"secret_version":"3"`), "secret_version"},
		{"the retired key_vault_secret method", strings.Replace(fedBearer(""), `"mint_method":"bearer_token"`, `"mint_method":"key_vault_secret"`, 1), "no longer supported"},
		{"scopes on a bearer token spec", fedBearer(`,"scopes":"https://graph.microsoft.com/.default"`), "scopes"},
		{"explicit resource under the defaulted minimal profile", fedBearer(`,"assertion_resource":"azure:https://management.azure.com/"`), "defaulted to 'minimal'"},
		{"unimplemented azure_db_iam_token", `{"type":"db_auth_token","source":"` + refusalSource + `","config":{
			"mint_method":"azure_db_iam_token","db_host":"db.postgres.database.azure.com","db_user":"app"}}`, "not implemented"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, resp := h.APIRequest(t, "POST", "sys/cred/specs/"+refusalSpec, leaderPort, tc.body)
			if status < 400 {
				h.APIRequest(t, "DELETE", "sys/cred/specs/"+refusalSpec, leaderPort, "")
				t.Fatalf("status %d, want a refusal: %s", status, resp)
			}
			if !strings.Contains(string(resp), tc.want) {
				t.Errorf("refusal should name %q, got: %s", tc.want, resp)
			}
		})
	}

	// Source-level refusals: a rotation period with an endpoint override (rotation
	// writes to the real tenant through Graph, which the override does not redirect),
	// an endpoint carrying a query, and a malformed activation delay.
	staticSource := func(extraConfig, extraTop string) string {
		return `{"type":"azure","config":{"auth_method":"static",
			"tenant_id":"` + azkvTenant + `","client_id":"` + azkvStaticClient + `",
			"client_secret":"` + azkvStaticSecret + `","secret_id":"` + azkvStaticKeyID + `",
			"login_endpoint":"` + azkvStub.URL + `"` + extraConfig + `}` + extraTop + `}`
	}
	for _, tc := range []struct {
		name, body, want string
	}{
		{"rotation with an endpoint override", staticSource("", `,"rotation_period":"720h"`), "login_endpoint"},
		{"endpoint with a query", strings.Replace(staticSource("", ""), `"login_endpoint":"`+azkvStub.URL+`"`, `"login_endpoint":"`+azkvStub.URL+`/?x=1"`, 1), "query"},
		{"malformed activation delay", staticSource(`,"activation_delay":"5 minutes"`, ""), "activation_delay"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+refusalStatic, leaderPort, tc.body)
			if status < 400 {
				h.APIRequest(t, "DELETE", "sys/cred/sources/"+refusalStatic, leaderPort, "")
				t.Fatalf("status %d, want a refusal: %s", status, resp)
			}
			if !strings.Contains(string(resp), tc.want) {
				t.Errorf("refusal should name %q, got: %s", tc.want, resp)
			}
		})
	}

	// The keyless read's grant and read never reached the stub from any of these.
	if _, reads := azkvSeen(); len(reads) != 0 {
		t.Errorf("a refused spec must not read anything, saw %+v", reads)
	}
}
