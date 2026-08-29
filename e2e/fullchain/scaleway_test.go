//go:build e2e

package fullchain

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// scaleway is the first of the four dual-mode gateways in this package —
// providers that serve a REST API and an S3-compatible object store from one
// mount, detecting which per request. Two things make them worth rows of their
// own.
//
// They were unreachable by this suite until the config apply path was fixed: the
// upstream URL could only be set at mount time, the agent leg only by a later
// config write, and that write reset every key it did not name. There was no
// order that configured both.
//
// And scaleway is the one that authenticates with a header other than
// Authorization, which is why the inbound-Authorization row lives here.

// No vendor prefix — see the note in openai_test.go.
const (
	scalewayAccessKey = "SCWFCNOTAREALKEY0000"
	scalewaySecretKey = "fc-scaleway-not-a-real-secret-key"
)

// Scaleway is also the one provider whose two mint methods chain different
// secrets, at different levels, so the chained rows below come in a pair.
//
// dynamic_keys chains the management secret key on the SOURCE: it authenticates
// the source's own call to the IAM API, which is what makes it a source concern.
// static_keys chains the pair on the SPEC: that pair IS the credential handed to
// the caller, it authenticates nothing of the source's, and the path makes no
// call at all. Each row proves its own half of that split reached the wire.
const (
	// Written to secret/data/e2e/scaleway-mgmt-key by setup.sh, and the key the
	// driver authenticates its mint with on the dynamic row. It appears in no
	// spec or source config anywhere, so an assertion on it can only pass if the
	// whole chain ran.
	scalewayChainedMgmtKey = "e2e-scw-mgmt-not-a-real-secret-key"

	// What the stand-in IAM API returns from the mint call. Also in no config: it
	// is minted, not stored. SCW-prefixed because ScalewayKeysCredType.Validate
	// refuses anything else at parse.
	scalewayMintedAccessKey = "SCWE2EMINTEDKEY00000"
	scalewayMintedSecretKey = "e2e-scw-minted-not-a-real-secret"

	// Written to secret/data/e2e/scaleway-static-pair by setup.sh. Both halves,
	// because for static_keys the pair is the whole credential.
	scalewayChainedPairAccessKey = "SCWE2ECHAINEDPAIR000"
	scalewayChainedPairSecretKey = "e2e-scw-chained-pair-not-a-real-secret"

	scalewayIAMKeysPath = "/iam/v1alpha1/api-keys"

	// Test-local, the sources included, for the reason gitlab_test.go gives: a
	// killed run skips t.Cleanup, and a spec left hanging off a shared source
	// would block that source from being deleted, failing the next run's setup
	// before it reaches the cleanup that would have cleared it.
	scalewayMgmtSecretSpec  = "fc-scw-mgmt-from-vault"
	scalewayChainSource     = "fc-scw-keyless-src"
	scalewayDynSpec         = "fc-scw-dyn-cred"
	scalewayDynAgentRole    = "fc-scw-dyn-agent"
	scalewayPairSecretSpec  = "fc-scw-pair-from-vault"
	scalewayStaticSource    = "fc-scw-static-src"
	scalewayStaticSpec      = "fc-scw-static-cred"
	scalewayStaticAgentRole = "fc-scw-static-agent"
)

// scalewayMustWrite is the local provisioning helper the chained rows share.
func scalewayMustWrite(t *testing.T, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

// scalewaySubject names one of the two ways a chained secret's fetch can be
// pinned to the session, and the Vault federation source that accepts it.
//
// The store requires one or the other — an unpinned reference is refused — but
// they federate differently, so both belong in a chained row. agent_identity
// forwards the agent's own inbound JWT, which Vault validates against Hydra.
// warden_identity mints an assertion signed by Warden's own issuer, which the
// jwt-warden mount trusts by pinned public key; until setup.sh grew that mount
// no chained suite could exercise it at all.
type scalewaySubject struct {
	name   string
	source string
}

var scalewaySubjects = []scalewaySubject{
	{"agent_identity", "vault-fed-e2e"},
	{"warden_identity", "vault-warden-fed-e2e"},
}

// scalewayReferencedSpec creates the key_value spec a chain points at.
func scalewayReferencedSpec(t *testing.T, name, secretPath string, subj scalewaySubject) {
	t.Helper()
	scalewayMustWrite(t, "POST", "sys/cred/specs/"+name, fmt.Sprintf(`{
		"type":"key_value","source":%q,"config":{
			"mint_method":"kv2_read","kv2_mount":"secret","secret_path":%q,
			"subject_token_source":%q}}`, subj.source, secretPath, subj.name),
		"create the referenced secret spec "+name)
}

// serveScalewayIAM makes the upstream answer the driver's mint call, leaving
// every other path to the default probe response so the proxied request behaves
// like every other row's.
func serveScalewayIAM(t *testing.T) {
	t.Helper()
	upstream.SetHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == scalewayIAMKeysPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"access_key":%q,"secret_key":%q,"expires_at":%q}`,
				scalewayMintedAccessKey, scalewayMintedSecretKey,
				time.Now().Add(time.Hour).UTC().Format(time.RFC3339))))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

// findScalewayMint returns the mint call the driver made, failing if it never
// happened — the interesting failure on a chained row, since a chain that broke
// before the driver ran would otherwise present only as a 5xx.
func findScalewayMint(t *testing.T) h.UpstreamRequest {
	t.Helper()
	for _, req := range upstream.Requests() {
		if req.Method == http.MethodPost && req.Path == scalewayIAMKeysPath {
			return req
		}
	}
	t.Fatalf("upstream never received the mint call %s %s", http.MethodPost, scalewayIAMKeysPath)
	return h.UpstreamRequest{}
}

// setupScalewayDynChain builds the SOURCE-level chain: a source holding no
// management key, and a dynamic_keys spec that inherits the chain from it.
func setupScalewayDynChain(t *testing.T, subj scalewaySubject) {
	t.Helper()

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+scalewayDynAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+scalewayDynSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+scalewayChainSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+scalewayMgmtSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	scalewayReferencedSpec(t, scalewayMgmtSecretSpec, "e2e/scaleway-mgmt-key", subj)

	// Carrying none of the key its mint method would normally need: validation
	// refuses a source that keeps one while also naming a chain.
	scalewayMustWrite(t, "POST", "sys/cred/sources/"+scalewayChainSource, fmt.Sprintf(`{
		"type":"scaleway","config":{
			"scaleway_url":%q,"tls_skip_verify":"true",
			"secret_spec":%q,"secret_field":"management_secret_key"}}`,
		upstream.URL, scalewayMgmtSecretSpec),
		"create the keyless scaleway source")

	// Ordinary: it inherits the chain from its source and carries no chaining
	// config of its own, which is what source-level chaining means.
	scalewayMustWrite(t, "POST", "sys/cred/specs/"+scalewayDynSpec, `{
		"type":"scaleway_keys","source":"`+scalewayChainSource+`","config":{
			"mint_method":"dynamic_keys","application_id":"e2e-scw-app","ttl":"1h"}}`,
		"create the chained dynamic_keys spec")

	// The mount's own role binds its default spec, so the chained spec needs one
	// bound to it instead.
	scalewayMustWrite(t, "POST", "auth/jwt/role/"+scalewayDynAgentRole, `{
		"token_policies":["`+scalewayEnv.Policy()+`"],"cred_spec_name":"`+scalewayDynSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the chained dynamic agent role")
}

// scalewayCredStub is a stand-in Scaleway API that exists to be left alone: the
// static row points a source at it and asserts it was never called.
type scalewayCredStub struct {
	*httptest.Server
	mu    sync.Mutex
	calls int
}

func newScalewayCredStub(t *testing.T) *scalewayCredStub {
	t.Helper()
	stub := &scalewayCredStub{}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.calls++
		stub.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(stub.Close)
	return stub
}

func (s *scalewayCredStub) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// setupScalewayStaticChain builds the SPEC-level chain. The source holds
// nothing at all — not even a chain — because for static_keys the reference
// belongs to the spec whose credential it yields.
func setupScalewayStaticChain(t *testing.T, credURL string, subj scalewaySubject) {
	t.Helper()

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+scalewayStaticAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+scalewayStaticSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+scalewayStaticSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+scalewayPairSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	scalewayReferencedSpec(t, scalewayPairSecretSpec, "e2e/scaleway-static-pair", subj)

	scalewayMustWrite(t, "POST", "sys/cred/sources/"+scalewayStaticSource, fmt.Sprintf(`{
		"type":"scaleway","config":{"scaleway_url":%q,"tls_skip_verify":"true"}}`, credURL),
		"create the plain scaleway source")

	// No secret_field: it names a single secret, and a pair is not one — both
	// halves are read by name, and the spec is refused a field for that reason.
	// No inline halves either, for the same reason a chained source keeps no key.
	scalewayMustWrite(t, "POST", "sys/cred/specs/"+scalewayStaticSpec, `{
		"type":"scaleway_keys","source":"`+scalewayStaticSource+`","config":{
			"mint_method":"static_keys","secret_spec":"`+scalewayPairSecretSpec+`"}}`,
		"create the spec-chained static_keys spec")

	scalewayMustWrite(t, "POST", "auth/jwt/role/"+scalewayStaticAgentRole, `{
		"token_policies":["`+scalewayEnv.Policy()+`"],"cred_spec_name":"`+scalewayStaticSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the chained static agent role")
}

var scalewayEnv = h.ProviderEnv{
	Mount:    "fc-scaleway",
	Type:     "scaleway",
	URLKey:   "scaleway_url",
	CredType: "scaleway_keys",
	CredConfig: map[string]string{
		"access_key": scalewayAccessKey,
		"secret_key": scalewaySecretKey,
	},
}

// TestScaleway_MintLandsInNativeHeader is the baseline: the credential reaches
// the upstream in X-Auth-Token, which is where Scaleway looks, and none of the
// inbound Warden channels follow it.
func TestScaleway_MintLandsInNativeHeader(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, scalewayEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         scalewayEnv.CertRole(),
		Path:         "instance/v1/zones/fr-par-1/servers",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"X-Auth-Token": scalewaySecretKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestScaleway_InboundAuthorizationNeverReachesUpstream is the row this provider
// exists to carry. Scaleway authenticates with X-Auth-Token, so nothing the
// provider injects would overwrite Authorization — and the SDK used to leave it
// in place for exactly that reason, forwarding the caller's Warden credential to
// the vendor.
//
// The user leg is deliberately off. With it on, core captures the user and
// deletes Authorization itself before the backend ever sees the request
// (request_handler.go, at user capture), so the row would pass whether or not
// the gateway strips anything. Off, the agent's own JWT stays on Authorization
// all the way to handleAPIRequest, and only the strip keeps it off the wire.
func TestScaleway_InboundAuthorizationNeverReachesUpstream(t *testing.T) {
	ensureEnv(t)
	defer h.ResetFullChainLegs(t, leaderPort, upstream.URL, scalewayEnv)
	h.SetFullChainLegs(t, leaderPort, upstream.URL, scalewayEnv, h.JWTAgentPath, "")

	status, body, _ := h.ChainRequest(t, leaderPort, scalewayEnv, h.ChainOpts{
		Bearer: h.GetDefaultJWT(t),
		Role:   scalewayEnv.JWTAgentRole(),
		Path:   "instance/v1/zones/fr-par-1/servers",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"X-Auth-Token": scalewaySecretKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}

// TestScaleway_DynamicKeysChainMintsWithVaultHeldManagementKey is the
// source-level half of the chaining pair: a source that stores no management key
// still mints a fresh one.
//
// Both asserted values are absent from every spec and source config — one lives
// only in Vault, the other only in the mint response — so the row fails if any
// link breaks: the federation login, the KV read, the material reaching
// MintFromSecret, the mint itself, or the extractor.
//
// Run for both ways of pinning the fetch to the session. They take different
// paths into Vault — one forwards the agent's own JWT, the other presents an
// assertion Warden signed — and the mint must not be able to tell.
//
// Both principals are present, as in AgentTokenChannelFreesAuthorization: the
// agent on its own channel, a user on Authorization. That is the arrangement
// this provider exists here to cover, and the one worth proving chaining
// survives — the reference resolves as the AGENT, so a chain that silently keyed
// on the user would still pass a single-principal row.
//
// The agent leg is a JWT rather than the usual certificate: agent_identity
// forwards that JWT as the exchange subject and fails closed on a
// cert-authenticated request, and warden_identity needs the principal to be
// e2e-agent to match the Vault role's bound warden_sub.
func TestScaleway_DynamicKeysChainMintsWithVaultHeldManagementKey(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, scalewayEnv)

	for _, subj := range scalewaySubjects {
		t.Run(subj.name, func(t *testing.T) {
			setupScalewayDynChain(t, subj)
			serveScalewayIAM(t)
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, scalewayEnv, h.ChainOpts{
				AgentToken: h.GetDefaultJWT(t),
				Bearer:     h.FullChainUserJWT(t),
				Role:       scalewayDynAgentRole,
				Path:       "instance/v1/zones/fr-par-1/servers",
			})

			// Two calls: the driver's mint, then the proxied request. No
			// construction check, because at construction a chained source has
			// nothing to check with.
			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      map[string]string{"X-Auth-Token": scalewayMintedSecretKey},
				Absent:        h.AlwaysAbsent("Authorization"),
				UpstreamCalls: 2,
			})

			// The half a driver test cannot show: the key the mint authenticated
			// with came out of Vault, not out of config.
			mint := findScalewayMint(t)
			if got := mint.Header.Get("X-Auth-Token"); got != scalewayChainedMgmtKey {
				t.Errorf("mint call authenticated with %q, want the Vault-held management key %q", got, scalewayChainedMgmtKey)
			}
			// The key rides a header and only a header: a URL or body carrying it
			// would reach logs and proxies the header does not.
			if strings.Contains(string(mint.Body), scalewayChainedMgmtKey) {
				t.Errorf("the management key leaked into the mint body: %s", mint.Body)
			}
			if !strings.Contains(string(mint.Body), "e2e-scw-app") {
				t.Errorf("mint body should name the spec's application_id, got: %s", mint.Body)
			}

			// And the source really holds nothing: the create-time refusal is
			// pinned below, this is the state that refusal produces.
			_, srcBody := h.APIRequest(t, "GET", "sys/cred/sources/"+scalewayChainSource, leaderPort, "")
			if strings.Contains(string(srcBody), scalewayChainedMgmtKey) {
				t.Errorf("the source stores the management key it is supposed to fetch: %s", srcBody)
			}
		})
	}
}

// TestScaleway_StaticKeysChainServesVaultHeldPairWithoutCallingScaleway is the
// spec-level half. Its point is the negative: static_keys spends the fetched
// material directly, so the chain runs and the credential arrives having made no
// API call at all.
//
// That is why there are two servers. The source points at a stub whose only job
// is to record nothing; the mount keeps pointing at the shared upstream, which
// serves the proxied request. Pointed at one listener, "zero calls" could never
// be told apart from the proxied request itself.
//
// Only secret_key is observable here — it is the header Scaleway authenticates
// with, and the S3 leg that would carry both halves resolves its endpoint to a
// real public host with no override. The access_key is pinned instead by the
// mint refusing to produce a credential without it, and by ScalewayKeysCredType
// rejecting one that is not SCW-prefixed: a 200 means a complete, well-formed
// pair came out of Vault. Its exact value is asserted in the driver's unit tests.
func TestScaleway_StaticKeysChainServesVaultHeldPairWithoutCallingScaleway(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, scalewayEnv)

	for _, subj := range scalewaySubjects {
		t.Run(subj.name, func(t *testing.T) {
			credStub := newScalewayCredStub(t)
			setupScalewayStaticChain(t, credStub.URL, subj)
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, scalewayEnv, h.ChainOpts{
				AgentToken: h.GetDefaultJWT(t),
				Bearer:     h.FullChainUserJWT(t),
				Role:       scalewayStaticAgentRole,
				Path:       "instance/v1/zones/fr-par-1/servers",
			})

			// One call, the proxied request. The secret exists only in Vault, so
			// the chain is proven by its arrival.
			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      map[string]string{"X-Auth-Token": scalewayChainedPairSecretKey},
				Absent:        h.AlwaysAbsent("Authorization"),
				UpstreamCalls: 1,
			})

			if n := credStub.Count(); n != 0 {
				t.Errorf("static_keys called the Scaleway API %d times; it mints from the fetched pair and must call nothing", n)
			}
		})
	}
}

// TestScaleway_ChainedConfigRefusals pins the shapes a chained scaleway
// configuration must not take, at the point they are written rather than at
// first use.
//
// Each row exercises a different layer running in the real server: the driver
// factory, the store's cross-object guard, and the credential type. The last is
// the one the store's own unit tests cannot reach, since their Core is built
// without a type registry.
func TestScaleway_ChainedConfigRefusals(t *testing.T) {
	ensureEnv(t)
	setupScalewayDynChain(t, scalewaySubjects[0])

	sources := []struct {
		name   string
		id     string
		body   string
		errMsg string
	}{
		{
			name: "rotation_period on a source owning no secret",
			id:   "rotation-period",
			body: fmt.Sprintf(`{"type":"scaleway","rotation_period":86400,"config":{
				"scaleway_url":%q,"tls_skip_verify":"true","secret_spec":%q}}`,
				upstream.URL, scalewayMgmtSecretSpec),
			errMsg: "rotation_period does not apply",
		},
		{
			name: "an inline management key kept alongside the chain",
			id:   "inline-management-key",
			body: fmt.Sprintf(`{"type":"scaleway","config":{
				"scaleway_url":%q,"tls_skip_verify":"true","secret_spec":%q,
				"management_secret_key":"11111111-2222-3333-4444-555555555555"}}`,
				upstream.URL, scalewayMgmtSecretSpec),
			errMsg: "must be omitted when secret_spec is set",
		},
	}
	for _, tt := range sources {
		t.Run(tt.name, func(t *testing.T) {
			name := "fc-scw-refused-" + tt.id
			t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "") })

			status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leaderPort, tt.body)
			if status < 400 {
				t.Fatalf("got status %d, want a failure (body: %s)", status, body)
			}
			if !strings.Contains(string(body), tt.errMsg) {
				t.Errorf("error should mention %q, got: %s", tt.errMsg, body)
			}
		})
	}

	// id names the spec, rather than the description doing it: a description
	// reads better with an apostrophe in it, and a spec path does not survive one.
	specs := []struct {
		name   string
		id     string
		body   string
		errMsg string
	}{
		{
			// Source-level routing would hand this spec the management payload,
			// which is not its credential. The inline pair is what gets it past
			// the type validator, so the store's cross-object guard is the one
			// that fires.
			name: "a static_keys spec riding the source's chain",
			id:   "static-riding-source-chain",
			body: `{"type":"scaleway_keys","source":"` + scalewayChainSource + `","config":{
				"mint_method":"static_keys","access_key":"SCWE2EINLINEKEY00000",
				"secret_key":"e2e-scw-inline-not-a-real-secret"}}`,
			errMsg: "must set its own secret_spec",
		},
		{
			// The management key authenticates the source's own calls, and the
			// driver factory only ever sees source config — a reference parked on
			// the spec would slip past the checks that gate a chained source.
			name: "a spec-level reference on dynamic_keys",
			id:   "dynamic-spec-level-reference",
			body: `{"type":"scaleway_keys","source":"` + scalewayChainSource + `","config":{
				"mint_method":"dynamic_keys","application_id":"e2e-scw-app",
				"secret_spec":"` + scalewayMgmtSecretSpec + `"}}`,
			errMsg: "set 'secret_spec' on the source",
		},
	}
	for _, tt := range specs {
		t.Run(tt.name, func(t *testing.T) {
			name := "fc-scw-spec-refused-" + tt.id
			t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/specs/"+name, leaderPort, "") })

			status, body := h.APIRequest(t, "POST", "sys/cred/specs/"+name, leaderPort, tt.body)
			if status < 400 {
				t.Fatalf("got status %d, want a failure (body: %s)", status, body)
			}
			if !strings.Contains(string(body), tt.errMsg) {
				t.Errorf("error should mention %q, got: %s", tt.errMsg, body)
			}
		})
	}
}

// TestScaleway_AgentTokenChannelFreesAuthorization pins the row the dual-mode
// SDK used to get wrong. It never read X-Warden-Agent-Token at all, so a request
// that separated the two principals properly had the *user's* bearer taken as
// the agent — the mount authenticated as the wrong party, and said so nowhere.
func TestScaleway_AgentTokenChannelFreesAuthorization(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, scalewayEnv)

	status, body, _ := h.ChainRequest(t, leaderPort, scalewayEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		AgentToken:   h.GetDefaultJWT(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         scalewayEnv.JWTAgentRole(),
		Path:         "instance/v1/zones/fr-par-1/servers",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"X-Auth-Token": scalewaySecretKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}
