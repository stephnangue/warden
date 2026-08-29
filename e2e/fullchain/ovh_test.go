//go:build e2e

package fullchain

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	h "github.com/stephnangue/warden/e2e/helpers"
)

// ovh is the dual-mode gateway whose credential is minted rather than held.
// scaleway and cloudflare both sit on a local source, so their rows prove the
// injection but not the mint; this one exchanges a service account for a bearer
// token on every request.
//
// The exchange is a plain OAuth2 client_credentials grant, so Hydra can issue
// it — reached through the source's token_url, which exists because a
// deployment's service-account tokens need not come from ovh.com. Without that
// override the regional endpoint map is the only answer and every mint would
// call the vendor for real.
//
// It is also the only provider here whose two mint methods differ in whether
// they call anything at all. oauth2_token performs the grant; access_keys serves
// an object-storage pair held elsewhere and calls nothing, which is what makes
// the S3 rows below assertable against a listener of their own.

const ovhClientSecret = "agent-secret"

const (
	// Written to secret/data/e2e/ovh-client-credential by setup.sh, and the pair
	// a chained source performs its grant with. Hydra validates it, so the
	// chained row passes only if these values reached the driver from Vault —
	// unlike every other chained row here, whose secret is spent on a stand-in
	// that would accept anything.
	ovhChainedClientID     = "e2e-agent"
	ovhChainedClientSecret = "agent-secret"

	// Written to secret/data/e2e/ovh-access-keys by setup.sh. Both halves,
	// because for access_keys the pair IS the credential.
	ovhChainedAccessKey = "E2EOVHACCESSKEY00000"
	ovhChainedSecretKey = "e2e-ovh-access-not-a-real-secret"

	// Test-local, the sources included, for the reason gitlab_test.go gives: a
	// killed run skips t.Cleanup, and a spec left hanging off a shared source
	// would block that source from being deleted, failing the next run's setup
	// before it reaches the cleanup that would have cleared it.
	ovhClientCredSpec   = "fc-ovh-client-from-vault"
	ovhChainSource      = "fc-ovh-keyless-src"
	ovhChainSpec        = "fc-ovh-chain-cred"
	ovhChainAgentRole   = "fc-ovh-chain-agent"
	ovhPairSecretSpec   = "fc-ovh-pair-from-vault"
	ovhAccessSource     = "fc-ovh-access-src"
	ovhAccessSpec       = "fc-ovh-access-cred"
	ovhAccessAgentRole  = "fc-ovh-access-agent"
	ovhS3Region         = "gra"
	ovhS3SignedTestPath = "/fc-ovh-bucket/probe.txt"
)

// ovhMustWrite is the local provisioning helper the chained rows share.
func ovhMustWrite(t *testing.T, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

// ovhS3Upstream stands in for OVH Object Storage.
//
// It is a listener of its own, and a TLS one, for two reasons the shared
// recording upstream cannot satisfy: the S3 leg always forwards over https, and
// a row whose point is that access_keys calls nothing needs somewhere for
// "nothing" to be observable — pointed at one listener, zero mint calls could
// never be told apart from the proxied request itself.
type ovhS3Upstream struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
}

func startOVHS3Upstream() *ovhS3Upstream {
	up := &ovhS3Upstream{}
	up.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		up.reqs = append(up.reqs, r.Clone(context.Background()))
		up.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ListBucketResult></ListBucketResult>`))
	}))
	return up
}

func (u *ovhS3Upstream) Requests() []*http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]*http.Request(nil), u.reqs...)
}

func (u *ovhS3Upstream) Reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reqs = nil
}

func (u *ovhS3Upstream) Last(t *testing.T) *http.Request {
	t.Helper()
	reqs := u.Requests()
	if len(reqs) == 0 {
		t.Fatal("the S3 upstream received no request")
	}
	return reqs[len(reqs)-1]
}

// Both are built in ensureEnv: the mount names the S3 listener, which does not
// exist until it is listening.
var (
	ovhS3  *ovhS3Upstream
	ovhEnv h.ProviderEnv
)

// buildOVHEnv names the S3 listener, which is not known until it is up — the
// same reason kubernetes and ibmcloud build their envs in ensureEnv.
func buildOVHEnv(s3URL string) h.ProviderEnv {
	return h.ProviderEnv{
		Mount:      "fc-ovh",
		Type:       "ovh",
		URLKey:     "ovh_url",
		CredType:   "ovh_keys",
		SourceType: "ovh",
		SourceConfig: map[string]string{
			"client_id":       "e2e-agent",
			"client_secret":   ovhClientSecret,
			"token_url":       h.HydraIssuer + "/oauth2/token",
			"tls_skip_verify": "true",
		},
		// s3_url exists so an operator whose traffic leaves through a private
		// gateway can name it; here it is what makes the S3 leg reachable at all,
		// since the region otherwise resolves to a real public host.
		ExtraConfig: map[string]any{
			"s3_url":          s3URL,
			"tls_skip_verify": true,
		},
		CredConfig: map[string]string{"mint_method": "oauth2_token"},
	}
}

// ovhReferencedSpec creates the key_value spec a chain points at. It mirrors
// scalewayReferencedSpec and takes the same subject matrix: the store refuses an
// unpinned reference, and the two ways of pinning it federate differently.
func ovhReferencedSpec(t *testing.T, name, secretPath string, subj scalewaySubject) {
	t.Helper()
	ovhMustWrite(t, "POST", "sys/cred/specs/"+name, fmt.Sprintf(`{
		"type":"key_value","source":%q,"config":{
			"mint_method":"kv2_read","kv2_mount":"secret","secret_path":%q,
			"subject_token_source":%q}}`, subj.source, secretPath, subj.name),
		"create the referenced secret spec "+name)
}

// setupOVHClientCredChain builds the SOURCE-level chain: a source holding
// neither half of its service account, and an oauth2_token spec that inherits
// the chain from it.
func setupOVHClientCredChain(t *testing.T, subj scalewaySubject) {
	t.Helper()

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+ovhChainAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+ovhChainSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+ovhChainSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+ovhClientCredSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	ovhReferencedSpec(t, ovhClientCredSpec, "e2e/ovh-client-credential", subj)

	// Neither client_id nor client_secret: validation refuses a source that keeps
	// either while also naming a chain, because the two authenticate as a pair.
	//
	// secret_field is set because the payload holds two keys, so nothing could
	// pick between them — the id is read by name beside whatever the field names.
	ovhMustWrite(t, "POST", "sys/cred/sources/"+ovhChainSource, fmt.Sprintf(`{
		"type":"ovh","config":{
			"token_url":%q,"tls_skip_verify":"true",
			"secret_spec":%q,"secret_field":"client_secret"}}`,
		h.HydraIssuer+"/oauth2/token", ovhClientCredSpec),
		"create the keyless ovh source")

	// Ordinary: it inherits the chain from its source and carries no chaining
	// config of its own, which is what source-level chaining means.
	ovhMustWrite(t, "POST", "sys/cred/specs/"+ovhChainSpec, `{
		"type":"ovh_keys","source":"`+ovhChainSource+`","config":{
			"mint_method":"oauth2_token"}}`,
		"create the chained oauth2_token spec")

	ovhMustWrite(t, "POST", "auth/jwt/role/"+ovhChainAgentRole, `{
		"token_policies":["`+ovhEnv.Policy()+`"],"cred_spec_name":"`+ovhChainSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the chained agent role")
}

// setupOVHAccessKeysChain builds the SPEC-level chain. The source holds nothing
// at all — not even a chain — because for access_keys the reference belongs to
// the spec whose credential it yields, and the source performs no grant.
func setupOVHAccessKeysChain(t *testing.T, subj scalewaySubject) {
	t.Helper()

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+ovhAccessAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+ovhAccessSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+ovhAccessSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+ovhPairSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	ovhReferencedSpec(t, ovhPairSecretSpec, "e2e/ovh-access-keys", subj)

	// No service account: a source serving only access_keys specs never performs
	// the grant, so it is not asked for one.
	ovhMustWrite(t, "POST", "sys/cred/sources/"+ovhAccessSource,
		`{"type":"ovh","config":{"ovh_endpoint":"ovh-eu"}}`,
		"create the grant-free ovh source")

	// No secret_field: it names a single secret, and a pair is not one — both
	// halves are read by name, and the spec is refused a field for that reason.
	ovhMustWrite(t, "POST", "sys/cred/specs/"+ovhAccessSpec, `{
		"type":"ovh_keys","source":"`+ovhAccessSource+`","config":{
			"mint_method":"access_keys","secret_spec":"`+ovhPairSecretSpec+`"}}`,
		"create the spec-chained access_keys spec")

	ovhMustWrite(t, "POST", "auth/jwt/role/"+ovhAccessAgentRole, `{
		"token_policies":["`+ovhEnv.Policy()+`"],"cred_spec_name":"`+ovhAccessSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the chained access_keys agent role")
}

// signOVHS3Request signs a gateway request the way an S3 client authenticating
// to Warden does: the caller's own token is both halves of the SigV4 credential,
// because verification reconstructs the secret from the access key id it reads
// off the wire. Warden verifies that signature, then re-signs with the real
// provider keys before forwarding.
func signOVHS3Request(t *testing.T, token, role, path string, tamper bool) *http.Request {
	t.Helper()

	url := fmt.Sprintf("%s/v1/%s/gateway%s", h.NodeURL(leaderPort), ovhEnv.Mount, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build the S3 request: %v", err)
	}
	// Signed rather than added afterwards: Warden verifies over the headers as
	// they arrive, so a role added after signing would break the signature.
	req.Header.Set("X-Warden-Role", role)

	empty := sha256.Sum256(nil)
	creds := awssdk.Credentials{AccessKeyID: token, SecretAccessKey: token}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err := signer.SignHTTP(context.Background(), creds, req, hex.EncodeToString(empty[:]), "s3", ovhS3Region, time.Now()); err != nil {
		t.Fatalf("sign the S3 request: %v", err)
	}

	if tamper {
		// Change the signature and nothing else, so the request stays
		// well-formed and only verification can reject it.
		authz := req.Header.Get("Authorization")
		idx := strings.LastIndex(authz, "Signature=")
		if idx < 0 {
			t.Fatalf("signed Authorization has no Signature component: %q", authz)
		}
		req.Header.Set("Authorization", authz[:idx]+"Signature=00000000000000000000000000000000000000000000000000000000000000ff")
	}
	return req
}

func sendOVHS3Request(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send the S3 request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestOVH_MintedTokenReachesUpstream drives the whole chain including the
// credential exchange: the source trades its service account for a bearer
// token, and that token — not the caller's — is what the upstream sees.
func TestOVH_MintedTokenReachesUpstream(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, ovhEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         ovhEnv.CertRole(),
		Path:         "me",
	})

	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}

	got := upstream.Last(t)
	authz := got.Header.Get("Authorization")

	// The value is whatever Hydra minted this run, so it cannot be compared to a
	// constant. What it must not be is anything the request already had, or the
	// service account itself: forwarding the caller's bearer, or handing the
	// client_secret through unexchanged, would both leave a plausible-looking
	// Bearer on the wire.
	token, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok || token == "" {
		t.Fatalf("Authorization = %q, want a Bearer token", authz)
	}
	if token == h.FullChainUserJWT(t) {
		t.Error("the caller's own JWT was forwarded as the credential")
	}
	if token == ovhClientSecret {
		t.Error("the service account secret was forwarded unexchanged")
	}
	// Hydra issues JWTs, so a minted token is one. Anything else means the mint
	// was skipped and some other value rode through.
	if !strings.HasPrefix(token, "ey") {
		t.Errorf("credential %q is not a minted JWT", token)
	}
	if got.Path != "/me" {
		t.Errorf("upstream path = %q, want /me", got.Path)
	}
}

// TestOVH_AgentTokenChannelDisplacesTheUserBearer is the row the dual-mode SDK
// used to get wrong: it never read X-Warden-Agent-Token, so a request that
// separated the two principals had the user's bearer taken as the agent.
//
// ovh injects into Authorization rather than a native header, so the assertion
// is displacement rather than absence — the user's JWT arrived there and must
// not still be there.
func TestOVH_AgentTokenChannelDisplacesTheUserBearer(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, ovhEnv)

	userJWT := h.FullChainUserJWT(t)
	status, body, _ := h.ChainRequest(t, leaderPort, ovhEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     userJWT,
		Role:       ovhEnv.JWTAgentRole(),
		Path:       "me",
	})

	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}

	token, ok := strings.CutPrefix(upstream.Last(t).Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		t.Fatal("upstream received no Bearer credential")
	}
	if token == userJWT {
		t.Error("the user's bearer survived to the upstream instead of the minted credential")
	}
}

// TestOVH_OAuth2TokenChainMintsWithVaultHeldClientCredential is the source-level
// half: the service account is not in the source at all, it is fetched per
// request as the calling agent and spent on the grant.
//
// This row is stronger than the other chained rows in this package. Elsewhere
// the chained secret is spent against a stand-in that would accept any value, so
// the assertion has to inspect the mint call. Here Hydra checks the pair, so a
// 200 with a real JWT on the wire is itself proof that what came out of Vault
// was the genuine client credential.
func TestOVH_OAuth2TokenChainMintsWithVaultHeldClientCredential(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, ovhEnv)

	for _, subj := range scalewaySubjects {
		t.Run(subj.name, func(t *testing.T) {
			setupOVHClientCredChain(t, subj)
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, ovhEnv, h.ChainOpts{
				AgentToken: h.GetDefaultJWT(t),
				Bearer:     h.FullChainUserJWT(t),
				Role:       ovhChainAgentRole,
				Path:       "me",
			})
			if status != 200 {
				t.Fatalf("status %d, body %s", status, string(body))
			}

			// One call: the grant goes to Hydra, not to the upstream.
			if n := len(upstream.Requests()); n != 1 {
				t.Errorf("upstream calls = %d, want 1 (the grant is Hydra's)", n)
			}

			token, ok := strings.CutPrefix(upstream.Last(t).Header.Get("Authorization"), "Bearer ")
			if !ok || !strings.HasPrefix(token, "ey") {
				t.Fatalf("upstream Authorization did not carry a minted JWT: %q", token)
			}
			if token == h.FullChainUserJWT(t) || token == ovhChainedClientSecret {
				t.Error("something other than a minted token reached the upstream")
			}

			// And the source really holds nothing: the create-time refusal is
			// pinned below, this is the state that refusal produces.
			_, srcBody := h.APIRequest(t, "GET", "sys/cred/sources/"+ovhChainSource, leaderPort, "")
			for _, half := range []string{ovhChainedClientID, ovhChainedClientSecret} {
				if strings.Contains(string(srcBody), half) {
					t.Errorf("the source stores %q, which it is supposed to fetch: %s", half, srcBody)
				}
			}
		})
	}
}

// TestOVH_AccessKeysChainReSignsWithTheVaultHeldPair is the spec-level half, and
// the only row in this package that follows a credential all the way through the
// S3 leg.
//
// Its point is doubled. The pair exists only in Vault, so seeing it in the
// outgoing signature proves the chain ran; and access_keys mints by serving that
// pair rather than asking OVH for one, so the API upstream must stay untouched.
func TestOVH_AccessKeysChainReSignsWithTheVaultHeldPair(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, ovhEnv)

	for _, subj := range scalewaySubjects {
		t.Run(subj.name, func(t *testing.T) {
			setupOVHAccessKeysChain(t, subj)
			upstream.Reset()
			ovhS3.Reset()

			req := signOVHS3Request(t, h.GetDefaultJWT(t), ovhAccessAgentRole, ovhS3SignedTestPath, false)
			status, body := sendOVHS3Request(t, req)
			if status != 200 {
				t.Fatalf("status %d, body %s", status, body)
			}

			got := ovhS3.Last(t)
			authz := got.Header.Get("Authorization")
			if !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") {
				t.Fatalf("the S3 upstream was not addressed with a SigV4 signature: %q", authz)
			}
			// The re-signed credential names the access key. Its secret half never
			// appears on the wire — it is what the signature is computed with — so
			// the access key is what an assertion can reach, and it exists nowhere
			// but Vault.
			if !strings.Contains(authz, "Credential="+ovhChainedAccessKey+"/") {
				t.Errorf("re-signed with some other access key: %q", authz)
			}
			// The caller's own token was the inbound SigV4 credential; it must not
			// have been passed along as the outbound one.
			if strings.Contains(authz, h.GetDefaultJWT(t)) {
				t.Error("the caller's token was forwarded as the S3 credential")
			}
			// The secret half is what the signature is computed with and must
			// never travel: SigV4 exists so that it does not.
			for name, values := range got.Header {
				for _, v := range values {
					if strings.Contains(v, ovhChainedSecretKey) {
						t.Errorf("the secret key travelled in header %s", name)
					}
				}
			}
			if got.URL.Path != ovhS3SignedTestPath {
				t.Errorf("S3 upstream path = %q, want %q", got.URL.Path, ovhS3SignedTestPath)
			}

			// access_keys serves a pair that already exists. Any call to the OVH
			// API would mean something tried to create one.
			if n := len(upstream.Requests()); n != 0 {
				t.Errorf("the OVH API was called %d times; access_keys must call nothing", n)
			}
		})
	}
}

// TestOVH_S3SignatureIsVerifiedBeforeAnythingIsSpent pins the negative half of
// the S3 leg: a request Warden cannot verify never reaches a credential, so no
// mint happens and nothing leaves.
func TestOVH_S3SignatureIsVerifiedBeforeAnythingIsSpent(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, ovhEnv)
	setupOVHAccessKeysChain(t, scalewaySubjects[0])
	upstream.Reset()
	ovhS3.Reset()

	req := signOVHS3Request(t, h.GetDefaultJWT(t), ovhAccessAgentRole, ovhS3SignedTestPath, true)
	status, body := sendOVHS3Request(t, req)
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (body: %s)", status, body)
	}
	if n := len(ovhS3.Requests()); n != 0 {
		t.Errorf("a request with a bad signature reached the S3 upstream %d times", n)
	}
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("a request with a bad signature reached the API upstream %d times", n)
	}
}

// TestOVH_ChainedConfigRefusals pins the shapes a chained ovh configuration must
// not take, at the point they are written rather than at first use.
//
// Each row exercises a different layer running in the real server: the driver
// factory, the store's cross-object guard, and the credential type. The last is
// the one the store's own unit tests cannot reach, since their Core is built
// without a type registry.
func TestOVH_ChainedConfigRefusals(t *testing.T) {
	ensureEnv(t)
	setupOVHClientCredChain(t, scalewaySubjects[0])

	sources := []struct {
		name   string
		id     string
		body   string
		errMsg string
	}{
		{
			// Keeping the secret would leave a source that reads as keyless while
			// storing the very secret chaining removes.
			name: "an inline client_secret kept alongside the chain",
			id:   "inline-client-secret",
			body: fmt.Sprintf(`{"type":"ovh","config":{
				"token_url":%q,"tls_skip_verify":"true","secret_spec":%q,
				"client_secret":"left-behind"}}`,
				h.HydraIssuer+"/oauth2/token", ovhClientCredSpec),
			errMsg: "client_secret must be omitted when secret_spec is set",
		},
		{
			// And the id, because the pair authenticates together: an id here
			// beside a fetched secret would name one service account while
			// presenting another's.
			name: "an inline client_id kept alongside the chain",
			id:   "inline-client-id",
			body: fmt.Sprintf(`{"type":"ovh","config":{
				"token_url":%q,"tls_skip_verify":"true","secret_spec":%q,
				"client_id":"some-other-account"}}`,
				h.HydraIssuer+"/oauth2/token", ovhClientCredSpec),
			errMsg: "client_id must be omitted when secret_spec is set",
		},
	}
	for _, tt := range sources {
		t.Run(tt.name, func(t *testing.T) {
			name := "fc-ovh-refused-" + tt.id
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
			// Nothing mints the pair, so without a reference there is none to
			// serve — and inheriting the source's would hand this spec the client
			// credential, which is not its credential either. The store carries a
			// guard for the second reading, but the type validator refuses the
			// shape outright and is what fires here; the store's is what holds
			// when the type registry is unavailable.
			name: "an access_keys spec naming no reference",
			id:   "access-without-reference",
			body: `{"type":"ovh_keys","source":"` + ovhChainSource + `","config":{
				"mint_method":"access_keys"}}`,
			errMsg: "'access_keys' requires 'secret_spec'",
		},
		{
			// The client credential authenticates the source's own calls, and the
			// driver factory only ever sees source config — a reference parked on
			// the spec would slip past the checks that gate a chained source.
			name: "a spec-level reference on oauth2_token",
			id:   "token-spec-level-reference",
			body: `{"type":"ovh_keys","source":"` + ovhChainSource + `","config":{
				"mint_method":"oauth2_token","secret_spec":"` + ovhClientCredSpec + `"}}`,
			errMsg: "belongs on the source",
		},
		{
			// Removed outright: it created an object-storage pair that outlived
			// every lease, with nothing able to delete it afterwards.
			name: "the removed dynamic_s3 mint method",
			id:   "removed-dynamic-s3",
			body: `{"type":"ovh_keys","source":"` + ovhChainSource + `","config":{
				"mint_method":"dynamic_s3","project_id":"p","user_id":"u"}}`,
			errMsg: "mint_method",
		},
		{
			// A pair parked in spec config is the standing secret access_keys
			// exists to avoid, and nothing here would ever rotate it.
			name: "an access_keys spec carrying an inline pair",
			id:   "access-inline-pair",
			body: `{"type":"ovh_keys","source":"` + ovhChainSource + `","config":{
				"mint_method":"access_keys","secret_spec":"` + ovhPairSecretSpec + `",
				"access_key":"E2EOVHINLINEKEY00000","secret_key":"e2e-ovh-inline-not-a-real-secret"}}`,
			errMsg: "must be omitted for access_keys",
		},
	}
	for _, tt := range specs {
		t.Run(tt.name, func(t *testing.T) {
			name := "fc-ovh-spec-refused-" + tt.id
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
