//go:build e2e

package fullchain

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// A client assertion signed by a key Warden never holds.
//
// The unit tests prove the driver builds and sends the right assertion against a fake
// signer. What only a row here can prove is that the whole arrangement holds against a
// real store: a federated login pinned to a narrow role, a capability minted from it,
// carried through chaining, and spent on a signature that a relying party actually
// verifies against the key's public half. If any link produced plausible-but-wrong
// bytes — a DER signature where JWS wants R‖S, a kid naming the wrong version, a
// digest over the wrong input — the stand-in below refuses it, which a stand-in that
// merely recorded the assertion would not.
const (
	// Distinct from the issuer's own transit keys (warden-oidc-*), which live in this
	// same engine: colliding with those would corrupt the issuer and break every suite
	// that depends on it.
	kmsTransitKey = "e2e-tx-client-assertion"

	kmsSignerPolicy = "e2e-tx-signer"
	kmsSignerRole   = "e2e-tx-signer"

	kmsSignerSpec     = "fc-kms-signer"
	kmsExchangeSource = "fc-kms-tx-src"
	kmsExchangeSpec   = "fc-kms-tx-cred"
	kmsChainRole      = "fc-kms-tx"

	kmsClientID = "kms-tx-client"
	kmsBearer   = "kms-tx-bearer-not-real"
)

// kmsAssertion is one client assertion the stand-in received, after verification.
type kmsAssertion struct {
	verified bool
	reason   string
	kid      string
	alg      string
	iss      string
	sub      string
	aud      string
	clientID string
}

// serveAssertionVerifyingSTS stands in for the authorization server, and unlike the
// secret-based stand-in it actually checks the assertion: signature against the key's
// published public half, then the claims that bind it to this client and this endpoint.
// Verification is the point — an STS that only recorded the assertion would pass against
// a signer that produced well-formed nonsense.
//
// pubPEM is fetched by the caller before the server starts, so the handler never has to
// reach the store (or call t.Fatalf off the test goroutine).
func serveAssertionVerifyingSTS(t *testing.T, pubPEM string) (*httptest.Server, func() []kmsAssertion) {
	t.Helper()

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatalf("the signing key's public half is not PEM: %q", pubPEM)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the signing key's public half: %v", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("the signing key is %T, want an RSA public key", parsed)
	}

	var (
		mu   sync.Mutex
		seen []kmsAssertion
	)
	record := func(a kmsAssertion) {
		mu.Lock()
		seen = append(seen, a)
		mu.Unlock()
	}

	mux := http.NewServeMux()
	mux.HandleFunc(txTokenPath, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			record(kmsAssertion{reason: "unparsable form: " + err.Error()})
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		a := kmsAssertion{clientID: r.Form.Get("client_id")}
		assertion := r.Form.Get("client_assertion")

		fail := func(reason string) {
			a.reason = reason
			record(a)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		}

		if got := r.Form.Get("client_assertion_type"); got != clientAssertionTypeJWTBearer {
			fail("client_assertion_type " + got)
			return
		}
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			fail(fmt.Sprintf("assertion has %d segments", len(parts)))
			return
		}

		var hdr map[string]string
		if raw, derr := base64.RawURLEncoding.DecodeString(parts[0]); derr != nil {
			fail("undecodable header: " + derr.Error())
			return
		} else if derr = json.Unmarshal(raw, &hdr); derr != nil {
			fail("unparsable header: " + derr.Error())
			return
		}
		a.kid, a.alg = hdr["kid"], hdr["alg"]

		var claims map[string]interface{}
		if raw, derr := base64.RawURLEncoding.DecodeString(parts[1]); derr != nil {
			fail("undecodable claims: " + derr.Error())
			return
		} else if derr = json.Unmarshal(raw, &claims); derr != nil {
			fail("unparsable claims: " + derr.Error())
			return
		}
		a.iss, _ = claims["iss"].(string)
		a.sub, _ = claims["sub"].(string)
		a.aud, _ = claims["aud"].(string)

		sig, derr := base64.RawURLEncoding.DecodeString(parts[2])
		if derr != nil {
			fail("undecodable signature: " + derr.Error())
			return
		}
		// The check that matters: the signature is over exactly the bytes on the wire,
		// and it was made by the key whose public half the store publishes.
		digest := crypto.SHA256.New()
		digest.Write([]byte(parts[0] + "." + parts[1]))
		if verr := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest.Sum(nil), sig); verr != nil {
			fail("signature does not verify: " + verr.Error())
			return
		}
		if a.iss != kmsClientID || a.sub != kmsClientID {
			fail(fmt.Sprintf("iss/sub %q/%q, want %q", a.iss, a.sub, kmsClientID))
			return
		}

		a.verified = true
		record(a)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + kmsBearer + `","token_type":"Bearer","expires_in":1800}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func() []kmsAssertion {
		mu.Lock()
		defer mu.Unlock()
		return append([]kmsAssertion(nil), seen...)
	}
}

// clientAssertionTypeJWTBearer is the RFC 7523 client-assertion type, repeated here so
// the stand-in checks the wire value rather than trusting the driver's constant.
const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// provisionSigningKey creates the non-exportable signing key and returns the public half
// of its latest version, which is what the relying party would hold.
func provisionSigningKey(t *testing.T) (pubPEM string, version int) {
	t.Helper()

	// Idempotent: a create against an existing key is accepted and changes nothing.
	if status, resp := h.VaultDirectRequest(t, "POST", "transit/keys/"+kmsTransitKey,
		`{"type":"rsa-2048"}`); status >= 400 {
		t.Fatalf("creating the signing key (status %d): %s", status, resp)
	}

	status, body := h.VaultDirectRequest(t, "GET", "transit/keys/"+kmsTransitKey, "")
	if status != 200 {
		t.Fatalf("reading the signing key (status %d): %s", status, body)
	}
	var read struct {
		Data struct {
			Exportable    bool `json:"exportable"`
			LatestVersion int  `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &read); err != nil {
		t.Fatalf("parsing the signing key: %v (%s)", err, body)
	}
	if read.Data.Exportable {
		t.Fatal("the signing key is exportable; the whole arrangement assumes it cannot be read out")
	}
	version = read.Data.LatestVersion
	pubPEM = read.Data.Keys[fmt.Sprint(version)].PublicKey
	if pubPEM == "" {
		t.Fatalf("no public key for version %d: %s", version, body)
	}
	return pubPEM, version
}

// setupKMSAssertionChain provisions the narrow role the capability is minted under, then
// the three objects the chain needs: the signing-capability spec, the token_exchange
// source that references it, and the consuming spec a role binds to.
func setupKMSAssertionChain(t *testing.T, stsURL, signingAlg string) {
	t.Helper()

	mustWrite := func(method, path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}
	mustVault := func(method, path, body, what string) {
		t.Helper()
		if status, resp := h.VaultDirectRequest(t, method, path, body); status >= 400 {
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+kmsChainRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+kmsExchangeSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+kmsExchangeSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+kmsSignerSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// The capability may do exactly two things: sign with this one key, and read its
	// metadata. Everything the design claims about blast radius rests on this policy.
	policy := fmt.Sprintf(
		"path \"transit/sign/%s\" { capabilities = [\"update\"] }\n"+
			"path \"transit/keys/%s\" { capabilities = [\"read\"] }\n",
		kmsTransitKey, kmsTransitKey)
	policyBody, err := json.Marshal(map[string]string{"policy": policy})
	if err != nil {
		t.Fatalf("encoding the signing policy: %v", err)
	}
	mustVault("POST", "sys/policies/acl/"+kmsSignerPolicy, string(policyBody),
		"create the narrow signing policy")

	// A role of its own on the Warden-issuer mount, carrying only that policy. Batch
	// and short-lived: the capability is minted per request and never revoked, so a
	// tracked token would leave one behind on every mint. Claim bindings mirror the
	// broad role the same mount already carries.
	mustVault("POST", "auth/jwt-warden/role/"+kmsSignerRole, fmt.Sprintf(`{
		"role_type":"jwt","bound_audiences":["https://vault.e2e.warden"],
		"bound_claims":{"warden_sub":["%s","%s"]},"user_claim":"warden_sub",
		"token_policies":["%s"],"token_type":"batch","token_ttl":"120s"}`,
		txAgentA, txAgentB, kmsSignerPolicy),
		"create the narrow signing role")

	// The capability spec. Session-pinned, so it is minted as the caller and the login
	// happens under the narrow role rather than the source's broad one. client_id
	// travels in the payload because the consumer needs it and this driver only carries
	// it.
	mustWrite("POST", "sys/cred/specs/"+kmsSignerSpec, fmt.Sprintf(`{
		"type":"key_value","source":"vault-warden-fed-e2e","config":{
			"mint_method":"transit_signer",
			"jwt_role":%q,
			"transit_mount":"transit",
			"transit_key":%q,
			"signing_alg":%q,
			"payload.client_id":%q,
			"subject_token_source":"warden_identity"}}`,
		kmsSignerRole, kmsTransitKey, signingAlg, kmsClientID),
		"create the signing-capability spec")

	// The source stores no key and no client id: both reach it through the chain. No
	// secret_cache_ttl, so each mint takes a fresh capability and none is held longer
	// than the exchange that uses it.
	mustWrite("POST", "sys/cred/sources/"+kmsExchangeSource, fmt.Sprintf(`{
		"type":"token_exchange","config":{
			"token_url":%q,"grant":"rfc8693","client_auth":"kms_private_key_jwt",
			"tls_skip_verify":"true","secret_spec":%q}}`,
		stsURL+txTokenPath, kmsSignerSpec),
		"create the token_exchange source")

	mustWrite("POST", "sys/cred/specs/"+kmsExchangeSpec, fmt.Sprintf(`{
		"type":"oauth_bearer_token","source":%q,"config":{
			"subject_token_source":"agent_identity",
			"audience":"https://api.internal.example.com"}}`, kmsExchangeSource),
		"create the consuming spec")

	mustWrite("POST", "auth/jwt/role/"+kmsChainRole, fmt.Sprintf(`{
		"token_policies":["%s"],"cred_spec_name":%q,
		"user_claim":"sub","token_ttl":3600}`, restEnv.Policy(), kmsExchangeSpec),
		"create the consuming role")
}

// TestKMSClientAssertion_SignsWithAKeyWardenNeverHolds drives the whole chain: an agent
// request reaches a mount, which mints a downstream bearer by authenticating to an STS
// with an assertion signed inside the store. Nothing in Warden's configuration or
// storage holds the private key, and the relying party verifies the signature against
// the key's published public half before issuing anything.
func TestKMSClientAssertion_SignsWithAKeyWardenNeverHolds(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)

	pubPEM, version := provisionSigningKey(t)
	sts, assertions := serveAssertionVerifyingSTS(t, pubPEM)
	setupKMSAssertionChain(t, sts.URL, "RS256")
	upstream.Reset()

	agentToken := h.GetJWT(t, txAgentA, "agent-secret")
	mint := func(what string) {
		t.Helper()
		status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
			AgentToken: agentToken,
			Role:       kmsChainRole,
		})
		if status != 200 {
			t.Fatalf("%s got status %d: %s", what, status, body)
		}
	}

	mint("first request")
	// The same caller again: the minted bearer is cached, so this must not cost another
	// exchange — and therefore not another signature.
	mint("second request")

	got := assertions()
	if len(got) == 0 {
		t.Fatal("the STS received no client assertion; the exchange never authenticated")
	}
	for i, a := range got {
		if !a.verified {
			t.Fatalf("assertion %d was refused: %s", i, a.reason)
		}
	}
	if len(got) != 1 {
		t.Errorf("the STS saw %d exchanges for one caller, want 1 (the minted bearer should be cached)", len(got))
	}

	a := got[0]
	if want := fmt.Sprintf("%s-v%d", kmsTransitKey, version); a.kid != want {
		t.Errorf("assertion kid %q, want %q — the kid must name the exact version that signed, or a relying party cannot select the right public key", a.kid, want)
	}
	if a.alg != "RS256" {
		t.Errorf("assertion alg %q, want RS256", a.alg)
	}
	if a.clientID != kmsClientID {
		t.Errorf("client_id %q on the wire, want %q", a.clientID, kmsClientID)
	}
	if want := sts.URL + txTokenPath; a.aud != want {
		t.Errorf("assertion aud %q, want the token endpoint %q", a.aud, want)
	}

	// And the bearer the STS issued for that assertion is what reached the upstream.
	var injected []string
	for _, req := range upstream.Requests() {
		if got := req.Header.Get("X-Custom-Auth"); got != "" {
			injected = append(injected, got)
		}
	}
	if len(injected) == 0 {
		t.Fatal("no proxied request carried an injected credential")
	}
	for i, v := range injected {
		if !strings.Contains(v, kmsBearer) {
			t.Errorf("proxied request %d carried %q, want the bearer minted against the signed assertion", i, v)
		}
	}
}

// TestKMSClientAssertion_RefusesAKeyItCannotUse: the capability is validated against the
// real key when it is minted, so an algorithm the key cannot sign fails there — naming
// the key — rather than as an assertion the STS rejects for reasons it will not explain.
func TestKMSClientAssertion_RefusesAKeyItCannotUse(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)

	pubPEM, _ := provisionSigningKey(t)
	sts, assertions := serveAssertionVerifyingSTS(t, pubPEM)
	// ES256 against an RSA key: a mismatch only the store can settle, so the chain is
	// built asking for it from the start rather than edited afterwards — a referenced
	// spec cannot be replaced while something points at it.
	setupKMSAssertionChain(t, sts.URL, "ES256")
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
		AgentToken: h.GetJWT(t, txAgentA, "agent-secret"),
		Role:       kmsChainRole,
	})
	if status == 200 {
		t.Fatalf("the mint succeeded with an algorithm the key cannot sign: %s", body)
	}
	if !strings.Contains(string(body), kmsTransitKey) {
		t.Errorf("the failure did not name the key: %s", body)
	}
	if n := len(assertions()); n != 0 {
		t.Errorf("the STS saw %d assertions; the mismatch should have failed before anything was sent", n)
	}
}
