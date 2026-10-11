//go:build e2e

package fullchain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// An oauth2 source authenticating with a client assertion.
//
// The same arrangement as the token_exchange rows in transit_signer_test.go, with an
// oauth2 source in front: a client_credentials grant whose client authenticates with an
// assertion signed inside the store, by a key nothing in Warden holds. The stand-in STS
// verifies every assertion against the public half before issuing anything.
const (
	oauth2KMSSignerSpec = "fc-kms-oauth2-signer"
	oauth2KMSSource     = "fc-kms-oauth2-src"
	oauth2KMSSpec       = "fc-kms-oauth2-cred"
	oauth2KMSRole       = "fc-kms-oauth2"

	oauth2KeySource = "fc-key-oauth2-src"
	oauth2KeySpec   = "fc-key-oauth2-cred"
	oauth2KeyRole   = "fc-key-oauth2"
)

// e2eWrite issues a Warden API write and fails the test on anything but success.
func e2eWrite(t *testing.T, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

// provisionKMSSignerRole creates the narrow role a signing capability is minted under:
// a policy allowing exactly sign and key-read on the one key, on a batch, short-lived
// role on the Warden-issuer mount. Idempotent, so rows that share the key can each call
// it.
func provisionKMSSignerRole(t *testing.T) {
	t.Helper()
	mustVault := func(method, path, body, what string) {
		t.Helper()
		if status, resp := h.VaultDirectRequest(t, method, path, body); status >= 400 {
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}
	policy := fmt.Sprintf(
		"path \"transit/sign/%s\" { capabilities = [\"update\"] }\n"+
			"path \"transit/keys/%s\" { capabilities = [\"read\"] }\n",
		kmsTransitKey, kmsTransitKey)
	policyBody, err := json.Marshal(map[string]string{"policy": policy})
	if err != nil {
		t.Fatalf("encoding the signing policy: %v", err)
	}
	mustVault("POST", "sys/policies/acl/"+kmsSignerPolicy, string(policyBody), "create the narrow signing policy")
	mustVault("POST", "auth/jwt-warden/role/"+kmsSignerRole, fmt.Sprintf(`{
		"role_type":"jwt","bound_audiences":["https://vault.e2e.warden"],
		"bound_claims_type":"glob","bound_claims":{"sub":["wid:root:*:%s","wid:root:*:%s"]},"user_claim":"sub",
		"token_policies":["%s"],"token_type":"batch","token_ttl":"120s"}`,
		txAgentA, txAgentB, kmsSignerPolicy),
		"create the narrow signing role")
}

// bindOAuth2Chain creates the consuming spec on source and a role that mints it.
func bindOAuth2Chain(t *testing.T, source, spec, role string) {
	t.Helper()
	e2eWrite(t, "POST", "sys/cred/specs/"+spec, fmt.Sprintf(`{
		"type":"oauth_bearer_token","source":%q,"config":{"scope":"api.read"}}`, source),
		"create the consuming oauth2 spec")
	e2eWrite(t, "POST", "auth/jwt/role/"+role, fmt.Sprintf(`{
		"token_policies":["%s"],"cred_spec_name":%q,
		"user_claim":"sub","token_ttl":3600}`, restEnv.Policy(), spec),
		"create the consuming role")
}

// mintThroughRole makes one gateway request under role and fails on anything but 200.
func mintThroughRole(t *testing.T, role, what string) {
	t.Helper()
	status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
		AgentToken: h.GetJWT(t, txAgentA, "agent-secret"),
		Role:       role,
	})
	if status != 200 {
		t.Fatalf("%s got status %d: %s", what, status, body)
	}
}

// assertBearerInjected checks that the bearer the STS issued is what reached the
// upstream.
func assertBearerInjected(t *testing.T) {
	t.Helper()
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

// TestOAuth2KMSClientAssertion_SignsWithAKeyWardenNeverHolds drives an oauth2
// client_credentials mint whose client authenticates with kms_private_key_jwt: the
// capability is minted as the caller under the narrow role, carried through chaining,
// and spent on an assertion the STS verifies against the key's published public half.
func TestOAuth2KMSClientAssertion_SignsWithAKeyWardenNeverHolds(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)

	pubPEM, version := provisionSigningKey(t)
	sts, assertions := serveAssertionVerifyingSTS(t, pubPEM)
	provisionKMSSignerRole(t)

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+oauth2KMSRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+oauth2KMSSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+oauth2KMSSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+oauth2KMSSignerSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	e2eWrite(t, "POST", "sys/cred/specs/"+oauth2KMSSignerSpec, fmt.Sprintf(`{
		"type":"key_value","source":"vault-warden-fed-e2e","config":{
			"mint_method":"transit_signer","jwt_role":%q,"transit_mount":"transit",
			"transit_key":%q,"signing_alg":"RS256","payload.client_id":%q,
			"subject_token_source":"warden_identity"}}`,
		kmsSignerRole, kmsTransitKey, kmsClientID),
		"create the signing-capability spec")

	// The source stores no key and no client id: both reach it through the chain.
	e2eWrite(t, "POST", "sys/cred/sources/"+oauth2KMSSource, fmt.Sprintf(`{
		"type":"oauth2","config":{
			"token_url":%q,"client_auth":"kms_private_key_jwt",
			"tls_skip_verify":"true","secret_spec":%q}}`,
		sts.URL+txTokenPath, oauth2KMSSignerSpec),
		"create the oauth2 source")
	bindOAuth2Chain(t, oauth2KMSSource, oauth2KMSSpec, oauth2KMSRole)
	upstream.Reset()

	mintThroughRole(t, oauth2KMSRole, "the request")

	got := assertions()
	if len(got) != 1 {
		t.Fatalf("the STS saw %d client assertions, want 1", len(got))
	}
	a := got[0]
	if !a.verified {
		t.Fatalf("the assertion was refused: %s", a.reason)
	}
	if want := fmt.Sprintf("%s-v%d", kmsTransitKey, version); a.kid != want {
		t.Errorf("assertion kid %q, want %q", a.kid, want)
	}
	if a.clientID != kmsClientID {
		t.Errorf("client_id %q on the wire, want %q", a.clientID, kmsClientID)
	}
	if want := sts.URL + txTokenPath; a.aud != want {
		t.Errorf("assertion aud %q, want the token endpoint %q", a.aud, want)
	}
	assertBearerInjected(t)
}

// TestOAuth2PrivateKeyJWT_SignsWithTheSourceKey: the inline form. The source holds the
// key; the STS verifies the assertion against its public half.
func TestOAuth2PrivateKeyJWT_SignsWithTheSourceKey(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	sts, assertions := serveAssertionVerifyingSTS(t, pubPEM)

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+oauth2KeyRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+oauth2KeySpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+oauth2KeySource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	source, err := json.Marshal(map[string]interface{}{
		"type": "oauth2",
		"config": map[string]string{
			"token_url":            sts.URL + txTokenPath,
			"client_auth":          "private_key_jwt",
			"client_id":            kmsClientID,
			"private_key":          privPEM,
			"client_assertion_kid": "inline-key",
			"tls_skip_verify":      "true",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e2eWrite(t, "POST", "sys/cred/sources/"+oauth2KeySource, string(source), "create the oauth2 source")
	bindOAuth2Chain(t, oauth2KeySource, oauth2KeySpec, oauth2KeyRole)

	// The key is masked on read, like any secret the source holds.
	if status, body := h.APIRequest(t, "GET", "sys/cred/sources/"+oauth2KeySource, leaderPort, ""); status != 200 {
		t.Fatalf("reading the source (status %d): %s", status, body)
	} else if strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatalf("the source's private_key was returned unmasked: %s", body)
	}

	upstream.Reset()
	before := len(assertions()) // the spec's create-time test mint and verification already authenticated
	mintThroughRole(t, oauth2KeyRole, "the request")

	got := assertions()[before:]
	if len(got) != 1 {
		t.Fatalf("the STS saw %d client assertions for the request, want 1", len(got))
	}
	if a := got[0]; !a.verified {
		t.Fatalf("the assertion was refused: %s", a.reason)
	} else if a.kid != "inline-key" {
		t.Errorf("assertion kid %q, want the source's %q", a.kid, "inline-key")
	}
	assertBearerInjected(t)
}
