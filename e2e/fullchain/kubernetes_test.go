//go:build e2e

package fullchain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The keyless kubernetes source is the one mount here that authenticates upstream
// with nothing of its own: it presents the caller's identity assertion as the
// bearer token on the TokenRequest call. There is no exchange hop, because an API
// server configured to trust the assertion's issuer accepts it directly.
//
// That makes this package's recording upstream unusually well placed. It stands in
// for the API server for BOTH hops — the mint (Warden calling TokenRequest with the
// assertion) and the gateway request that follows (the caller reaching the cluster
// with the minted ServiceAccount token) — so one server sees the whole chain, and
// the two can be told apart by path.
//
// What is NOT covered here is the cluster's half: that a real kube-apiserver
// accepts the assertion under an AuthenticationConfiguration, maps warden_role to
// groups, and enforces the resourceNames RBAC. That needs a live cluster. What this
// pins instead is that the assertion Warden sends is one such a cluster would
// accept — verified against the issuer's published JWKS, audience and all.

const (
	// kubernetesAudience is the source's assertion audience. In a real cluster it
	// must appear in the authenticator's own audiences list.
	kubernetesAudience = "https://kubernetes.e2e.example.com"

	// The namespace/service-account pairs the specs mint for. Distinct per variant
	// so the TokenRequest path itself distinguishes them.
	k8sReadonlyNamespace = "prod"
	k8sReadonlySA        = "payments-readonly"
	k8sDeployNamespace   = "prod"
	k8sDeploySA          = "deployer"

	// k8sAgentVariant mints from the agent's own inbound JWT rather than a
	// Warden-signed assertion.
	k8sAgentVariant = "agentidentity"
	// k8sDeployVariant is the second access level, on the same source.
	k8sDeployVariant = "deploy"

	k8sTokenRequestSuffix = "/token"

	// wardenIssuerURL is what the harness configures the issuer with (e2e/setup.sh
	// step 9j). A cluster authenticator pins iss to exactly this.
	wardenIssuerURL = "https://127.0.0.1:8000"
)

// kubernetesEnv is built in ensureEnv rather than here: its SourceConfig needs the
// recording upstream's URL, which does not exist until the listener is up.
var kubernetesEnv h.ProviderEnv

// buildKubernetesEnv describes the keyless mount. The source holds no token — that
// is the point — and tls_skip_verify is what lets it name the plain-HTTP recording
// upstream, the same allowance every dev cluster uses.
func buildKubernetesEnv(upstreamURL string) h.ProviderEnv {
	return h.ProviderEnv{
		Mount:      "fc-kubernetes",
		Type:       "kubernetes",
		URLKey:     "kubernetes_url",
		CredType:   "kubernetes_token",
		SourceType: "kubernetes",
		SourceConfig: map[string]string{
			"kubernetes_url":  upstreamURL,
			"auth_method":     "oidc_federation",
			"audience":        kubernetesAudience,
			"tls_skip_verify": "true",
		},
		// The mount's default spec has to request exchange like the rest: a
		// non-exchange spec on a keyless source is refused at create by the
		// test-mint, which would fatal the whole package's setup.
		CredConfig: map[string]string{
			"subject_token_source": "warden_identity",
			"service_account":      k8sReadonlySA,
			"namespace":            k8sReadonlyNamespace,
			// No audiences: the minted token is destined for the API server, so it
			// inherits the cluster's own. This is the outbound audience, unrelated
			// to the source's inbound assertion audience above.
			"ttl": "1h",
		},
		Variants: map[string]map[string]string{
			// A second access level on the same source. Nothing about the source
			// changes — only which service account is minted for.
			k8sDeployVariant: {
				"subject_token_source": "warden_identity",
				"service_account":      k8sDeploySA,
				"namespace":            k8sDeployNamespace,
				"ttl":                  "15m",
			},
			// agent_identity forwards the agent's own inbound JWT as the assertion.
			// It gets a cert role here like every variant, but no row uses that
			// role: the subject source fails closed on a cert-authenticated
			// request, so the rows below drive it through a JWT agent leg instead.
			k8sAgentVariant: {
				"subject_token_source": "agent_identity",
				"service_account":      k8sReadonlySA,
				"namespace":            k8sReadonlyNamespace,
				"ttl":                  "1h",
			},
		},
	}
}

// serveTokenRequest answers the TokenRequest hop with a canned response and lets
// every other path through as a plain 200.
//
// Installing this is not optional for any row on this mount: the upstream's default
// reply carries no status.token, which the mint rejects outright.
func serveTokenRequest(t *testing.T) {
	t.Helper()
	upstream.SetHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if !isTokenRequest(r.URL.Path) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind":       "TokenRequest",
			"apiVersion": "authentication.k8s.io/v1",
			"status": map[string]any{
				"token":               mintedTokenFor(r.URL.Path),
				"expirationTimestamp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
		})
	})
}

func isTokenRequest(path string) bool {
	return strings.HasPrefix(path, "/api/v1/namespaces/") && strings.HasSuffix(path, k8sTokenRequestSuffix)
}

// mintedTokenFor derives a token value from the path it was requested at, so a row
// asserting on the gateway hop is really asserting that the credential came from
// the service account its spec names.
func mintedTokenFor(path string) string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/namespaces/"), k8sTokenRequestSuffix)
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 {
		return "minted-token"
	}
	return "minted-token-for-" + parts[0] + "-" + parts[2]
}

// splitHops separates the two requests the upstream saw. The mint hop and the
// gateway hop both land here, so a row must say which one it means — and their
// count varies with the credential cache, which is why no row on this mount asserts
// on a total.
func splitHops(t *testing.T) (mint, gateway []h.UpstreamRequest) {
	t.Helper()
	for _, req := range upstream.Requests() {
		if isTokenRequest(req.Path) {
			mint = append(mint, req)
			continue
		}
		gateway = append(gateway, req)
	}
	return mint, gateway
}

// TestKubernetes_KeylessMintPresentsWardenAssertion is the row this file exists
// for. It checks the assertion Warden sent to the API server the way the API server
// would: verified against the issuer's published JWKS.
//
// A shape check would pass on a token no cluster would accept. Checking the
// signature against the JWKS, the audience against the source's, and the claims a
// cluster maps to a user and groups is what makes this meaningful.
func TestKubernetes_KeylessMintPresentsWardenAssertion(t *testing.T) {
	ensureEnv(t)
	serveTokenRequest(t)

	status, body, _ := h.ChainRequest(t, leaderPort, kubernetesEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Role:         kubernetesEnv.CertRole(),
	})
	if status != 200 {
		t.Fatalf("status: got %d, want 200 (body: %s)", status, body)
	}

	mint, gateway := splitHops(t)
	if len(mint) != 1 {
		t.Fatalf("expected exactly one TokenRequest hop, got %d", len(mint))
	}
	if len(gateway) != 1 {
		t.Fatalf("expected exactly one gateway hop, got %d", len(gateway))
	}

	// The mint hop went to the spec's service account, carrying the assertion.
	wantPath := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token", k8sReadonlyNamespace, k8sReadonlySA)
	if mint[0].Path != wantPath {
		t.Errorf("TokenRequest path: got %q, want %q", mint[0].Path, wantPath)
	}

	assertion := bearerOf(t, mint[0].Header.Get("Authorization"))
	claims := verifyAssertion(t, assertion)

	if got := claims["aud"]; got != kubernetesAudience {
		t.Errorf("assertion aud: got %v, want %q — a cluster pinning its audiences would reject this", got, kubernetesAudience)
	}
	if sub, _ := claims["sub"].(string); !strings.HasPrefix(sub, "wid:") {
		t.Errorf("assertion sub: got %q, want the wid: identity shape", sub)
	}
	// The claim a cluster maps to groups, and so the one an RBAC binding keys on.
	if got, _ := claims["warden_role"].(string); got != kubernetesEnv.CertRole() {
		t.Errorf("warden_role: got %q, want %q", got, kubernetesEnv.CertRole())
	}
	// A cluster pins the issuer exactly and rejects anything expired, so checking
	// both here is part of "would a real authenticator take this".
	if got, _ := claims["iss"].(string); got != wardenIssuerURL {
		t.Errorf("assertion iss: got %q, want %q", got, wardenIssuerURL)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Error("assertion carries no exp; a verifier would reject it outright")
	} else if time.Until(time.Unix(int64(exp), 0)) <= 0 {
		t.Errorf("assertion already expired at %s", time.Unix(int64(exp), 0))
	}

	// The gateway hop carries the minted ServiceAccount token — not the assertion,
	// and not the caller's own credential.
	gotAuth := gateway[0].Header.Get("Authorization")
	want := "Bearer " + mintedTokenFor(wantPath)
	if gotAuth != want {
		t.Errorf("gateway Authorization: got %q, want %q", gotAuth, want)
	}
	if strings.Contains(gotAuth, assertion) {
		t.Error("the assertion reached the gateway hop; only the minted token should")
	}
}

// TestKubernetes_AccessLevelsMintTheirOwnServiceAccount pins what separates two
// access levels on one keyless source: the spec, and nothing else.
//
// The source is identical for both — no token, one audience. Which service account
// a caller ends up as is decided by the spec its role binds, which is what a
// cluster-side resourceNames rule then constrains.
func TestKubernetes_AccessLevelsMintTheirOwnServiceAccount(t *testing.T) {
	ensureEnv(t)
	serveTokenRequest(t)

	status, body, _ := h.ChainRequest(t, leaderPort, kubernetesEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Role:         kubernetesEnv.VariantRole(k8sDeployVariant),
	})
	if status != 200 {
		t.Fatalf("status: got %d, want 200 (body: %s)", status, body)
	}

	mint, gateway := splitHops(t)
	if len(mint) != 1 {
		t.Fatalf("expected exactly one TokenRequest hop, got %d", len(mint))
	}

	wantPath := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token", k8sDeployNamespace, k8sDeploySA)
	if mint[0].Path != wantPath {
		t.Errorf("TokenRequest path: got %q, want %q — the deploy role must not mint the read-only account", mint[0].Path, wantPath)
	}

	if len(gateway) != 1 {
		t.Fatalf("expected exactly one gateway hop, got %d", len(gateway))
	}
	if got, want := gateway[0].Header.Get("Authorization"), "Bearer "+mintedTokenFor(wantPath); got != want {
		t.Errorf("gateway Authorization: got %q, want %q", got, want)
	}
}

// TestKubernetes_AgentIdentityForwardsTheAgentsOwnToken covers the other subject
// source: the agent's inbound JWT goes to the API server unchanged, so the cluster
// federates the agent's own issuer rather than Warden's.
//
// A JWT agent leg, not the usual certificate: agent_identity reuses the token
// Warden verified at the door, and fails closed when there was none.
func TestKubernetes_AgentIdentityForwardsTheAgentsOwnToken(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, kubernetesEnv)
	serveTokenRequest(t)

	agentJWT := h.GetDefaultJWT(t)

	// The mount's own JWT agent role binds its default spec, so this needs one
	// bound to the agent_identity variant instead.
	jwtRole := "fc-k8s-agentidentity"
	// Checked rather than fired and forgotten: a role that failed to create would
	// surface as a chain 4xx below, blaming the request for a missing fixture.
	if status, body := h.APIRequest(t, "POST", "auth/jwt/role/"+jwtRole, leaderPort, `{
		"token_policies":["`+kubernetesEnv.Policy()+`"],
		"cred_spec_name":"`+kubernetesEnv.VariantSpec(k8sAgentVariant)+`",
		"user_claim":"sub","token_ttl":3600}`); status >= 400 {
		t.Fatalf("create the agent_identity jwt role = %d: %s", status, body)
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+jwtRole, leaderPort, "")
	})

	status, body, _ := h.ChainRequest(t, leaderPort, kubernetesEnv, h.ChainOpts{
		AgentToken: agentJWT,
		Role:       jwtRole,
	})
	if status != 200 {
		t.Fatalf("status: got %d, want 200 (body: %s)", status, body)
	}

	mint, _ := splitHops(t)
	if len(mint) != 1 {
		t.Fatalf("expected exactly one TokenRequest hop, got %d", len(mint))
	}

	// Byte-equal to the agent's own token: nothing was minted or re-signed on the
	// way through.
	if got := bearerOf(t, mint[0].Header.Get("Authorization")); got != agentJWT {
		t.Errorf("TokenRequest bearer is not the agent's own JWT (got %d bytes, want %d)", len(got), len(agentJWT))
	}
}

// TestKubernetes_NonExchangeSpecIsRefusedAtCreate pins where the fail-closed guard
// bites.
//
// A spec that names no subject source has nothing to authenticate the mint with on
// a keyless source. That is caught at spec create by the test-mint, not deferred to
// the first request — so the operator learns immediately rather than at 3am.
func TestKubernetes_NonExchangeSpecIsRefusedAtCreate(t *testing.T) {
	ensureEnv(t)

	name := "fc-k8s-nonexchange"
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/specs/"+name, leaderPort, "") })

	status, body := h.APIRequest(t, "POST", "sys/cred/specs/"+name, leaderPort, `{
		"type":"kubernetes_token","source":"`+kubernetesEnv.Source()+`","config":{
			"service_account":"`+k8sReadonlySA+`","namespace":"`+k8sReadonlyNamespace+`"}}`)
	if status < 400 {
		t.Fatalf("creating a non-exchange spec on a keyless source returned %d, want a rejection: %s", status, body)
	}
	if !strings.Contains(string(body), "subject_token_source") {
		t.Errorf("rejection does not name what is missing: %s", body)
	}
}

// TestKubernetes_RotationPeriodRefusedOnKeylessSource pins the gate that keeps a
// keyless source out of the rotation manager. Without it the source would be
// enrolled for a rotation the driver refuses on every cycle, forever.
func TestKubernetes_RotationPeriodRefusedOnKeylessSource(t *testing.T) {
	ensureEnv(t)

	name := "fc-k8s-rotating"
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "") })

	status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leaderPort, `{
		"type":"kubernetes","rotation_period":86400,"config":{
			"kubernetes_url":"`+upstream.URL+`","auth_method":"oidc_federation",
			"audience":"`+kubernetesAudience+`","tls_skip_verify":"true"}}`)
	if status < 400 {
		t.Fatalf("creating a keyless source with a rotation_period returned %d, want a rejection: %s", status, body)
	}
	if !strings.Contains(string(body), "rotation_period") {
		t.Errorf("rejection does not name rotation_period: %s", body)
	}
}

// ============================================================================
// Assertion verification
// ============================================================================

// bearerOf strips the scheme from an Authorization header.
func bearerOf(t *testing.T, header string) string {
	t.Helper()
	if !strings.HasPrefix(header, "Bearer ") {
		t.Fatalf("Authorization is not a bearer credential: %q", header)
	}
	return strings.TrimPrefix(header, "Bearer ")
}

// verifyAssertion checks a Warden-minted assertion against the issuer's published
// JWKS and returns its claims — the same two steps a cluster's JWT authenticator
// takes, which is why this is worth doing here rather than decoding and trusting.
func verifyAssertion(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion is not a three-part JWT (%d parts)", len(parts))
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(decodeSegment(t, parts[0]), &header); err != nil {
		t.Fatalf("parse assertion header: %v", err)
	}

	key := jwksKey(t, header.Kid, header.Alg)
	signed := parts[0] + "." + parts[1]
	verifySignature(t, header.Alg, key, signed, decodeSegment(t, parts[2]))

	var claims map[string]any
	if err := json.Unmarshal(decodeSegment(t, parts[1]), &claims); err != nil {
		t.Fatalf("parse assertion claims: %v", err)
	}
	return claims
}

func decodeSegment(t *testing.T, segment string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode JWT segment: %v", err)
	}
	return decoded
}

// jwksKey fetches the issuer's published JWKS and rebuilds the key the assertion
// names. Going through the published document rather than any internal handle is
// the point: it is what a cluster would fetch.
func jwksKey(t *testing.T, kid, alg string) any {
	t.Helper()

	status, body := h.DoRequest(t, "GET", h.NodeURL(leaderPort)+"/oidc/jwks", nil, "")
	if status != 200 {
		t.Fatalf("GET /oidc/jwks = %d: %s", status, body)
	}

	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse jwks: %v (%s)", err, body)
	}

	for _, k := range doc.Keys {
		if k.Kid != kid {
			continue
		}
		switch k.Kty {
		case "RSA":
			return &rsa.PublicKey{
				N: new(big.Int).SetBytes(decodeSegment(t, k.N)),
				E: int(new(big.Int).SetBytes(decodeSegment(t, k.E)).Int64()),
			}
		case "EC":
			return &ecdsa.PublicKey{
				Curve: ecCurve(t, k.Crv),
				X:     new(big.Int).SetBytes(decodeSegment(t, k.X)),
				Y:     new(big.Int).SetBytes(decodeSegment(t, k.Y)),
			}
		default:
			t.Fatalf("jwk %s has unsupported kty %q", kid, k.Kty)
		}
	}

	t.Fatalf("assertion names kid %q (alg %s), which the published JWKS does not carry", kid, alg)
	return nil
}

func ecCurve(t *testing.T, crv string) elliptic.Curve {
	t.Helper()
	if crv != "P-256" {
		t.Fatalf("unsupported EC curve %q", crv)
	}
	return elliptic.P256()
}

// verifySignature checks the assertion's signature with the published key. A
// cluster that could not do this would reject the token, so a row that skipped it
// could pass on an assertion no cluster would accept.
func verifySignature(t *testing.T, alg string, key any, signed string, sig []byte) {
	t.Helper()

	digest := sha256.Sum256([]byte(signed))

	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("alg RS256 but the JWKS key is %T", key)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("assertion signature does not verify against the published JWKS: %v", err)
		}
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("alg ES256 but the JWKS key is %T", key)
		}
		// JWS packs ES256 as r||s fixed-width, not as the ASN.1 form ecdsa.Verify
		// would take.
		if len(sig) != 64 {
			t.Fatalf("ES256 signature is %d bytes, want 64", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			t.Fatal("assertion signature does not verify against the published JWKS")
		}
	default:
		t.Fatalf("unsupported assertion alg %q", alg)
	}
}
