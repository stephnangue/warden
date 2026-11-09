//go:build e2e

package msgraph

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Certificate authentication: the app proves itself to Entra with a PS256 client
// assertion signed by the key of a certificate registered on it — a key held in the
// source config, or one held in the store's transit engine that Warden never reads.
// The fake Entra records the assertion; each test verifies it the way Entra does,
// strictly, against the certificate.
const (
	certSource = "e2e-obo-cert"
	certSpec   = "e2e-obo-cert-graph"
	certRole   = "e2e-obo-cert-agent"

	kmsSource     = "e2e-obo-kms"
	kmsSpec       = "e2e-obo-kms-graph"
	kmsRole       = "e2e-obo-kms-agent"
	kmsSignerSpec = "e2e-entra-signer"
	// The transit key, and the store policy and JWT role a capability for it is
	// minted under. Distinct from the issuer's own keys, which share the engine.
	kmsTransitKey  = "e2e-entra-signer"
	kmsVaultPolicy = "e2e-entra-signer"
	kmsVaultRole   = "e2e-entra-signer"
)

// testCA issues the certificates these tests register: Entra takes any certificate
// that carries the app's key, so a throwaway CA is enough.
type testCA struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{key: key, cert: cert}
}

// issue returns a leaf certificate for pub, as PEM, and its DER.
func (ca *testCA) issue(t *testing.T, pub *rsa.PublicKey) (string, []byte) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "warden-entra"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), der
}

// verifyEntraCertAssertion checks a recorded client assertion as Entra does: PS256
// with a hash-length salt, the certificate named by x5t#S256 and nothing else, and
// claims binding it to this app at this tenant's token endpoint.
func verifyEntraCertAssertion(t *testing.T, assertion string, pub *rsa.PublicKey, certDER []byte) {
	t.Helper()
	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3, "not a compact JWS")

	var hdr map[string]any
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &hdr))
	sum := sha256.Sum256(certDER)
	assert.Equal(t, "PS256", hdr["alg"])
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), hdr["x5t#S256"])
	assert.NotContains(t, hdr, "kid")

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig,
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}),
		"the assertion verifies as PS256 against the certificate's key")

	claims := jwtClaims(t, assertion)
	assert.Equal(t, oboClient, claims["iss"])
	assert.Equal(t, oboClient, claims["sub"])
	assert.Equal(t, entra.URL+"/"+oboTenant+"/oauth2/v2.0/token", claims["aud"])
	assert.NotZero(t, claims["nbf"])
}

// oboGrantsOnly drops the source's own token requests (its connection probe).
func oboGrantsOnly(all []oboGrant) []oboGrant {
	var out []oboGrant
	for _, g := range all {
		if g.RequestedUse == "on_behalf_of" {
			out = append(out, g)
		}
	}
	return out
}

func jsonBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// setupOBOOverSource creates an on_behalf_of spec on source, with no actor — the
// source's own credential authenticates the app — and an agent role bound to it.
func setupOBOOverSource(t *testing.T, source, spec, role string) {
	t.Helper()
	mustAPI(t, leaderPort, "POST", "sys/cred/specs/"+spec, jsonBody(t, map[string]any{
		"type": "azure_bearer_token", "source": source,
		"config": map[string]any{
			"mint_method":          "on_behalf_of",
			"tenant_id":            oboTenant,
			"client_id":            oboClient,
			"resource_uri":         "https://graph.microsoft.com/",
			"subject_token_source": "user_identity",
		},
	}), "create the on_behalf_of spec over "+source)
	h.GrantRole(t, leaderPort, "auth/jwt/", role, h.Role{Policies: []string{policyName}, CredSpec: spec}, nil)
}

// setupCertSource creates a certificate source holding its key, issued by ca.
func setupCertSource(t *testing.T, ca *testCA) (*rsa.PrivateKey, []byte) {
	t.Helper()
	clear := func() {
		h.RevokeRole(t, leaderPort, "auth/jwt/", certRole)
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+certSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+certSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certPEM, certDER := ca.issue(t, &key.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	// Creating the source probes Entra with the certificate.
	resetRecordings(entraOK)
	mustAPI(t, leaderPort, "POST", "sys/cred/sources/"+certSource, jsonBody(t, map[string]any{
		"type": "azure",
		"config": map[string]any{
			"auth_method":    "certificate",
			"tenant_id":      oboTenant,
			"client_id":      oboClient,
			"certificate":    certPEM,
			"private_key":    keyPEM,
			"login_endpoint": entra.URL,
		},
	}), "create the certificate source")
	setupOBOOverSource(t, certSource, certSpec, certRole)
	return key, certDER
}

// TestCertificate_LocalKey_OnBehalfOf: over a certificate source, the user's token is
// the OBO assertion and the app authenticates with the certificate — no secret, no
// actor — and the delegated token reaches the upstream.
func TestCertificate_LocalKey_OnBehalfOf(t *testing.T) {
	ensureEnv(t)
	key, certDER := setupCertSource(t, newTestCA(t))

	probe := recordedGrants()
	require.NotEmpty(t, probe, "the source was probed when it was created")
	assert.Equal(t, "client_credentials", probe[0].GrantType)
	verifyEntraCertAssertion(t, probe[0].ClientAssertion, &key.PublicKey, certDER)

	resetRecordings(entraOK)
	user := userToken(t)
	status, body, _ := gatewayCallAs(t, certRole, http.MethodGet, stubMount, "v1.0/me", user, "")
	require.Equal(t, http.StatusOK, status, "%s", body)

	got := oboGrantsOnly(recordedGrants())
	require.Len(t, got, 1)
	g := got[0]
	assert.Equal(t, user, g.Assertion, "the user's token is the OBO assertion")
	assert.False(t, g.HasSecret)
	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", g.AssertionType)
	verifyEntraCertAssertion(t, g.ClientAssertion, &key.PublicKey, certDER)

	bearers := recordedBearers()
	require.Len(t, bearers, 1)
	assert.Regexp(t, `^Bearer graph-token-\d+$`, bearers[0])

	// The source shows when its certificate expires; its key stays masked.
	status, readBody := h.APIRequest(t, "GET", "sys/cred/sources/"+certSource, leaderPort, "")
	require.Equal(t, http.StatusOK, status, "%s", readBody)
	var read struct {
		Data struct {
			Config          map[string]string `json:"config"`
			CertificateInfo map[string]any    `json:"certificate_info"`
			StoredSecrets   []string          `json:"stored_secrets"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(readBody, &read))
	assert.NotEmpty(t, read.Data.CertificateInfo["not_after"])
	sum := sha256.Sum256(certDER)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), read.Data.CertificateInfo["x5t_s256"])
	assert.NotContains(t, read.Data.Config["private_key"], "PRIVATE KEY")
	assert.Equal(t, []string{"private_key"}, read.Data.StoredSecrets)
}

// TestCertificate_RefusedIsExplained: Entra refusing the certificate is reported as
// that, naming the certificate, with none of Entra's free text.
func TestCertificate_RefusedIsExplained(t *testing.T) {
	ensureEnv(t)
	setupCertSource(t, newTestCA(t))

	resetRecordings(entraCertRefused)
	t.Cleanup(func() { resetRecordings(entraOK) })
	status, body, headers := gatewayCallAs(t, certRole, http.MethodGet, graphMount, "v1.0/me", userToken(t), "")
	require.Equal(t, http.StatusForbidden, status, "%s", body)
	assert.Empty(t, headers.Values("WWW-Authenticate"), "re-authenticating the user will not help")

	_, message := graphError(t, body)
	assert.Contains(t, message, "refused the certificate assertion of app "+oboClient)
	assert.Contains(t, message, "x5t#S256")
	assert.NotContains(t, message, "not registered on application", "Entra's free text never reaches the client")
}

// provisionEntraSigningKey creates the non-exportable transit key and returns the
// public half of its latest version.
func provisionEntraSigningKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	if status, resp := h.VaultDirectRequest(t, "POST", "transit/keys/"+kmsTransitKey, `{"type":"rsa-2048"}`); status >= 400 {
		t.Fatalf("creating the signing key (status %d): %s", status, resp)
	}
	status, body := h.VaultDirectRequest(t, "GET", "transit/keys/"+kmsTransitKey, "")
	require.Equal(t, http.StatusOK, status, "%s", body)
	var read struct {
		Data struct {
			Exportable    bool `json:"exportable"`
			LatestVersion int  `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &read))
	require.False(t, read.Data.Exportable, "the key must not be readable out of the store")
	block, _ := pem.Decode([]byte(read.Data.Keys[fmt.Sprint(read.Data.LatestVersion)].PublicKey))
	require.NotNil(t, block, "no public key: %s", body)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return pub.(*rsa.PublicKey)
}

// TestCertificate_KMSKey_OnBehalfOf: the certificate's key is held in the store's
// transit engine. Each mint fetches a capability to sign with it, as the agent, under a
// role that may only sign with that key — and the assertion Entra receives verifies
// against the key Warden never held.
func TestCertificate_KMSKey_OnBehalfOf(t *testing.T) {
	ensureEnv(t)

	clear := func() {
		h.RevokeRole(t, leaderPort, "auth/jwt/", kmsRole)
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+kmsSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+kmsSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+kmsSignerSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	pub := provisionEntraSigningKey(t)
	certPEM, certDER := newTestCA(t).issue(t, pub)

	// The capability may sign with this one key and read its public half; nothing else.
	policy := fmt.Sprintf("path \"transit/sign/%s\" { capabilities = [\"update\"] }\n"+
		"path \"transit/keys/%s\" { capabilities = [\"read\"] }\n", kmsTransitKey, kmsTransitKey)
	if status, resp := h.VaultDirectRequest(t, "POST", "sys/policies/acl/"+kmsVaultPolicy,
		jsonBody(t, map[string]string{"policy": policy})); status >= 400 {
		t.Fatalf("create the signing policy (status %d): %s", status, resp)
	}
	if status, resp := h.VaultDirectRequest(t, "POST", "auth/jwt-warden/role/"+kmsVaultRole, fmt.Sprintf(`{
		"role_type":"jwt","bound_audiences":["https://vault.e2e.warden"],
		"bound_claims_type":"glob","bound_claims":{"sub":["wid:root:*:e2e-agent"]},"user_claim":"sub",
		"token_policies":[%q],"token_type":"batch","token_ttl":"120s"}`, kmsVaultPolicy)); status >= 400 {
		t.Fatalf("create the signing role (status %d): %s", status, resp)
	}

	mustAPI(t, leaderPort, "POST", "sys/cred/specs/"+kmsSignerSpec, jsonBody(t, map[string]any{
		"type": "key_value", "source": "vault-warden-fed-e2e",
		"config": map[string]any{
			"mint_method":          "transit_signer",
			"jwt_role":             kmsVaultRole,
			"transit_mount":        "transit",
			"transit_key":          kmsTransitKey,
			"signing_alg":          "PS256",
			"payload.client_id":    oboClient,
			"subject_token_source": "warden_identity",
		},
	}), "create the signer spec")

	resetRecordings(entraOK)
	mustAPI(t, leaderPort, "POST", "sys/cred/sources/"+kmsSource, jsonBody(t, map[string]any{
		"type": "azure",
		"config": map[string]any{
			"auth_method":      "certificate",
			"tenant_id":        oboTenant,
			"client_id":        oboClient,
			"certificate":      certPEM,
			"secret_spec":      kmsSignerSpec,
			"secret_cache_ttl": "5m",
			"login_endpoint":   entra.URL,
		},
	}), "create the KMS certificate source")
	assert.Empty(t, recordedGrants(), "a KMS source has no capability to probe Entra with until a mint")
	setupOBOOverSource(t, kmsSource, kmsSpec, kmsRole)

	resetRecordings(entraOK)
	user := userToken(t)
	status, body, _ := gatewayCallAs(t, kmsRole, http.MethodGet, stubMount, "v1.0/me", user, "")
	require.Equal(t, http.StatusOK, status, "%s", body)

	got := oboGrantsOnly(recordedGrants())
	require.Len(t, got, 1)
	assert.Equal(t, user, got[0].Assertion)
	assert.False(t, got[0].HasSecret)
	verifyEntraCertAssertion(t, got[0].ClientAssertion, pub, certDER)

	bearers := recordedBearers()
	require.Len(t, bearers, 1)
	assert.Regexp(t, `^Bearer graph-token-\d+$`, bearers[0])

	// The source stores no secret at all.
	status, readBody := h.APIRequest(t, "GET", "sys/cred/sources/"+kmsSource, leaderPort, "")
	require.Equal(t, http.StatusOK, status, "%s", readBody)
	assert.NotContains(t, string(readBody), "stored_secrets")
}
