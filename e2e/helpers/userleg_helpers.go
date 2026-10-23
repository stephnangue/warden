//go:build e2e

package helpers

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Per-user (secondary principal) test environment ---
//
// These build the one shape the user leg needs and the rest of the e2e suite
// never exercises: a mount whose AGENT arrives out of band (a client
// certificate) while Authorization is free to carry a USER credential.
//
// Two distinct Hydra clients stand in for the two principals — the agent
// authenticates by certificate, the user by JWT — so per-user attribution is
// provable rather than assumed: the two have different `sub` values.

const (
	// UserLegMount is the provider mount opted into the user leg.
	UserLegMount = "vault-user"

	// UserLegMountDescription is asserted as `resource_name` in the protected
	// resource metadata document.
	UserLegMountDescription = "Vault for the e2e platform team"

	// UserLegAuthMount is the auth mount that authenticates USER credentials.
	// Deliberately separate from auth/jwt/ (the agent mount) so a token valid
	// for one leg is not silently valid for the other: it admits humans only.
	UserLegAuthMount = "auth/user-jwt/"

	// UserLegAgentRole is the role the stock agent-* certificates are granted
	// on the user-leg mount.
	UserLegAgentRole = "e2e-userleg-agent"

	// UserLegResourceURL is the external base advertised in metadata. Pinned to
	// node 1 because the setting is deployment-wide while the cluster has three
	// nodes; document *content* is node-independent, so standby tests still work.
	UserLegResourceURL = "https://127.0.0.1:8500"

	// HydraIssuer is what the user auth mount's OIDC discovery URL resolves to,
	// and therefore what metadata advertises as the authorization server.
	HydraIssuer = "http://localhost:4444"
)

// UserJWT returns a JWT for the USER principal — a different Hydra client, and
// therefore a different `sub`, than GetDefaultJWT's agent.
func UserJWT(t *testing.T) string {
	t.Helper()
	return GetJWT(t, "e2e-pipeline", "pipeline-secret")
}

// SetupUserLegEnv builds a provider mount whose agent is a client certificate
// and whose user rides Authorization, plus the protected resource metadata
// configuration. Returns the CA for minting agent certificates.
//
// Reuses SetupCertAuth for the agent leg: a certificate is the cleanest way to
// occupy the agent slot without touching Authorization, which is exactly the
// shape the feature exists to enable.
func SetupUserLegEnv(t *testing.T, port int) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()

	// Best-effort cleanup first. A previous run that failed mid-setup leaves
	// mounts behind, and every subsequent attempt would then fail with 409 —
	// turning one real failure into a cascade that hides it.
	TeardownUserLegEnv(t, port)

	caCertPEM, caKey = SetupCertAuth(t, port)

	// User auth mount — same Hydra issuer, separate mount from the agent's, so a
	// token valid for one leg is not silently valid for the other.
	mustAPI(t, port, "POST", "sys/auth/user-jwt", `{"type":"jwt"}`, "mount user-jwt auth")
	time.Sleep(time.Second)

	writeUserLegAuthConfig(t, port, nil)

	// Provider mount. The description becomes `resource_name` in metadata.
	mustAPI(t, port, "POST", "sys/providers/"+UserLegMount,
		fmt.Sprintf(`{"type":"vault","description":%q}`, UserLegMountDescription),
		"mount provider")
	time.Sleep(time.Second)

	// Address and auth config go in one write: the vault provider rejects a
	// config that does not carry auto_auth_path, so they cannot be split.
	mustAPI(t, port, "PUT", UserLegMount+"/config",
		fmt.Sprintf(`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"timeout":"30s",`+
			`"auto_auth_path":"auth/cert/","user_auth_path":%q}`,
			UserLegAuthMount),
		"configure provider")

	mustAPI(t, port, "POST", "sys/policies/cbp/"+UserLegMount+"-access",
		fmt.Sprintf(`{"policy":"path \"%s/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\npath \"%s/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`,
			UserLegMount, UserLegMount),
		"create policy")

	// The agent's role, bound to a credential spec so a successful request
	// actually mints something, granted to the stock agent-* certificates.
	GrantRole(t, port, "auth/cert/", UserLegAgentRole,
		Role{Policies: []string{UserLegMount + "-access"}, CredSpec: "vault-token-reader"},
		Rule{"cn": {"agent-*"}})

	EnableProtectedResourceMetadata(t, port)

	return caCertPEM, caKey
}

// writeUserLegAuthConfig writes the user auth mount's whole configuration:
// Hydra's issuer, the audience the suites' tokens carry, a human entity kind,
// and facts (none when nil), which become the user's metadata.
func writeUserLegAuthConfig(t *testing.T, port int, facts map[string]string) {
	t.Helper()
	if facts == nil {
		facts = map[string]string{}
	}
	mustAPI(t, port, "PUT", "auth/user-jwt/config", jsonBody(t, map[string]any{
		"mode":               "oidc",
		"oidc_discovery_url": HydraIssuer,
		"bound_issuer":       HydraIssuer,
		"bound_audiences":    []string{HydraAudience},
		"user_claim":         "sub",
		"entity_kind":        "human",
		"facts":              facts,
	}), "configure user-jwt auth")
}

// UserLegJWTRole is a role scoped to the user-leg mount, granted to agents of
// auth/jwt/, for tests that swap the certificate agent for a JWT one. The
// stock e2e-reader role grants vault/gateway*, so reusing it would fail
// authorization instead of exercising the agent channel under test.
const UserLegJWTRole = "e2e-userleg-jwt"

// CreateUserLegJWTRole creates that role and its grant. Idempotent.
func CreateUserLegJWTRole(t *testing.T, port int) {
	t.Helper()
	GrantRole(t, port, "auth/jwt/", UserLegJWTRole,
		Role{Policies: []string{UserLegMount + "-access"}, CredSpec: "vault-token-reader"}, nil)
}

// SetUserLegAgentPath repoints the mount's AGENT leg while leaving the user leg
// intact. Lets a test swap a certificate agent for a JWT one without rebuilding
// the whole environment.
func SetUserLegAgentPath(t *testing.T, port int, autoAuthPath, defaultRole string) {
	t.Helper()
	body := fmt.Sprintf(`{"auto_auth_path":%q,"user_auth_path":%q`,
		autoAuthPath, UserLegAuthMount)
	if defaultRole != "" {
		body += fmt.Sprintf(`,"default_role":%q`, defaultRole)
	}
	body += "}"
	mustAPI(t, port, "POST", UserLegMount+"/config", body, "configure user leg")
}

// mustAPI issues an API request and fails the test unless it succeeded.
// Accepts 201 as well as 200/204 — role creation returns Created.
func mustAPI(t *testing.T, port int, method, path, body, what string) {
	t.Helper()
	status, resp := APIRequest(t, method, path, port, body)
	switch status {
	case 200, 201, 204:
		return
	default:
		t.Fatalf("%s (status %d): %s", what, status, string(resp))
	}
}

// TeardownUserLegEnv removes everything SetupUserLegEnv created.
func TeardownUserLegEnv(t *testing.T, port int) {
	t.Helper()
	TeardownUserLegEnvBestEffort(port)
}

// TeardownUserLegEnvBestEffort is TeardownUserLegEnv without a *testing.T, for
// use from TestMain — where a zero-value T cannot be used, because t.Fatalf
// calls runtime.Goexit and deadlocks the process outside a test goroutine.
// Every call is best-effort: cleanup must not fail a run that already passed.
func TeardownUserLegEnvBestEffort(port int) {
	token := rootTokenBestEffort()
	del := func(path string) {
		TryRequest("DELETE", fmt.Sprintf("%s/v1/%s", NodeURL(port), path),
			map[string]string{"X-Warden-Token": token}, "")
	}
	TryRequest("POST", fmt.Sprintf("%s/v1/sys/protected-resource/config", NodeURL(port)),
		map[string]string{"X-Warden-Token": token}, `{"resource_url":""}`)
	RevokeRoleBestEffort(port, "auth/cert/", UserLegAgentRole)
	RevokeRoleBestEffort(port, "auth/jwt/", UserLegJWTRole)
	del("sys/policies/cbp/" + UserLegMount + "-access")
	del("sys/providers/" + UserLegMount)
	del("sys/auth/user-jwt")
	del("sys/auth/cert")
	time.Sleep(time.Second)
}

// rootTokenBestEffort reads the root token without a *testing.T.
func rootTokenBestEffort() string {
	b, err := os.ReadFile(filepath.Join(E2EDir(), ".root_token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// EnableProtectedResourceMetadata turns on RFC 9728 metadata publication.
func EnableProtectedResourceMetadata(t *testing.T, port int) {
	t.Helper()
	status, body := APIRequest(t, "POST", "sys/protected-resource/config", port,
		fmt.Sprintf(`{"resource_url":%q,"cache_ttl":"1h"}`, UserLegResourceURL))
	if status != 200 && status != 204 {
		t.Fatalf("enable protected resource metadata (status %d): %s", status, string(body))
	}
}

// DisableProtectedResourceMetadata clears the master switch, so every metadata
// path 404s while mounts keep their user_auth_path.
func DisableProtectedResourceMetadata(t *testing.T, port int) {
	t.Helper()
	APIRequest(t, "POST", "sys/protected-resource/config", port, `{"resource_url":""}`)
}

// DoRequestWithResponseHeaders is DoRequest plus the response headers. The user
// leg is largely a header protocol — WWW-Authenticate carries the challenge,
// Cache-Control bounds document staleness — so asserting only status and body
// would miss most of what these tests exist to check.
func DoRequestWithResponseHeaders(t *testing.T, method, rawURL string, headers map[string]string, body string) (int, []byte, map[string][]string) {
	t.Helper()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	applyHeaders(req, headers)
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed e2e cert
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, resp.Header
}

// PRMPath builds the well-known URL for a mount's metadata on a given node.
func PRMPath(port int, mount string) string {
	return fmt.Sprintf("%s/.well-known/oauth-protected-resource/v1/%s", NodeURL(port), mount)
}

// UserLegRequest makes a gateway request to the user-leg mount with the agent
// presented as a client certificate and the given headers merged in.
func UserLegRequest(t *testing.T, port int, agentCertPEM string, headers map[string]string) (int, []byte) {
	t.Helper()
	all := map[string]string{"X-Warden-Role": UserLegAgentRole}
	if agentCertPEM != "" {
		all["X-SSL-Client-Cert"] = URLEncodePEM(agentCertPEM)
	}
	for k, v := range headers {
		all[k] = v
	}
	u := fmt.Sprintf("%s/v1/%s/gateway/v1/secret/data/e2e/app-config", NodeURL(port), UserLegMount)
	return DoRequest(t, "GET", u, all, "")
}

// =============================================================================
// Agent-user binding
// =============================================================================
//
// A binding is decided cryptographically at the IdP and enforced at the gateway,
// per request. Where the IdP has decided nothing, the gateway decides and
// enforces in one step. Both land on the same machinery — a CEL condition
// comparing a value carried on the USER's token against the agent's own identity
// — and differ only in where the compared value came from.
//
// When the IdP decided: it attests the pairing with RFC 8693 `act.sub` ("agent A
// acting for user B"), mapped as a fact of the user auth mount with a JSON
// Pointer, facts { "/act/sub" = "acting_agent" }, and the gateway verifies the
// agent presenting the request is the one attested.
//
// This harness runs the other case. Hydra's client_credentials grant emits no
// `act` claim, so there is no IdP decision to enforce and the rule is decided
// here: the user's own `sub` must match the agent's principal. The claim
// mapping, the condition layer and the per-request evaluation are the same; only
// the provenance of the compared value differs — so what stays unexercised is
// the JSON Pointer into a nested `act` claim, which is unit-covered instead.
const (
	// UserLegBindingPolicy carries the binding condition. It deliberately does
	// NOT also grant the unconditioned `-access` policy: conditions merge with
	// OR across policies covering one path, so attaching both would let the
	// unconditioned grant allow everything and the binding would prove nothing.
	UserLegBindingPolicy = "e2e-userleg-binding"

	// UserLegBoundRole is a role granted to certificates whose CN is the value
	// the user's mapped claim carries, so a certificate minted with that CN
	// satisfies the binding.
	UserLegBoundRole = "e2e-userleg-bound"

	// UserLegUnboundRole is a role granted to the stock `agent-*` certificates.
	// It carries the same binding policy, so a request through it is denied by
	// the CONDITION rather than by authorization — which is what makes the deny
	// case evidence of the binding working.
	UserLegUnboundRole = "e2e-userleg-unbound"

	// UserLegActingAgentKey is the metadata key the mapped claim lands on.
	UserLegActingAgentKey = "acting_agent"
)

// SetupUserLegBinding installs the binding policy, the two cert-granted roles,
// and the claim mapping on the user auth mount. actingAgent is the value the
// user's mapped claim will carry; the caller reads it off the actual user token
// rather than assuming it, so the fixture cannot drift from what the IdP issues.
func SetupUserLegBinding(t *testing.T, port int, actingAgent string) {
	t.Helper()

	policy := fmt.Sprintf(
		`path \"%s/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n  condition = \"user.present && user.metadata.%s == agent.principal\"\n}`,
		UserLegMount, UserLegActingAgentKey)
	mustAPI(t, port, "POST", "sys/policies/cbp/"+UserLegBindingPolicy,
		fmt.Sprintf(`{"policy":"%s"}`, policy), "create binding policy")

	// Map the claim on the user auth mount. Additive: other tests read the
	// user's identity, not its metadata, so they are unaffected.
	SetUserLegClaimMapping(t, port, true)

	// The CN is matched exactly; the acting agent's subject holds no glob
	// character, which GrantRole would read as a pattern.
	if strings.ContainsAny(actingAgent, `*?\`) {
		t.Fatalf("acting agent %q holds a glob character", actingAgent)
	}
	for role, cn := range map[string]string{
		UserLegBoundRole:   actingAgent,
		UserLegUnboundRole: "agent-*",
	} {
		GrantRole(t, port, "auth/cert/", role,
			Role{Policies: []string{UserLegBindingPolicy}, CredSpec: "vault-token-reader"},
			Rule{"cn": {cn}})
	}
}

// SetUserLegClaimMapping rewrites the user auth mount with or without the
// acting-agent fact, so a test can remove the mapping and watch the binding
// fail closed. The mapping applies on the next request: no new login.
func SetUserLegClaimMapping(t *testing.T, port int, mapped bool) {
	t.Helper()
	var facts map[string]string
	if mapped {
		facts = map[string]string{"sub": UserLegActingAgentKey}
	}
	writeUserLegAuthConfig(t, port, facts)
}

// TeardownUserLegBinding removes what SetupUserLegBinding created and restores
// the user auth mount to its unmapped shape.
func TeardownUserLegBinding(t *testing.T, port int) {
	t.Helper()
	RevokeRole(t, port, "auth/cert/", UserLegBoundRole)
	RevokeRole(t, port, "auth/cert/", UserLegUnboundRole)
	APIRequest(t, "DELETE", "sys/policies/cbp/"+UserLegBindingPolicy, port, "")
	SetUserLegClaimMapping(t, port, false)
}

// UserLegRequestAs is UserLegRequest under a caller-chosen role, so a test can
// drive the same mount through roles granted to different CNs.
func UserLegRequestAs(t *testing.T, port int, role, agentCertPEM string, headers map[string]string) (int, []byte) {
	t.Helper()
	all := map[string]string{"X-Warden-Role": role}
	if agentCertPEM != "" {
		all["X-SSL-Client-Cert"] = URLEncodePEM(agentCertPEM)
	}
	for k, v := range headers {
		all[k] = v
	}
	u := fmt.Sprintf("%s/v1/%s/gateway/v1/secret/data/e2e/app-config", NodeURL(port), UserLegMount)
	return DoRequest(t, "GET", u, all, "")
}

// JWTSubject returns the `sub` claim of a compact JWS, so a test can bind a
// fixture to the identity the IdP actually issued instead of hardcoding it.
func JWTSubject(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("not a compact JWS: %d segments", len(parts))
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(DecodeJWTSegment(t, parts[1]), &claims); err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	if claims.Sub == "" {
		t.Fatal("user token carries no sub claim; the binding fixture has nothing to bind to")
	}
	return claims.Sub
}
