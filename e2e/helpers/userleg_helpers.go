//go:build e2e

package helpers

import (
	"crypto/ecdsa"
	"crypto/tls"
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
	// for one leg is not silently valid for the other.
	UserLegAuthMount = "auth/user-jwt/"

	// UserLegAuthRole is the role user credentials are validated under.
	UserLegAuthRole = "e2e-user"

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

	mustAPI(t, port, "PUT", "auth/user-jwt/config",
		fmt.Sprintf(`{"mode":"oidc","oidc_discovery_url":"%s","bound_issuer":"%s"}`, HydraIssuer, HydraIssuer),
		"configure user-jwt auth")

	mustAPI(t, port, "POST", "auth/user-jwt/role/"+UserLegAuthRole,
		`{"user_claim":"sub","token_ttl":3600}`, "create user role")

	// Provider mount. The description becomes `resource_name` in metadata.
	mustAPI(t, port, "POST", "sys/providers/"+UserLegMount,
		fmt.Sprintf(`{"type":"vault","description":%q}`, UserLegMountDescription),
		"mount provider")
	time.Sleep(time.Second)

	// Address and auth config go in one write: the vault provider rejects a
	// config that does not carry auto_auth_path, so they cannot be split.
	mustAPI(t, port, "PUT", UserLegMount+"/config",
		fmt.Sprintf(`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"timeout":"30s",`+
			`"auto_auth_path":"auth/cert/","user_auth_path":%q,"user_auth_role":%q}`,
			UserLegAuthMount, UserLegAuthRole),
		"configure provider")

	mustAPI(t, port, "POST", "sys/policies/cbp/"+UserLegMount+"-access",
		fmt.Sprintf(`{"policy":"path \"%s/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\npath \"%s/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`,
			UserLegMount, UserLegMount),
		"create policy")

	// Cert role for the agent, bound to a credential spec so a successful
	// request actually mints something.
	mustAPI(t, port, "POST", "auth/cert/role/e2e-userleg-agent",
		fmt.Sprintf(`{"allowed_common_names":["agent-*"],"token_policies":["%s-access"],"cred_spec_name":"vault-token-reader","token_ttl":3600}`,
			UserLegMount),
		"create cert role")

	EnableProtectedResourceMetadata(t, port)

	return caCertPEM, caKey
}

// UserLegJWTRole is a JWT role scoped to the user-leg mount, for tests that
// swap the certificate agent for a JWT one. The stock e2e-reader role grants
// vault/gateway*, so reusing it would fail authorization instead of exercising
// the agent channel under test.
const UserLegJWTRole = "e2e-userleg-jwt"

// CreateUserLegJWTRole creates that role. Idempotent.
func CreateUserLegJWTRole(t *testing.T, port int) {
	t.Helper()
	APIRequest(t, "DELETE", "auth/jwt/role/"+UserLegJWTRole, port, "")
	mustAPI(t, port, "POST", "auth/jwt/role/"+UserLegJWTRole,
		fmt.Sprintf(`{"token_policies":["%s-access"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":3600}`,
			UserLegMount),
		"create user-leg jwt role")
}

// SetUserLegAgentPath repoints the mount's AGENT leg while leaving the user leg
// intact. Lets a test swap a certificate agent for a JWT one without rebuilding
// the whole environment.
func SetUserLegAgentPath(t *testing.T, port int, autoAuthPath, defaultRole string) {
	t.Helper()
	body := fmt.Sprintf(`{"auto_auth_path":%q,"user_auth_path":%q,"user_auth_role":%q`,
		autoAuthPath, UserLegAuthMount, UserLegAuthRole)
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
	del("auth/cert/role/e2e-userleg-agent")
	del("sys/policies/cbp/" + UserLegMount + "-access")
	del("sys/providers/" + UserLegMount)
	del("auth/user-jwt/role/" + UserLegAuthRole)
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
	all := map[string]string{"X-Warden-Role": "e2e-userleg-agent"}
	if agentCertPEM != "" {
		all["X-SSL-Client-Cert"] = URLEncodePEM(agentCertPEM)
	}
	for k, v := range headers {
		all[k] = v
	}
	u := fmt.Sprintf("%s/v1/%s/gateway/v1/secret/data/e2e/app-config", NodeURL(port), UserLegMount)
	return DoRequest(t, "GET", u, all, "")
}
