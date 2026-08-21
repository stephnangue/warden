//go:build e2e

package fullchain

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Everything else in this package runs in the root namespace. A namespace is not
// a prefix on the same objects — it is a separate tree of mounts, policies,
// credential sources and auth methods, resolved from a header. A provider that
// works at the root proves nothing about one inside a namespace, because every
// name the chain resolves is resolved somewhere else.
//
// This file builds its own environment rather than extending ProviderEnv. A
// namespaced mount needs its own auth methods inside the namespace, so it is a
// parallel environment rather than the shared one with a header attached, and
// threading a namespace through the shared helpers would complicate every
// provider to serve these rows.

const (
	nsName     = "fc-tenant"
	nsPath     = nsName + "/"
	nsMount    = "ns-openai"
	nsAPIKey   = "fc-ns-not-a-real-key"
	nsCertRole = "ns-openai-agent"
	nsPolicy   = "ns-openai-access"
	nsSource   = "ns-openai-src"
	nsSpec     = "ns-openai-cred"
	nsUserAuth = "auth/ns-user-jwt/"
	nsUserRole = "ns-user"
	nsAgentCN  = "agent-ns"
)

// nsEnv is the namespaced environment, built once for the rows below.
type nsEnv struct {
	caPEM string
	caKey *ecdsa.PrivateKey
}

// nsMust issues a namespace-scoped API call and fails unless it worked.
func nsMust(t *testing.T, port int, method, path, body, what string) {
	t.Helper()
	status, resp := h.NSAPIRequest(t, method, path, nsPath, port, body)
	switch status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

func nsJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// ensureNamespaceEnv builds the namespaced environment once for the package.
//
// Not per test: deleting a namespace is asynchronous, and a recreate that lands
// while the previous one is still being torn down is refused as tainted. Building
// once removes that collision between rows; the one at the start of a run, after
// a previous run ended without its teardown, is handled by waiting for the
// deletion in setup.
func ensureNamespaceEnv(t *testing.T) nsEnv {
	t.Helper()
	nsOnce.Do(func() {
		nsBuilt = setupNamespaceEnv(t, leaderPort, upstream.URL)
	})
	if nsBuilt.caPEM == "" {
		t.Fatal("the namespaced environment is not available")
	}
	upstream.Reset()
	return nsBuilt
}

var (
	nsOnce  sync.Once
	nsBuilt nsEnv
)

// teardownNamespaceEnvBestEffort removes the namespace, and with it everything
// mounted inside. Called from TestMain, so it takes no *testing.T.
func teardownNamespaceEnvBestEffort(port int) {
	token := h.RootTokenBestEffort()
	h.TryRequest("DELETE", fmt.Sprintf("%s/v1/sys/namespaces/%s", h.NodeURL(port), nsName),
		map[string]string{"X-Warden-Token": token}, "")
}

// waitForNamespaceGone blocks until the namespace no longer exists, so a create
// cannot land while a previous deletion is still in flight.
func waitForNamespaceGone(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if status, _ := h.APIRequest(t, "GET", "sys/namespaces/"+nsName, port, ""); status == 404 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("namespace %q still exists after waiting for its deletion", nsName)
}

// setupNamespaceEnv builds, inside a namespace, everything a full chain needs:
// its own certificate and user auth methods, a provider mount, a credential
// source and spec, a policy, and a role.
//
// The mount, role, policy, source and spec names deliberately match nothing at
// the root: were one shared, a lookup that fell through to the root would still
// succeed and the rows would prove nothing about scoping.
//
// The cert auth method is the exception — it is at auth/cert here as it is at the
// root, because that is where a mount's auto_auth_path points. That collision is
// load-bearing in an unobvious way: if the namespace header were ignored during
// setup, mounting it would collide with the root's and fail, rather than quietly
// building this whole environment at the root and overwriting the root's trusted
// CA. TestNamespace_HeaderIsWhatSelectsTheMount asserts the header directly, so
// nothing rests on that accident.
func setupNamespaceEnv(t *testing.T, port int, upstreamURL string) nsEnv {
	t.Helper()

	// A run that ended without its teardown leaves the namespace behind. Deleting
	// one is asynchronous — the call taints the name and enqueues the work — and a
	// create against a tainted name is refused, so it is not enough to delete and
	// carry on: the delete has to be waited out. Without this an aborted run poisons
	// the next one, which then fails here and takes both rows with it.
	teardownNamespaceEnvBestEffort(port)
	waitForNamespaceGone(t, port)

	status, resp := h.APIRequest(t, "POST", "sys/namespaces/"+nsName, port, `{}`)
	switch status {
	case 200, 201, 204:
	default:
		t.Fatalf("create namespace (status %d): %s", status, resp)
	}

	// The namespace's own cert auth, with its own CA: a certificate minted here
	// is trusted here and nowhere else.
	nsMust(t, port, "POST", "sys/auth/cert", `{"type":"cert"}`, "mount cert auth in namespace")
	caPEM, caKey := h.GenerateTestCA(t)
	nsMust(t, port, "PUT", "auth/cert/config",
		nsJSON(t, map[string]any{"trusted_ca_pem": caPEM}), "configure namespace cert auth")

	nsMust(t, port, "POST", "sys/auth/ns-user-jwt", `{"type":"jwt"}`, "mount user jwt in namespace")
	nsMust(t, port, "PUT", "auth/ns-user-jwt/config",
		fmt.Sprintf(`{"mode":"oidc","oidc_discovery_url":%q,"bound_issuer":%q}`, h.HydraIssuer, h.HydraIssuer),
		"configure namespace user jwt")
	nsMust(t, port, "POST", "auth/ns-user-jwt/role/"+nsUserRole,
		`{"user_claim":"sub","token_ttl":3600}`, "create namespace user role")

	nsMust(t, port, "POST", "sys/providers/"+nsMount,
		`{"type":"openai","description":"e2e namespaced openai"}`, "mount provider in namespace")

	nsMust(t, port, "PUT", nsMount+"/config",
		nsJSON(t, map[string]any{
			"openai_url":      upstreamURL,
			"tls_skip_verify": true,
			"auto_auth_path":  "auth/cert/",
			"user_auth_path":  nsUserAuth,
			"user_auth_role":  nsUserRole,
		}), "configure namespaced provider")

	nsMust(t, port, "POST", "sys/cred/sources/"+nsSource, `{"type":"local"}`,
		"create namespaced credential source")
	nsMust(t, port, "POST", "sys/cred/specs/"+nsSpec,
		nsJSON(t, map[string]any{
			"type":   "api_key",
			"source": nsSource,
			"config": map[string]string{"api_key": nsAPIKey},
		}), "create namespaced credential spec")

	nsMust(t, port, "POST", "sys/policies/cbp/"+nsPolicy,
		nsJSON(t, map[string]any{
			"policy": fmt.Sprintf("path %q {\n  capabilities = [\"read\",\"create\",\"update\"]\n}\n",
				nsMount+"/gateway*"),
		}), "create namespaced policy")

	nsMust(t, port, "POST", "auth/cert/role/"+nsCertRole,
		nsJSON(t, map[string]any{
			"allowed_common_names": []string{nsAgentCN},
			"token_policies":       []string{nsPolicy},
			"cred_spec_name":       nsSpec,
			"token_ttl":            3600,
		}), "create namespaced cert role")

	return nsEnv{caPEM: caPEM, caKey: caKey}
}

// nsRequest drives a gateway request against the namespaced mount.
func nsRequest(t *testing.T, port int, certPEM, bearer, path string) (int, []byte) {
	t.Helper()
	headers := map[string]string{
		"X-Warden-Namespace": nsPath,
		"X-Warden-Role":      nsCertRole,
		"X-SSL-Client-Cert":  h.URLEncodePEM(certPEM),
	}
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	u := fmt.Sprintf("%s/v1/%s/gateway/%s", h.NodeURL(port), nsMount, path)
	return h.DoRequest(t, "GET", u, headers, "")
}

// TestNamespace_FullChainInsideANamespace drives the whole chain against a mount
// that exists only inside a namespace.
//
// Every name resolved along the way — the auth method, the policy, the credential
// spec, the mount itself — lives in the namespace's own tree. Nothing here has a
// counterpart at the root, so a resolution that escaped to the root would fail
// rather than quietly succeed.
func TestNamespace_FullChainInsideANamespace(t *testing.T) {
	ensureEnv(t)

	env := ensureNamespaceEnv(t)

	certPEM, _ := h.GenerateClientCert(t, env.caPEM, env.caKey, nsAgentCN)
	status, body := nsRequest(t, leaderPort, certPEM, h.FullChainUserJWT(t), "probe")

	// The same assertions every root row makes, so a namespaced chain is held to
	// the same standard — exact header values rather than a first-value match,
	// and exactly one forwarded request.
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + nsAPIKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestNamespace_HeaderIsWhatSelectsTheMount makes the namespace header
// load-bearing rather than incidental. The same request without it must not find
// the mount at all, since nothing by that name exists at the root.
//
// Without this row the positive one rests on an accident: setup would fail on a
// name collision if the header were ignored, but that is a property of the
// fixture rather than something asserted.
func TestNamespace_HeaderIsWhatSelectsTheMount(t *testing.T) {
	ensureEnv(t)

	env := ensureNamespaceEnv(t)
	certPEM, _ := h.GenerateClientCert(t, env.caPEM, env.caKey, nsAgentCN)

	u := fmt.Sprintf("%s/v1/%s/gateway/probe", h.NodeURL(leaderPort), nsMount)
	status, body := h.DoRequest(t, "GET", u, map[string]string{
		"X-Warden-Role":     nsCertRole,
		"X-SSL-Client-Cert": h.URLEncodePEM(certPEM),
	}, "")

	if status != http.StatusNotFound {
		t.Errorf("status: got %d, want 404 — without the namespace header the mount does not "+
			"exist (body: %s)", status, body)
	}
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests; nothing should have been forwarded", n)
	}
}

// TestNamespace_RootCertificateIsNotAccepted pins the boundary in the direction
// that matters. The root namespace has its own cert auth with its own CA, and a
// certificate minted there names the same kind of agent — but it is not trusted
// here, and must not authenticate against a namespaced mount.
//
// Without this, the row above would be equally consistent with the namespace
// falling back to the root's trust.
func TestNamespace_RootCertificateIsNotAccepted(t *testing.T) {
	ensureEnv(t)

	ensureNamespaceEnv(t)

	// Signed by the ROOT suite's CA but carrying the common name the NAMESPACE's
	// role allows. Every other attribute matches what the namespace expects, so
	// the CA is the only thing that can refuse it.
	//
	// Using the root suite's own certificate instead would prove nothing: its
	// common name is the root's, which the namespace role does not allow, and cert
	// auth answers the same 401 for a rejected common name as for an untrusted
	// CA. It would fail identically whether or not the namespace inherited the
	// root's trust — which is the possibility this row exists to exclude.
	rootCAButNamespaceCN, _ := h.GenerateClientCert(t, agentCAPEM, agentCAKey, nsAgentCN)
	status, body := nsRequest(t, leaderPort, rootCAButNamespaceCN, h.FullChainUserJWT(t), "probe")

	if status != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401 — a certificate from the root's CA must be refused "+
			"by the namespace's own cert mount (body: %s)", status, body)
	}
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests; nothing should have been forwarded", n)
	}
}
