//go:build e2e

package roles

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

const k8sIssuer = "https://kubernetes.e2e.example"

// kubernetesEnv mounts a kubernetes auth method at mount against a fresh
// TokenReview stub, with config, in namespace, a vault provider admitting
// through it, and role granted to the service account name sa there.
func kubernetesEnv(t *testing.T, port int, namespace, mount, provider, role, sa string, config map[string]any) *h.TokenReviewer {
	t.Helper()
	reviewer := h.StartTokenReviewer(t)
	h.EnableKubernetesAuth(t, port, namespace, mount, reviewer, config)
	policy := vaultProvider(t, port, namespace, provider, mount)
	writeRole(t, port, namespace, role, h.Role{Policies: []string{policy}, CredSpec: "vault-token-reader", ProviderPath: provider})
	h.WriteGroupInNS(t, port, namespace, role, h.Group{
		Roles: []string{role},
		Rules: []map[string][]string{{"mount": {mount}, "service_account_name": {sa}}},
	})
	return reviewer
}

func configWarnings(t *testing.T, body []byte) []string {
	t.Helper()
	var out struct {
		Data struct {
			Warnings []string `json:"warnings"`
		} `json:"data"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return append(out.Data.Warnings, out.Warnings...)
}

// TestKubernetes_EmptyBoundAudiencesAdmitsWithWarning: a kubernetes mount
// without bound_audiences lets the API server check its own audience, so a
// default service account token is admitted, and every config write and read
// says so.
func TestKubernetes_EmptyBoundAudiencesAdmitsWithWarning(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		mount    = "auth/e2e-roles-k8s-noaud/"
		provider = "e2e-roles-k8s-noaud-vault"
		role     = "e2e-roles-k8s-noaud"
	)
	reviewer := kubernetesEnv(t, port, "", mount, provider, role, "default-sa", nil)

	const warning = "bound_audiences is empty: TokenReview checks the API server's own audience"
	status, body := h.APIRequest(t, "PUT", strings.TrimSuffix(mount, "/")+"/config", port, `{"token_ttl":"1h"}`)
	if status != 200 || !containsAny(configWarnings(t, body), warning) {
		t.Errorf("config write without bound_audiences: status %d, want the warning %q: %s", status, warning, body)
	}
	status, body = h.APIRequest(t, "GET", strings.TrimSuffix(mount, "/")+"/config", port, "")
	if status != 200 || !containsAny(configWarnings(t, body), warning) {
		t.Errorf("config read without bound_audiences: status %d, want the warning %q: %s", status, warning, body)
	}

	token := reviewer.Issue(t, h.ServiceAccount{
		Namespace: "default", Name: "default-sa", UID: "uid-default", Audiences: []string{h.KubeAPIAudience},
	}, k8sIssuer, true)
	status, body = get(t, gatewayURL(port, provider, role), bearer(token))
	expectStatus(t, "a token for the API server's own audience", status, body, 200)
}

// TestKubernetes_MaxAgeRefusesTokenWithoutIat: with max_age set, a token
// carrying no iat (a legacy secret-based token) is not admitted, while a fresh
// token for the same service account is.
func TestKubernetes_MaxAgeRefusesTokenWithoutIat(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		mount    = "auth/e2e-roles-k8s-maxage/"
		provider = "e2e-roles-k8s-maxage-vault"
		role     = "e2e-roles-k8s-maxage"
	)
	reviewer := kubernetesEnv(t, port, "", mount, provider, role, "aged-sa", map[string]any{
		"bound_audiences": []string{h.HydraAudience},
		"max_age":         "10m",
	})
	sa := h.ServiceAccount{Namespace: "ci", Name: "aged-sa", UID: "uid-aged", Audiences: []string{h.HydraAudience}}

	legacy := reviewer.Issue(t, sa, k8sIssuer, false)
	status, body := get(t, gatewayURL(port, provider, role), bearer(legacy))
	expectStatus(t, "a token without iat under max_age", status, body, 401)

	fresh := reviewer.Issue(t, sa, k8sIssuer, true)
	status, body = get(t, gatewayURL(port, provider, role), bearer(fresh))
	expectStatus(t, "a fresh token under max_age", status, body, 200)
}

// TestKubernetes_GenericJWTAtKubernetesTarget: discovery with a JWT that is
// not a service account token, in a namespace whose only target is a
// kubernetes mount reviewing tokens with the caller's own (self-review). The
// API server refuses the review call itself, so the one mount the caller could
// be admitted through cannot decide: sys/introspect/roles, which admits the
// caller before answering, answers 503, naming the mount in its fixed phrase:
// nothing of what the API server answered, nor where it lives, reaches the
// caller. The call costs one review.
func TestKubernetes_GenericJWTAtKubernetesTarget(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		ns       = "e2e-roles-k8s-generic"
		mount    = "auth/k8s/"
		provider = "vault"
		role     = "k8s-reader"
	)
	h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	h.MustNS(t, port, "", "POST", "sys/namespaces/"+ns, "")
	t.Cleanup(func() { h.CleanupNamespaces(t, port, ns) })
	reviewer := kubernetesEnv(t, port, ns, mount, provider, role, "reader", map[string]any{
		"bound_audiences": []string{h.HydraAudience},
	})

	status, body := h.DoRequest(t, "GET", h.NodeURL(port)+"/v1/sys/introspect/roles", map[string]string{
		"Authorization":      "Bearer " + h.GetDefaultJWT(t),
		"X-Warden-Namespace": ns,
	}, "")
	if status != 503 {
		t.Fatalf("discovery: status %d, want 503: %s", status, body)
	}
	var out struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	want := `no auth mount could decide on the presented credential (mount "k8s/": could not verify the credential)`
	if len(out.Errors) != 1 || out.Errors[0] != want {
		t.Errorf("errors = %q, want exactly %q", out.Errors, want)
	}
	stub, _ := url.Parse(reviewer.URL)
	if h.LeaksStubDetail(body) || strings.Contains(string(body), stub.Host) {
		t.Errorf("discovery repeats what the API server said or where it lives: %s", body)
	}
	if got := reviewer.Reviews(); got != 1 {
		t.Errorf("one discovery call cost %d review calls, want 1", got)
	}
}

func containsAny(list []string, part string) bool {
	for _, s := range list {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}
