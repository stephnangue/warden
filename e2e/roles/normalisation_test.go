//go:build e2e

package roles

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestNormalisation_OneFactNameAcrossMounts maps one fact name, workload, on
// two auth mounts of different methods: a kubernetes mount publishes the
// service account's name under it, a cert mount the certificate's CN. One rule
// listing both mounts admits the same workload through either. Taking a mount
// off the rule's mount list refuses that path on the next request of the
// cached credential, without admitting it again (the TokenReview count holds),
// while the other mount keeps its grant.
func TestNormalisation_OneFactNameAcrossMounts(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		k8sMount  = "auth/e2e-roles-norm-k8s/"
		certMount = "auth/e2e-roles-norm-cert/"
		k8sVault  = "e2e-roles-norm-vault-k8s"
		certVault = "e2e-roles-norm-vault-cert"
		role      = "e2e-roles-workload"
		group     = "e2e-roles-workloads"
		workload  = "deployer"
	)
	reviewer := h.StartTokenReviewer(t)
	h.EnableKubernetesAuth(t, port, "", k8sMount, reviewer, map[string]any{
		"bound_audiences": []string{h.HydraAudience},
		"facts":           map[string]string{"service_account_name": "workload"},
	})
	caPEM, caKey := newCA(t)
	enableAuth(t, port, "", certMount, "cert", certConfig([]string{caPEM}, map[string]any{
		"facts": map[string]string{"cn": "workload"},
	}))
	k8sPolicy := vaultProvider(t, port, "", k8sVault, k8sMount)
	certPolicy := vaultProvider(t, port, "", certVault, certMount)
	writeRole(t, port, "", role, h.Role{Policies: []string{k8sPolicy, certPolicy}, CredSpec: "vault-token-reader"})

	grant := func(mounts ...string) {
		t.Helper()
		warnings := h.WriteGroupInNS(t, port, "", group, h.Group{
			Roles: []string{role},
			Rules: []map[string][]string{{"mount": mounts, "workload": {workload}}},
		})
		if len(warnings) != 0 {
			t.Fatalf("a rule on a fact name every listed mount maps warns: %v", warnings)
		}
	}
	grant(k8sMount, certMount)

	token := reviewer.Issue(t, h.ServiceAccount{
		Namespace: "ci", Name: workload, UID: "uid-deployer", Audiences: []string{h.HydraAudience},
	}, "https://kubernetes.e2e.example", true)
	certPEM, _ := h.GenerateClientCert(t, caPEM, caKey, workload)
	otherPEM, _ := h.GenerateClientCert(t, caPEM, caKey, "intruder")

	viaK8s := func() (int, []byte) { return get(t, gatewayURL(port, k8sVault, role), bearer(token)) }
	viaCert := func(pem string) (int, []byte) { return get(t, gatewayURL(port, certVault, role), forwardedCert(pem)) }

	status, body := viaK8s()
	expectStatus(t, "the workload's service account token", status, body, 200)
	status, body = viaCert(certPEM)
	expectStatus(t, "the workload's certificate", status, body, 200)
	status, body = viaCert(otherPEM)
	expectRefused(t, "another workload's certificate", status, body, 403, "not assumable")
	if got := reviewer.Reviews(); got != 1 {
		t.Fatalf("one service account token cost %d TokenReviews, want 1", got)
	}

	// The rule stops trusting the kubernetes mount.
	grant(certMount)
	status, body = viaK8s()
	expectRefused(t, "the cached token once its mount left the rule", status, body, 403, "not assumable through "+k8sMount)
	status, body = viaCert(certPEM)
	expectStatus(t, "the certificate through the mount still listed", status, body, 200)
	if got := reviewer.Reviews(); got != 1 {
		t.Errorf("the token was admitted again: %d TokenReviews, want 1", got)
	}

	// Listed again, it is granted again on the same admission.
	grant(k8sMount, certMount)
	status, body = viaK8s()
	expectStatus(t, "the cached token once its mount is listed again", status, body, 200)
	if got := reviewer.Reviews(); got != 1 {
		t.Errorf("the token was admitted again: %d TokenReviews, want 1", got)
	}
}
