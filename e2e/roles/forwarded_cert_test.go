//go:build e2e

package roles

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestForwardedCert_TransparentOperations drives the non-gateway path: a
// namespace whose auto_auth_path is a cert mount admits the client certificate
// a trusted proxy forwards (X-SSL-Client-Cert from 127.0.0.1, which the
// listeners trust) on a request to Warden's own API, and a group grants the
// role on the certificate's ca and cn facts. The mount trusts two CAs; the
// rule pins one, so a certificate with the right CN from the other CA is
// admitted but not granted, as is one from the pinned CA with another CN. The
// role is selected with ?role= or X-Warden-Role, and a request selecting none
// is refused before admission.
func TestForwardedCert_TransparentOperations(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		ns     = "e2e-roles-ops"
		mount  = "auth/cert/"
		role   = "ops-reader"
		policy = "ops-reader"
		cn     = "agent-ops"
		target = "auth/cert/config"
	)
	h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	h.MustNS(t, port, "", "POST", "sys/namespaces/"+ns, `{"custom_metadata":{"auto_auth_path":"`+mount+`"}}`)
	t.Cleanup(func() { h.CleanupNamespaces(t, port, ns) })

	pinnedPEM, pinnedKey := newCA(t)
	otherPEM, otherKey := newCA(t)
	enableAuth(t, port, ns, mount, "cert", certConfig([]string{pinnedPEM, otherPEM}, nil))
	h.MustNS(t, port, ns, "POST", "sys/policies/cbp/"+policy,
		`{"policy":"path \"auth/cert/config\" {\n  capabilities = [\"read\"]\n}"}`)
	writeRole(t, port, ns, role, h.Role{Policies: []string{policy}})
	h.WriteGroupInNS(t, port, ns, role, h.Group{
		Roles: []string{role},
		Rules: []map[string][]string{{"mount": {mount}, "ca": {caFingerprint(t, pinnedPEM)}, "cn": {cn}}},
	})

	pinned, _ := h.GenerateClientCert(t, pinnedPEM, pinnedKey, cn)
	otherCA, _ := h.GenerateClientCert(t, otherPEM, otherKey, cn)
	otherCN, _ := h.GenerateClientCert(t, pinnedPEM, pinnedKey, "agent-elsewhere")

	request := func(certPEM, query string, headers map[string]string) (int, []byte) {
		t.Helper()
		all := forwardedCert(certPEM)
		all["X-Warden-Namespace"] = ns
		for k, v := range headers {
			all[k] = v
		}
		return get(t, h.NodeURL(port)+"/v1/"+target+query, all)
	}
	withHeader := map[string]string{"X-Warden-Role": role}

	status, body := request(pinned, "?role="+role, nil)
	expectStatus(t, "the pinned CA's certificate, role in the query", status, body, 200)
	if h.JSONPath(h.ParseJSON(t, body), "data.trusted_ca_pem") == nil {
		t.Errorf("the read did not return the mount's config: %s", body)
	}
	status, body = request(pinned, "", withHeader)
	expectStatus(t, "the pinned CA's certificate, role in X-Warden-Role", status, body, 200)

	status, body = request(otherCA, "", withHeader)
	expectRefused(t, "the right CN from the other trusted CA", status, body, 403, "not assumable through "+mount)
	status, body = request(otherCN, "", withHeader)
	expectRefused(t, "another CN from the pinned CA", status, body, 403, "not assumable through "+mount)

	status, body = request(pinned, "", nil)
	expectRefused(t, "a request selecting no role", status, body, 400, "no role selected")
}
