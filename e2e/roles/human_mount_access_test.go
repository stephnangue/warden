//go:build e2e

package roles

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestHumanMount_RefusedOnAccessBackends is the access-backend half of
// TestHumanMount_RefusedOnTheAgentLeg: an rds provider admits its agents
// through a human jwt mount, with a role granted at that mount. The access
// path is refused before any policy runs and the provider's config read warns;
// flipping the mount to agent admits the same JWT on the next request, which is
// served a connection string.
func TestHumanMount_RefusedOnAccessBackends(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		mount  = "auth/e2e-roles-human-access/"
		rds    = "e2e-roles-rds"
		role   = "e2e-roles-human-rds"
		grant  = "app"
		dbHost = "e2e-db.cluster-abc.eu-west-1.rds.amazonaws.com"
	)
	h.EnableAuth(t, port, "", mount, "jwt", h.HydraJWTConfig(map[string]any{"entity_kind": "human"}))
	policy := rdsProvider(t, port, rds, mount, grant, dbHost)
	writeRole(t, port, "", role, h.Role{Policies: []string{policy}})
	h.WriteGroupInNS(t, port, "", role, h.Group{Roles: []string{role}, Rules: []map[string][]string{{"mount": {mount}}}})

	jwt := h.GetDefaultJWT(t)
	access := func() (int, []byte) {
		t.Helper()
		return get(t, fmt.Sprintf("%s/v1/%s/access/%s?role=%s", h.NodeURL(port), rds, grant, role), bearer(jwt))
	}

	status, body := access()
	expectRefused(t, "access backend, agent admitted through a human mount", status, body, 401,
		"agent leg cannot admit through a human mount")
	status, body = h.APIRequest(t, "GET", rds+"/config", port, "")
	if status != 200 || !strings.Contains(string(body), "names a human auth mount") {
		t.Errorf("config read: status %d, want a warning that auto_auth_path names a human mount: %s", status, body)
	}

	h.MustNS(t, port, "", "PUT", strings.TrimSuffix(mount, "/")+"/config", `{"entity_kind":"agent"}`)

	status, body = access()
	expectStatus(t, "access backend once the mount admits agents", status, body, 200)
	if dsn := h.JSONString(t, body, "data.connection_string"); !strings.Contains(dsn, "host="+dbHost) ||
		!strings.Contains(dsn, "X-Amz-Signature=") {
		t.Errorf("the access path did not serve an IAM connection string: %s", dsn)
	}
}

// rdsProvider mounts an rds access backend at mount, its agents admitted
// through authMount, with grant minting an IAM auth token for dbHost from an
// aws source whose credential probe answers locally, and returns the policy a
// role needs to read its access paths.
func rdsProvider(t *testing.T, port int, mount, authMount, grant, dbHost string) string {
	t.Helper()
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "GetCallerIdentity" {
			http.Error(w, "unexpected STS action", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/e2e-rds</Arn>
    <UserId>AIDAE2ERDSEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>4c5d6e7f-0000-4000-8000-000000000002</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`))
	}))
	t.Cleanup(sts.Close)

	source, spec, policy := mount+"-aws", mount+"-db", mount+"-access"
	for _, p := range []string{"sys/providers/" + mount, "sys/cred/specs/" + spec, "sys/cred/sources/" + source} {
		h.NSRequestBestEffort(port, "", "DELETE", p)
	}
	h.MustNS(t, port, "", "POST", "sys/cred/sources/"+source, mustJSON(t, map[string]any{
		"type": "aws",
		"config": map[string]string{
			"access_key_id": "AKIAE2ERDSEXAMPLE", "secret_access_key": "e2e-not-a-real-secret-key",
			"region": "eu-west-1", "sts_endpoint": sts.URL,
		},
	}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/cred/sources/"+source) })
	h.MustNS(t, port, "", "POST", "sys/cred/specs/"+spec, mustJSON(t, map[string]any{
		"type": "db_auth_token", "source": source,
		"config": map[string]string{
			"mint_method": "rds_iam_token", "db_endpoint": dbHost, "db_user": "app_ro", "db_engine": "postgres",
		},
	}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/cred/specs/"+spec) })

	h.MustNS(t, port, "", "POST", "sys/providers/"+mount, `{"type":"rds"}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/providers/"+mount) })
	h.MustNS(t, port, "", "PUT", mount+"/config", mustJSON(t, map[string]any{"auto_auth_path": authMount}))
	h.MustNS(t, port, "", "POST", mount+"/grants/"+grant, mustJSON(t, map[string]any{
		"credential_spec": spec, "db_name": "appdb",
	}))

	h.MustNS(t, port, "", "POST", "sys/policies/cbp/"+policy, mustJSON(t, map[string]any{
		"policy": fmt.Sprintf("path %q {\n  capabilities = [\"read\"]\n}\n", mount+"/access/*"),
	}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/policies/cbp/"+policy) })
	return policy
}
