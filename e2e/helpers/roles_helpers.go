//go:build e2e

package helpers

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
)

// Role is a namespace role as the suites write it at sys/roles/<name>: what a
// caller may do under it and what discovery says about it. Who may assume it
// is a group's business (GrantRole).
type Role struct {
	Policies     []string
	CredSpec     string
	Description  string
	Skill        string
	ProviderPath string
}

func (r Role) body() map[string]any {
	out := map[string]any{"policies": r.Policies}
	if r.Policies == nil {
		out["policies"] = []string{}
	}
	if r.CredSpec != "" {
		out["cred_spec_name"] = r.CredSpec
	}
	if r.Description != "" {
		out["description"] = r.Description
	}
	if r.Skill != "" {
		out["skill"] = r.Skill
	}
	if r.ProviderPath != "" {
		out["provider_path"] = r.ProviderPath
	}
	return out
}

// Rule is one rule of a virtual group without its "mount" selector, which
// GrantRole adds: fact names mapped to the values each may take (AND across
// names, any-of within one). Nil matches every caller the mount admits.
type Rule map[string][]string

// AuthMountPath normalises an auth mount to the namespace-relative form a
// group's "mount" selector names: "jwt", "jwt/", "auth/jwt" and "auth/jwt/"
// are all "auth/jwt/".
func AuthMountPath(mount string) string {
	m := strings.Trim(mount, "/")
	if !strings.HasPrefix(m, "auth/") {
		m = "auth/" + m
	}
	return m + "/"
}

// GrantGroup names the group GrantRole writes for role at mount.
func GrantGroup(mount, role string) string {
	m := strings.TrimPrefix(strings.Trim(AuthMountPath(mount), "/"), "auth/")
	return role + "--" + strings.ReplaceAll(m, "/", "-")
}

// GrantRole writes role in the root namespace and a virtual group granting it
// to every caller admitted at mount whose facts match rule. Both are replaced
// when they exist, so a later call with other policies or another rule takes
// over; a role granted at several mounts gets one group per mount.
func GrantRole(t *testing.T, port int, mount, role string, r Role, rule Rule) {
	t.Helper()
	GrantRoleInNS(t, port, "", mount, role, r, rule)
}

// GrantRoleInNS is GrantRole in namespace (the root namespace when empty).
func GrantRoleInNS(t *testing.T, port int, namespace, mount, role string, r Role, rule Rule) {
	t.Helper()
	WriteRoleInNS(t, port, namespace, role, r)
	GrantInNS(t, port, namespace, mount, role, rule)
}

// WriteRoleInNS (re)creates role in namespace without granting it.
func WriteRoleInNS(t *testing.T, port int, namespace, role string, r Role) {
	t.Helper()
	nsRequest(t, port, namespace, "DELETE", "sys/roles/"+role, "")
	mustNS(t, port, namespace, "POST", "sys/roles/"+role, jsonBody(t, r.body()), "create role "+role)
}

// GrantInNS (re)creates the group that grants an existing role at mount, to
// callers whose facts match rule.
func GrantInNS(t *testing.T, port int, namespace, mount, role string, rule Rule) {
	t.Helper()
	group := GrantGroup(mount, role)
	selectors := map[string][]string{"mount": {AuthMountPath(mount)}}
	for k, v := range rule {
		selectors[k] = v
	}
	nsRequest(t, port, namespace, "DELETE", "sys/identity/group/"+group+"?type=virtual", "")
	mustNS(t, port, namespace, "POST", "sys/identity/group/"+group, jsonBody(t, map[string]any{
		"type":  "virtual",
		"roles": []string{role},
		"rules": []map[string][]string{selectors},
	}), "grant role "+role+" at "+AuthMountPath(mount))
}

// RevokeRole deletes the group GrantRole wrote for role at mount, and role
// itself. A role still granted at another mount stops working there too.
func RevokeRole(t *testing.T, port int, mount, role string) {
	t.Helper()
	nsRequest(t, port, "", "DELETE", "sys/identity/group/"+GrantGroup(mount, role)+"?type=virtual", "")
	nsRequest(t, port, "", "DELETE", "sys/roles/"+role, "")
}

// RevokeRoleBestEffort is RevokeRole without a *testing.T, for teardown from
// TestMain and cleanups that must not fail a run.
func RevokeRoleBestEffort(port int, mount, role string) {
	RevokeRoleInNSBestEffort(port, "", mount, role)
}

// RevokeRoleInNSBestEffort is RevokeRoleBestEffort in namespace.
func RevokeRoleInNSBestEffort(port int, namespace, mount, role string) {
	headers := map[string]string{"X-Warden-Token": rootTokenBestEffort()}
	if namespace != "" {
		headers["X-Warden-Namespace"] = namespace
	}
	for _, p := range []string{"sys/identity/group/" + GrantGroup(mount, role) + "?type=virtual", "sys/roles/" + role} {
		TryRequest("DELETE", fmt.Sprintf("%s/v1/%s", NodeURL(port), p), headers, "")
	}
}

// CapMountTokenTTL lowers the token_ttl of the auth mount (how long an admitted
// credential is reused before it is verified again) to seconds for the rest of
// the test, and restores it in cleanup. A mount already at or below seconds is
// left alone. A test that must watch a session end uses it: lifetimes belong to
// the mount, not to a role. Every session the mount admits meanwhile is capped
// too, which is safe while the suites run one test at a time.
func CapMountTokenTTL(t *testing.T, port int, mount string, seconds int) {
	t.Helper()
	path := strings.TrimSuffix(AuthMountPath(mount), "/") + "/config"
	status, body := APIRequest(t, "GET", path, port, "")
	if status != 200 {
		t.Fatalf("read %s (status %d): %s", path, status, body)
	}
	was := JSONString(t, body, "data.token_ttl")
	current, err := time.ParseDuration(was)
	if err != nil {
		t.Fatalf("%s token_ttl %q does not parse: %v", path, was, err)
	}
	if current <= time.Duration(seconds)*time.Second {
		return
	}
	mustNS(t, port, "", "PUT", path, fmt.Sprintf(`{"token_ttl":%d}`, seconds), "shorten the session lifetime of "+path)
	t.Cleanup(func() {
		mustNS(t, port, "", "PUT", path, fmt.Sprintf(`{"token_ttl":%d}`, int(current.Seconds())), "restore the session lifetime of "+path)
	})
}

// Group is a virtual group as a test writes it whole: the roles it grants,
// its rules (each names its mounts under "mount") and, when set, the RFC 3339
// instant after which it grants nothing.
type Group struct {
	Roles      []string
	Rules      []map[string][]string
	ValidUntil string
}

// WriteGroupInNS writes group name in namespace (the root namespace when
// empty): it creates it, or updates it in place when it exists, as an
// operator's edit does. It deletes the group when the test ends and returns
// the write's warnings.
func WriteGroupInNS(t *testing.T, port int, namespace, name string, g Group) []string {
	t.Helper()
	body := map[string]any{"type": "virtual", "roles": g.Roles, "rules": g.Rules}
	if g.ValidUntil != "" {
		body["valid_until"] = g.ValidUntil
	}
	path := "sys/identity/group/" + name
	status, resp := nsRequest(t, port, namespace, "POST", path, jsonBody(t, body))
	if status == 409 {
		status, resp = nsRequest(t, port, namespace, "PUT", path, jsonBody(t, body))
	}
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("write group %s (status %d): %s", name, status, resp)
	}
	t.Cleanup(func() { nsRequest(t, port, namespace, "DELETE", path+"?type=virtual", "") })
	var out struct {
		Warnings []string `json:"warnings"`
		Data     struct {
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	_ = json.Unmarshal(resp, &out)
	return append(out.Warnings, out.Data.Warnings...)
}

// MustNS issues a request in namespace (the root namespace when empty) with
// the root token and fails the test unless it succeeded.
func MustNS(t *testing.T, port int, namespace, method, path, body string) []byte {
	t.Helper()
	status, resp := nsRequest(t, port, namespace, method, path, body)
	switch status {
	case 200, 201, 204:
		return resp
	}
	t.Fatalf("%s %s (status %d): %s", method, path, status, resp)
	return nil
}

// NSRequestBestEffort issues a request in namespace (the root namespace when
// empty) with the root token and ignores the outcome, for cleanups that must
// not fail a run.
func NSRequestBestEffort(port int, namespace, method, path string) {
	headers := map[string]string{"X-Warden-Token": rootTokenBestEffort()}
	if namespace != "" {
		headers["X-Warden-Namespace"] = namespace
	}
	TryRequest(method, fmt.Sprintf("%s/v1/%s", NodeURL(port), path), headers, "")
}

// EnableAuth mounts an auth method of type kind at mount in namespace (the
// root namespace when empty), writes config, and disables it when the test
// ends.
func EnableAuth(t *testing.T, port int, namespace, mount, kind string, config map[string]any) {
	t.Helper()
	path := strings.TrimSuffix(AuthMountPath(mount), "/")
	NSRequestBestEffort(port, namespace, "DELETE", "sys/"+path)
	MustNS(t, port, namespace, "POST", "sys/"+path, fmt.Sprintf(`{"type":%q}`, kind))
	t.Cleanup(func() { NSRequestBestEffort(port, namespace, "DELETE", "sys/"+path) })
	if config != nil {
		MustNS(t, port, namespace, "PUT", path+"/config", JSON(t, config))
	}
}

// HydraJWTConfig is the config of a jwt mount admitting the suites' Hydra
// tokens, with extra merged over it.
func HydraJWTConfig(extra map[string]any) map[string]any {
	cfg := map[string]any{
		"mode":               "oidc",
		"oidc_discovery_url": HydraIssuer,
		"bound_issuer":       HydraIssuer,
		"bound_audiences":    []string{HydraAudience},
		"user_claim":         "sub",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

// CertMountConfig is the config of a cert mount trusting the CAs in cas,
// with extra merged over it.
func CertMountConfig(cas []string, extra map[string]any) map[string]any {
	cfg := map[string]any{"trusted_ca_pem": strings.Join(cas, "\n")}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

// VaultProvider mounts a vault provider at mount in namespace, admitting its
// gateway requests through authMount, plus a policy granting read on its
// gateway, and returns the policy's name. Both go when the test ends.
func VaultProvider(t *testing.T, port int, namespace, mount, authMount string) string {
	t.Helper()
	NSRequestBestEffort(port, namespace, "DELETE", "sys/providers/"+mount)
	MustNS(t, port, namespace, "POST", "sys/providers/"+mount, `{"type":"vault"}`)
	t.Cleanup(func() { NSRequestBestEffort(port, namespace, "DELETE", "sys/providers/"+mount) })
	MustNS(t, port, namespace, "POST", mount+"/config", JSON(t, map[string]any{
		"vault_address":   "http://127.0.0.1:8200",
		"tls_skip_verify": true,
		"timeout":         "30s",
		"auto_auth_path":  AuthMountPath(authMount),
	}))
	policy := mount + "-access"
	MustNS(t, port, namespace, "POST", "sys/policies/cbp/"+policy, JSON(t, map[string]any{
		"policy": fmt.Sprintf("path %q {\n  capabilities = [\"read\"]\n}\npath %q {\n  capabilities = [\"read\"]\n}\n",
			mount+"/role/+/gateway*", mount+"/gateway*"),
	}))
	t.Cleanup(func() { NSRequestBestEffort(port, namespace, "DELETE", "sys/policies/cbp/"+policy) })
	return policy
}

// JSON returns v encoded as JSON.
func JSON(t *testing.T, v any) string {
	t.Helper()
	return jsonBody(t, v)
}

// ErrorText returns the errors of an error response body joined into one
// string, unescaped, so a test can look for a message in it; the body itself
// when it carries none.
func ErrorText(body []byte) string {
	var out struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Errors) == 0 {
		return string(body)
	}
	return strings.Join(out.Errors, "; ")
}

// AwaitAuditEntries polls a node's audit log until it holds at least n entries
// whose line contains substr and that match accepts, and returns those. The
// file device flushes every few seconds, so a test reading the entries of a
// request it just made has to wait for them.
func AwaitAuditEntries(t *testing.T, nodeNum int, substr string, n int, match func(audit.LogEntry) bool) []audit.LogEntry {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var got []audit.LogEntry
		for _, e := range ReadAuditEntries(t, nodeNum, substr) {
			if match == nil || match(e) {
				got = append(got, e)
			}
		}
		if len(got) >= n || time.Now().After(deadline) {
			if len(got) < n {
				t.Fatalf("node %d audit log: %d matching entries containing %q, want at least %d", nodeNum, len(got), substr, n)
			}
			return got
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func nsRequest(t *testing.T, port int, namespace, method, path, body string) (int, []byte) {
	t.Helper()
	if namespace == "" {
		return APIRequest(t, method, path, port, body)
	}
	return NSAPIRequest(t, method, path, namespace, port, body)
}

func mustNS(t *testing.T, port int, namespace, method, path, body, what string) {
	t.Helper()
	status, resp := nsRequest(t, port, namespace, method, path, body)
	switch status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, string(resp))
	}
}

func jsonBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return string(b)
}
