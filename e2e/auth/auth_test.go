//go:build e2e

package auth

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
	"github.com/stephnangue/warden/logical"
)

// findAuditedCondition polls the leader node's audit log for up to ~6s for an
// entry (whose raw line contains marker) that carries a path-level CEL condition
// decision, and returns it. Audit writes are asynchronous, hence the poll.
func findAuditedCondition(t *testing.T, nodeNum int, marker string) *logical.ConditionResult {
	t.Helper()
	for i := 0; i < 30; i++ {
		for _, e := range h.ReadAuditEntries(t, nodeNum, marker) {
			if e.Auth != nil && e.Auth.PolicyResults != nil && e.Auth.PolicyResults.Condition != nil {
				return e.Auth.PolicyResults.Condition
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

// TestJWTLoginExpiredJWT verifies expired JWT is rejected (T-058).
func TestJWTLoginExpiredJWT(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetJWT(t, "e2e-ephemeral", "ephemeral-secret")

	time.Sleep(3 * time.Second)

	status, _ := h.LoginJWT(t, jwt, port)
	if status != 401 && status != 403 && status != 400 {
		t.Fatalf("expected 401, 403, or 400 for expired JWT, got %d", status)
	}
}

// TestJWTLoginWrongAudience verifies a JWT not issued for the mount's bound
// audience is rejected, at login and on the gateway (T-059). The issuer signs
// it; only the audience is wrong.
func TestJWTLoginWrongAudience(t *testing.T) {
	port := h.GetLeaderPort(t)

	jwt := h.GetJWTForAudience(t, "e2e-agent", "agent-secret", "")
	status, _ := h.LoginJWT(t, jwt, port)
	if status != 401 && status != 403 && status != 400 {
		t.Fatalf("expected 401, 403, or 400 for wrong audience, got %d", status)
	}

	status, _ = h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", port, jwt)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 on the gateway for wrong audience, got %d", status)
	}

	// The same client's token issued for the bound audience is admitted.
	status, body := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", port, h.GetDefaultJWT(t))
	if status != 200 {
		t.Fatalf("expected the bound audience to be admitted on the gateway, got %d: %s", status, body)
	}
}

// TestJWTLoginWrongIssuer verifies JWT with wrong issuer is rejected (T-060).
func TestJWTLoginWrongIssuer(t *testing.T) {
	port := h.GetLeaderPort(t)

	forgedJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIiwiaXNzIjoiaHR0cDovL2V2aWwuY29tIn0.invalid"
	loginBody := fmt.Sprintf(`{"jwt":"%s"}`, forgedJWT)
	u := fmt.Sprintf("%s/v1/auth/jwt/login", h.NodeURL(port))

	status, _ := h.DoRequest(t, "POST", u,
		map[string]string{"Content-Type": "application/json"}, loginBody)
	if status != 401 && status != 403 && status != 400 {
		t.Fatalf("expected 401, 403, or 400 for wrong issuer, got %d", status)
	}
}

// TestTokenIPBindingDisabled verifies requests with X-Forwarded-For succeed
// when IP binding is disabled (T-061).
func TestTokenIPBindingDisabled(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	u := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(port))
	headers := map[string]string{
		"Authorization":   "Bearer " + jwt,
		"X-Forwarded-For": "10.99.99.99",
	}

	status, _ := h.DoRequest(t, "GET", u, headers, "")
	if status != 200 {
		t.Fatalf("expected 200 with IP binding disabled, got %d", status)
	}
}

// TestRequestWithNoToken verifies unauthenticated requests are rejected (T-062).
func TestRequestWithNoToken(t *testing.T) {
	port := h.GetLeaderPort(t)
	u := fmt.Sprintf("%s/v1/sys/namespaces?warden-list=true", h.NodeURL(port))

	status, _ := h.DoRequest(t, "GET", u, nil, "")
	if status != 403 && status != 401 {
		t.Fatalf("expected 403 or 401, got %d", status)
	}
}

// TestRootPolicyAccess verifies root token can access system endpoints (T-064).
func TestRootPolicyAccess(t *testing.T) {
	port := h.GetLeaderPort(t)

	healthStatus, _ := h.APIRequest(t, "GET", "sys/health", port, "")
	if healthStatus != 200 {
		t.Fatalf("sys/health: expected 200, got %d", healthStatus)
	}

	nsStatus, _ := h.APIRequest(t, "GET", "sys/namespaces?warden-list=true", port, "")
	if nsStatus != 200 {
		t.Fatalf("sys/namespaces: expected 200, got %d", nsStatus)
	}

	credStatus, _ := h.APIRequest(t, "GET", "sys/cred/sources?warden-list=true", port, "")
	if credStatus != 200 {
		t.Fatalf("sys/cred/sources: expected 200, got %d", credStatus)
	}
}

// TestPolicyWildcardSegments verifies wildcard policy creation and read-back (T-065).
func TestPolicyWildcardSegments(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-wildcard", port,
		`{"policy":"path \"vault/role/e2e-reader/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n}"}`)

	readStatus, _ := h.APIRequest(t, "GET", "sys/policies/cbp/e2e-wildcard", port, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on policy read, got %d", readStatus)
	}

	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-wildcard", port, "")
}

// TestTokenLookupAfterFailover verifies a JWT remains valid
// on the new leader after failover (T-066).
func TestTokenLookupAfterFailover(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status != 200 {
		t.Fatalf("expected 200 before failover, got %d", status)
	}

	nodeNum := h.NodeNumberForPort(leader)
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	newStatus, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", newLeader, jwt)
	if newStatus != 200 {
		t.Fatalf("expected 200 after failover, got %d", newStatus)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestConditionsSourceIPDenied verifies that a CEL condition gating on source
// IP denies a request whose client IP does not match, even with correct
// capabilities (T-070).
func TestConditionsSourceIPDenied(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-deny", port,
		`{"policy":"path \"vault/role/e2e-reader/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n  condition = \"cidrContains('10.0.0.0/8', request.client_ip)\"\n}"}`)
	h.GrantRole(t, port, "auth/jwt/", "e2e-cond-deny-test",
		h.Role{Policies: []string{"e2e-cond-deny"}, CredSpec: "vault-token-reader"}, nil)

	jwt := h.GetDefaultJWT(t)

	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-cond-deny-test", port, jwt)
	if status != 403 {
		t.Fatalf("expected 403 with non-matching source_ip condition, got %d", status)
	}

	h.RevokeRole(t, port, "auth/jwt/", "e2e-cond-deny-test")
	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-cond-deny", port, "")
}

// TestConditionsBlockRejected verifies that the removed conditions {} block is
// rejected at policy-write time with a directed error (T-071).
func TestConditionsBlockRejected(t *testing.T) {
	port := h.GetLeaderPort(t)

	status, _ := h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-block", port,
		`{"policy":"path \"secret/*\" {\n  capabilities = [\"read\"]\n  conditions {\n    source_ip = [\"10.0.0.0/8\"]\n  }\n}"}`)
	if status != 400 {
		t.Fatalf("expected 400 for the removed conditions {} block, got %d", status)
	}
}

// TestConditionRejectsInvalidCEL verifies that a CEL condition that does not
// compile to a bool is rejected at policy-write time (T-072).
func TestConditionRejectsInvalidCEL(t *testing.T) {
	port := h.GetLeaderPort(t)

	status, _ := h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-bad-cel", port,
		`{"policy":"path \"secret/*\" {\n  capabilities = [\"read\"]\n  condition = \"1 + 1\"\n}"}`)
	if status != 400 {
		t.Fatalf("expected 400 for a non-bool CEL condition, got %d", status)
	}
}

// TestConditionRecordedInAudit verifies that a path-level CEL condition's
// decision and referenced inputs are recorded in the audit log. The policy path
// matches the role used for the request so the condition is actually reached
// (T-073).
func TestConditionRecordedInAudit(t *testing.T) {
	port := h.GetLeaderPort(t)
	node := h.NodeNumberForPort(port)

	// Condition always holds (request.path is non-empty) → allow, and records
	// request.path in the audited inputs.
	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-audit", port,
		`{"policy":"path \"vault/role/e2e-cond-audit-role/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n  condition = \"request.path != ''\"\n}"}`)
	h.GrantRole(t, port, "auth/jwt/", "e2e-cond-audit-role",
		h.Role{Policies: []string{"e2e-cond-audit"}, CredSpec: "vault-token-reader"}, nil)
	defer func() {
		h.RevokeRole(t, port, "auth/jwt/", "e2e-cond-audit-role")
		h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-cond-audit", port, "")
	}()

	jwt := h.GetDefaultJWT(t)
	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-cond-audit-role", port, jwt)
	if status != 200 {
		t.Fatalf("expected 200 (condition allows), got %d", status)
	}

	cond := findAuditedCondition(t, node, "e2e-cond-audit-role")
	if cond == nil {
		t.Fatal("expected an audit entry carrying auth.policy_results.condition")
	}
	if cond.Decision != "allow" {
		t.Fatalf("condition decision = %q, want allow", cond.Decision)
	}
	if cond.Inputs["request.path"] == "" {
		t.Fatalf("expected request.path recorded in condition inputs, got %v", cond.Inputs)
	}
}

// TestConditionRequestNamespaceEnforced verifies the request.namespace variable:
// a condition matching the request's (root) namespace allows; one requiring a
// different namespace denies (T-074).
func TestConditionRequestNamespaceEnforced(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.GrantRole(t, port, "auth/jwt/", "e2e-cond-ns-role",
		h.Role{Policies: []string{"e2e-cond-ns"}, CredSpec: "vault-token-reader"}, nil)
	defer func() {
		h.RevokeRole(t, port, "auth/jwt/", "e2e-cond-ns-role")
		h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-cond-ns", port, "")
	}()
	jwt := h.GetDefaultJWT(t)

	// Root request → request.namespace == "" → condition matches → allow.
	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-ns", port,
		`{"policy":"path \"vault/role/e2e-cond-ns-role/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n  condition = \"request.namespace == ''\"\n}"}`)
	if status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-cond-ns-role", port, jwt); status != 200 {
		t.Fatalf("root-namespace match: expected 200, got %d", status)
	}

	// Same request, condition now requires a different namespace → deny.
	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-ns", port,
		`{"policy":"path \"vault/role/e2e-cond-ns-role/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n  condition = \"request.namespace == 'other/'\"\n}"}`)
	if status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-cond-ns-role", port, jwt); status != 403 {
		t.Fatalf("cross-namespace mismatch: expected 403, got %d", status)
	}
}

const (
	denyProbe = "secret/data/e2e/app-config"
	denyOther = "secret/data/e2e/database"

	// conditionHolds and conditionFails are true and false on every request.
	conditionHolds = "request.path != ''"
	conditionFails = "request.path == 'nowhere'"
)

// grantPolicies writes the CBP policies named role-<key> and a role holding
// them, granted to every JWT caller, and removes them all when the test ends.
// It returns the full policy names by key.
func grantPolicies(t *testing.T, port int, role string, docs map[string]string) map[string]string {
	t.Helper()
	names := make(map[string]string, len(docs))
	policies := make([]string, 0, len(docs))
	for key, doc := range docs {
		name := role + "-" + key
		if status, body := h.APIRequest(t, "POST", "sys/policies/cbp/"+name, port, fmt.Sprintf(`{"policy":%q}`, doc)); status >= 300 {
			t.Fatalf("write policy %s: %d: %s", name, status, body)
		}
		names[key] = name
		policies = append(policies, name)
	}
	h.GrantRole(t, port, "auth/jwt/", role, h.Role{Policies: policies, CredSpec: "vault-token-reader"}, nil)
	t.Cleanup(func() {
		h.RevokeRole(t, port, "auth/jwt/", role)
		for _, name := range names {
			h.APIRequest(t, "DELETE", "sys/policies/cbp/"+name, port, "")
		}
	})
	return names
}

// stanza renders one policy stanza; condition may be empty.
func stanza(path, capabilities, condition string) string {
	s := fmt.Sprintf("path %q {\n  capabilities = [%s]\n", path, capabilities)
	if condition != "" {
		s += fmt.Sprintf("  condition = %q\n", condition)
	}
	return s + "}\n"
}

// awaitPolicyResults waits for an audit entry whose line contains marker and
// whose policy results match accepts, and returns those results.
func awaitPolicyResults(t *testing.T, port int, marker string, match func(*audit.PolicyResults) bool) *audit.PolicyResults {
	t.Helper()
	entries := h.AwaitAuditEntries(t, h.NodeNumberForPort(port), marker, 1, func(e audit.LogEntry) bool {
		return e.Auth != nil && e.Auth.PolicyResults != nil && match(e.Auth.PolicyResults)
	})
	return entries[0].Auth.PolicyResults
}

// awaitRefusal returns the policy results of a refused request.
func awaitRefusal(t *testing.T, port int, marker string) *audit.PolicyResults {
	t.Helper()
	return awaitPolicyResults(t, port, marker, func(r *audit.PolicyResults) bool { return !r.Allowed })
}

// awaitGrant returns the policy results of a request that policy granted. A
// gateway request also audits its login, so being allowed doesn't identify it.
func awaitGrant(t *testing.T, port int, marker, policy string) *audit.PolicyResults {
	t.Helper()
	return awaitPolicyResults(t, port, marker, func(r *audit.PolicyResults) bool {
		return r.Allowed && slices.Contains(r.GrantingPolicies, policy)
	})
}

// A condition gates only its own stanza's capabilities: an unconditional stanza
// for other capabilities on the same path, in the same policy, doesn't lift it.
func TestPolicyCondition_GatesOnlyItsOwnStanza(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	for _, tc := range []struct {
		name, role, condition string
		want                  int
	}{
		{"false refuses", "e2e-bound-false", conditionFails, 403},
		{"true allows", "e2e-bound-true", conditionHolds, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := "vault/role/" + tc.role + "/gateway/*"
			names := grantPolicies(t, port, tc.role, map[string]string{"mixed": stanza(gateway, `"read"`, tc.condition) +
				stanza(gateway, `"create", "update", "list"`, "")})

			status, body := h.VaultTransparentRequest(t, "GET", denyProbe, tc.role, port, jwt)
			if status != tc.want {
				t.Fatalf("GET = %d, want %d: %s", status, tc.want, body)
			}
			var results *audit.PolicyResults
			if tc.want == 200 {
				results = awaitGrant(t, port, tc.role, names["mixed"])
			} else {
				results = awaitRefusal(t, port, tc.role)
			}
			if results.Condition == nil || results.Condition.Expression != tc.condition {
				t.Fatalf("audited condition = %+v, want the read stanza's", results.Condition)
			}
			if results.DenyingPolicy != "" {
				t.Fatalf("denying_policy = %q: a grant that didn't apply denied nothing", results.DenyingPolicy)
			}
		})
	}
}

// Sudo answers to the condition of the stanza that brought it, on a path that
// needs sudo, whatever an unconditional stanza grants beside it.
//
// A person's session is the credential here: a Root path is a system path, and
// a bearer JWT authenticates only on a provider's mount.
func TestPolicyCondition_SudoAnswersToItsOwnStanza(t *testing.T) {
	e := newHumanEnv(t)
	const groups = "sys/identity/group/*"
	refused, allowed := h.UniqueMount("e2e-sudo-false"), h.UniqueMount("e2e-sudo-true")
	e.grant(t, refused, stanza(groups, `"read"`, "")+stanza(groups, `"sudo"`, conditionFails), h.Role{})
	e.grant(t, allowed, stanza(groups, `"read"`, "")+stanza(groups, `"sudo"`, conditionHolds), h.Role{})

	home := t.TempDir()
	if run := e.login(t, home, personAda, "-role="+refused); run.Err != nil {
		t.Fatalf("login: %v\n%s", run.Err, run.Stderr)
	}
	ticket := h.SessionTicket(t, home)

	// A role in a header isn't in the audited path, so the path names the row.
	path := "sys/identity/group/" + refused
	if status, body := h.TicketRequest(t, "GET", path, e.port, ticket, asRole(refused)); status != 403 {
		t.Fatalf("sudo condition false = %d, want 403: %s", status, body)
	}
	results := awaitRefusal(t, e.port, path)
	if results.Condition == nil || results.Condition.Expression != conditionFails {
		t.Fatalf("audited condition = %+v, want the sudo stanza's", results.Condition)
	}

	if status, body := h.TicketRequest(t, "GET", "sys/identity/group/"+allowed, e.port, ticket, asRole(allowed)); status == 403 {
		t.Fatalf("sudo condition true was refused: %s", body)
	}
}

// A plain deny applies on every path it matches, so a more specific grant no
// longer beats it, and the audit names the policy that denied.
func TestPolicyDeny_PlainBeatsAMoreSpecificGrant(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)
	const role = "e2e-deny-plain"
	names := grantPolicies(t, port, role, map[string]string{
		"reader": stanza("vault/role/"+role+"/gateway/v1/"+denyProbe, `"read"`, ""),
		"closed": stanza("vault/role/"+role+"/gateway/*", `"deny"`, ""),
	})

	if status, body := h.VaultTransparentRequest(t, "GET", denyProbe, role, port, jwt); status != 403 {
		t.Fatalf("GET = %d, want 403: %s", status, body)
	}
	results := awaitRefusal(t, port, role)
	if results.DenyingPolicy != names["closed"] {
		t.Fatalf("denying_policy = %q, want %q", results.DenyingPolicy, names["closed"])
	}
	if results.Condition != nil {
		t.Fatalf("condition = %+v, want none: no CEL ran", results.Condition)
	}
}

// A conditional deny applies only when its condition holds, reaches every path
// it matches, and doesn't hide a broader grant when it stands aside.
func TestPolicyDeny_ConditionDecidesWhenItApplies(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	for _, tc := range []struct {
		name, role, grant, deny, condition string
		want                               int
	}{
		{"a broader deny fires over a specific grant", "e2e-deny-broad-fires", "v1/" + denyProbe, "*", conditionHolds, 403},
		{"a broader deny stands aside", "e2e-deny-broad-aside", "v1/" + denyProbe, "*", conditionFails, 200},
		{"a narrower deny fires over a broad grant", "e2e-deny-narrow-fires", "*", "v1/" + denyProbe, conditionHolds, 403},
		{"a narrower deny stands aside and hides nothing", "e2e-deny-narrow-aside", "*", "v1/" + denyProbe, conditionFails, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := "vault/role/" + tc.role + "/gateway/"
			names := grantPolicies(t, port, tc.role, map[string]string{
				"grant": stanza(prefix+tc.grant, `"read"`, ""),
				"guard": stanza(prefix+tc.deny, `"deny"`, tc.condition),
			})

			status, body := h.VaultTransparentRequest(t, "GET", denyProbe, tc.role, port, jwt)
			if status != tc.want {
				t.Fatalf("GET = %d, want %d: %s", status, tc.want, body)
			}
			if tc.want == 200 {
				results := awaitGrant(t, port, tc.role, names["grant"])
				if results.DenyingPolicy != "" || results.Condition != nil {
					t.Fatalf("a deny that stood aside left a trace: %+v", results)
				}
				return
			}
			results := awaitRefusal(t, port, tc.role)
			if results.DenyingPolicy != names["guard"] {
				t.Fatalf("denying_policy = %q, want %q", results.DenyingPolicy, names["guard"])
			}
			if results.Condition == nil || results.Condition.Decision != "deny" || results.Condition.Expression != tc.condition {
				t.Fatalf("audited condition = %+v, want the deny's", results.Condition)
			}
		})
	}
}

// A deny condition that can't be evaluated refuses the request.
func TestPolicyDeny_ErroringConditionRefuses(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)
	const role = "e2e-deny-error"
	gateway := "vault/role/" + role + "/gateway/*"
	names := grantPolicies(t, port, role, map[string]string{
		"grant": stanza(gateway, `"read"`, ""),
		"guard": stanza(gateway, `"deny"`, "request.data.tier == 'gold'"),
	})

	if status, body := h.VaultTransparentRequest(t, "GET", denyProbe, role, port, jwt); status != 403 {
		t.Fatalf("GET = %d, want 403: %s", status, body)
	}
	results := awaitRefusal(t, port, role)
	if results.DenyingPolicy != names["guard"] {
		t.Fatalf("denying_policy = %q, want %q", results.DenyingPolicy, names["guard"])
	}
	if results.Condition == nil || results.Condition.ErrorKind != "no_such_key" {
		t.Fatalf("audited condition = %+v, want error_kind no_such_key", results.Condition)
	}
}

// A carve-out lives inside the deny, as a condition on request.path.
func TestPolicyDeny_CarveOutInsideTheDeny(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)
	const role = "e2e-deny-carveout"
	gateway := "vault/role/" + role + "/gateway/"
	grantPolicies(t, port, role, map[string]string{
		"grant": stanza(gateway+"*", `"read"`, ""),
		"guard": stanza(gateway+"*", `"deny"`, "request.path != '"+gateway+"v1/"+denyProbe+"'"),
	})

	if status, body := h.VaultTransparentRequest(t, "GET", denyProbe, role, port, jwt); status != 200 {
		t.Fatalf("carved-out path = %d, want 200: %s", status, body)
	}
	if status, body := h.VaultTransparentRequest(t, "GET", denyOther, role, port, jwt); status != 403 {
		t.Fatalf("other path = %d, want 403: %s", status, body)
	}
}

// A deny's condition is compiled, so a broken one is refused at write where it
// used to be ignored.
func TestPolicyDeny_InvalidConditionRefusedAtWrite(t *testing.T) {
	port := h.GetLeaderPort(t)
	doc := stanza("secret/*", `"deny"`, "1 + 1")
	status, body := h.APIRequest(t, "POST", "sys/policies/cbp/e2e-deny-bad-cel", port, fmt.Sprintf(`{"policy":%q}`, doc))
	if status != 400 {
		t.Fatalf("write = %d, want 400: %s", status, body)
	}
}

// A request arriving at a standby is held to every deny the same way.
func TestPolicyDeny_AppliesThroughAStandby(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)
	jwt := h.GetDefaultJWT(t)
	const role = "e2e-deny-standby"
	prefix := "vault/role/" + role + "/gateway/"
	names := grantPolicies(t, leader, role, map[string]string{
		"grant": stanza(prefix+"*", `"read"`, ""),
		"guard": stanza(prefix+"v1/"+denyProbe, `"deny"`, ""),
	})

	if status, body := h.VaultTransparentRequest(t, "GET", denyProbe, role, standby, jwt); status != 403 {
		t.Fatalf("denied path through the standby = %d, want 403: %s", status, body)
	}
	if status, body := h.VaultTransparentRequest(t, "GET", denyOther, role, standby, jwt); status != 200 {
		t.Fatalf("other path through the standby = %d, want 200: %s", status, body)
	}
	if results := awaitRefusal(t, leader, role); results.DenyingPolicy != names["guard"] {
		t.Fatalf("denying_policy = %q, want %q", results.DenyingPolicy, names["guard"])
	}
}
