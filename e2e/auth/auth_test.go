//go:build e2e

package auth

import (
	"fmt"
	"testing"
	"time"

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

	status, _ := h.LoginJWT(t, jwt, "e2e-reader", port)
	if status != 401 && status != 403 && status != 400 {
		t.Fatalf("expected 401, 403, or 400 for expired JWT, got %d", status)
	}
}

// TestJWTLoginWrongAudience verifies JWT with wrong audience is rejected (T-059).
func TestJWTLoginWrongAudience(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "POST", "auth/jwt/role/e2e-bound-aud", port,
		`{"token_policies":["vault-gateway-access"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300,"bound_audiences":["some-other-audience"]}`)

	jwt := h.GetDefaultJWT(t)
	status, _ := h.LoginJWT(t, jwt, "e2e-bound-aud", port)
	if status != 401 && status != 403 && status != 400 {
		t.Fatalf("expected 401, 403, or 400 for wrong audience, got %d", status)
	}

	h.APIRequest(t, "DELETE", "auth/jwt/role/e2e-bound-aud", port, "")
}

// TestJWTLoginWrongIssuer verifies JWT with wrong issuer is rejected (T-060).
func TestJWTLoginWrongIssuer(t *testing.T) {
	port := h.GetLeaderPort(t)

	forgedJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIiwiaXNzIjoiaHR0cDovL2V2aWwuY29tIn0.invalid"
	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"e2e-reader"}`, forgedJWT)
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
	h.APIRequest(t, "POST", "auth/jwt/role/e2e-cond-deny-test", port,
		`{"token_policies":["e2e-cond-deny"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300}`)

	jwt := h.GetDefaultJWT(t)

	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-cond-deny-test", port, jwt)
	if status != 403 {
		t.Fatalf("expected 403 with non-matching source_ip condition, got %d", status)
	}

	h.APIRequest(t, "DELETE", "auth/jwt/role/e2e-cond-deny-test", port, "")
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
	h.APIRequest(t, "POST", "auth/jwt/role/e2e-cond-audit-role", port,
		`{"token_policies":["e2e-cond-audit"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300}`)
	defer func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/e2e-cond-audit-role", port, "")
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

	h.APIRequest(t, "POST", "auth/jwt/role/e2e-cond-ns-role", port,
		`{"token_policies":["e2e-cond-ns"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300}`)
	defer func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/e2e-cond-ns-role", port, "")
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
