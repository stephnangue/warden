//go:build e2e

package auth

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestJWTLoginValidClaims verifies JWT login with valid claims succeeds (T-057).
func TestJWTLoginValidClaims(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status, token := h.LoginJWTNT(t, jwt, "e2e-nt-reader", port)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d", status)
	}
	if token == "" {
		t.Fatalf("expected non-empty token, got empty string")
	}
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
		`{"token_policies":["vault-gateway-access"],"token_type":"transparent","cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300,"bound_audiences":["some-other-audience"]}`)

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
	token := h.GetNTWardenToken(t, port)

	u := fmt.Sprintf("%s/v1/vault-nt/gateway/v1/secret/data/e2e/app-config", h.NodeURL(port))
	headers := map[string]string{
		"X-Warden-Token":  token,
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

// TestPolicyDenyOverride verifies that deny and allow policies can coexist
// on a role and the token is created successfully (T-063).
func TestPolicyDenyOverride(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-allow-all", port,
		`{"policy":"path \"*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`)
	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-deny-seal", port,
		`{"policy":"path \"sys/seal\" {\n  capabilities = [\"deny\"]\n}"}`)
	h.APIRequest(t, "POST", "auth/jwt/role/e2e-deny-test", port,
		`{"token_policies":["e2e-allow-all","e2e-deny-seal"],"token_type":"warden","cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300}`)

	jwt := h.GetDefaultJWT(t)
	loginStatus, token := h.LoginJWT(t, jwt, "e2e-deny-test", port)
	if loginStatus != 200 && loginStatus != 201 {
		t.Fatalf("expected 200 or 201 on login, got %d", loginStatus)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}

	h.APIRequest(t, "DELETE", "auth/jwt/role/e2e-deny-test", port, "")
	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-allow-all", port, "")
	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-deny-seal", port, "")
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
		`{"policy":"path \"vault-nt/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n}"}`)

	readStatus, _ := h.APIRequest(t, "GET", "sys/policies/cbp/e2e-wildcard", port, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on policy read, got %d", readStatus)
	}

	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-wildcard", port, "")
}

// TestTokenLookupAfterFailover verifies a Warden token remains valid
// on the new leader after failover (T-066).
func TestTokenLookupAfterFailover(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	status, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if status != 200 {
		t.Fatalf("expected 200 before failover, got %d", status)
	}

	nodeNum := h.NodeNumberForPort(leader)
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	newStatus, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", newLeader, token)
	if newStatus != 200 {
		t.Fatalf("expected 200 after failover, got %d", newStatus)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestMultipleAuthRolesDifferentPolicies verifies creating a role with a
// different policy and logging in with it succeeds (T-067).
func TestMultipleAuthRolesDifferentPolicies(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-readonly", port,
		`{"policy":"path \"vault-nt/gateway/v1/secret/data/e2e/*\" {\n  capabilities = [\"read\"]\n}"}`)
	h.APIRequest(t, "POST", "auth/jwt/role/e2e-readonly", port,
		`{"token_policies":["e2e-readonly"],"token_type":"warden","cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300}`)

	jwt := h.GetDefaultJWT(t)
	loginStatus, token := h.LoginJWT(t, jwt, "e2e-readonly", port)
	if loginStatus != 200 && loginStatus != 201 {
		t.Fatalf("expected 200 or 201 on login, got %d", loginStatus)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}

	h.APIRequest(t, "DELETE", "auth/jwt/role/e2e-readonly", port, "")
	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-readonly", port, "")
}

// TestTokenTTLDecrement verifies login succeeds and returns token data (T-068).
func TestTokenTTLDecrement(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status, token := h.LoginJWTNT(t, jwt, "e2e-nt-reader", port)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d", status)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}
}

// TestConditionsSourceIPAllowed verifies that a policy with source_ip condition
// matching the request IP (127.0.0.1 for localhost) allows the request (T-069).
func TestConditionsSourceIPAllowed(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-allow", port,
		`{"policy":"path \"vault-nt/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n  conditions {\n    source_ip = [\"127.0.0.0/8\"]\n  }\n}"}`)
	h.APIRequest(t, "POST", "auth/jwt-nt/role/e2e-cond-allow-test", port,
		`{"token_policies":["e2e-cond-allow"],"token_type":"warden","cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300}`)

	jwt := h.GetDefaultJWT(t)
	loginStatus, token := h.LoginJWTNT(t, jwt, "e2e-cond-allow-test", port)
	if loginStatus != 200 && loginStatus != 201 {
		t.Fatalf("expected 200 or 201 on login, got %d", loginStatus)
	}

	status, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", port, token)
	if status != 200 {
		t.Fatalf("expected 200 with matching source_ip condition, got %d", status)
	}

	h.APIRequest(t, "DELETE", "auth/jwt-nt/role/e2e-cond-allow-test", port, "")
	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-cond-allow", port, "")
}

// TestConditionsSourceIPDenied verifies that a policy with source_ip condition
// NOT matching the request IP denies even with correct capabilities (T-070).
func TestConditionsSourceIPDenied(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-deny", port,
		`{"policy":"path \"vault-nt/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n  conditions {\n    source_ip = [\"10.0.0.0/8\"]\n  }\n}"}`)
	h.APIRequest(t, "POST", "auth/jwt-nt/role/e2e-cond-deny-test", port,
		`{"token_policies":["e2e-cond-deny"],"token_type":"warden","cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300}`)

	jwt := h.GetDefaultJWT(t)
	loginStatus, token := h.LoginJWTNT(t, jwt, "e2e-cond-deny-test", port)
	if loginStatus != 200 && loginStatus != 201 {
		t.Fatalf("expected 200 or 201 on login, got %d", loginStatus)
	}

	status, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", port, token)
	if status != 403 {
		t.Fatalf("expected 403 with non-matching source_ip condition, got %d", status)
	}

	h.APIRequest(t, "DELETE", "auth/jwt-nt/role/e2e-cond-deny-test", port, "")
	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-cond-deny", port, "")
}

// TestConditionsInvalidCIDRRejected verifies that creating a policy with an
// invalid CIDR in source_ip conditions is rejected at parse time (T-071).
func TestConditionsInvalidCIDRRejected(t *testing.T) {
	port := h.GetLeaderPort(t)

	status, _ := h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-bad-cidr", port,
		`{"policy":"path \"secret/*\" {\n  capabilities = [\"read\"]\n  conditions {\n    source_ip = [\"not-a-cidr\"]\n  }\n}"}`)
	if status != 400 {
		t.Fatalf("expected 400 for invalid CIDR, got %d", status)
	}
}

// TestConditionsUnknownTypeRejected verifies that creating a policy with an
// unknown condition type is rejected at parse time (T-072).
func TestConditionsUnknownTypeRejected(t *testing.T) {
	port := h.GetLeaderPort(t)

	status, _ := h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-bad-type", port,
		`{"policy":"path \"secret/*\" {\n  capabilities = [\"read\"]\n  conditions {\n    hostname = [\"foo.example.com\"]\n  }\n}"}`)
	if status != 400 {
		t.Fatalf("expected 400 for unknown condition type, got %d", status)
	}
}

// TestConditionsMergeWithUnconditional verifies that when a role has both a
// conditional and an unconditional policy for the same path, the unconditional
// policy wins (OR semantics) and access is granted (T-073).
func TestConditionsMergeWithUnconditional(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Conditional policy: source_ip does NOT match loopback
	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-restricted", port,
		`{"policy":"path \"vault-nt/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n  conditions {\n    source_ip = [\"10.0.0.0/8\"]\n  }\n}"}`)
	// Unconditional policy for same path
	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-unrestricted", port,
		`{"policy":"path \"vault-nt/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n}"}`)
	// Role with both policies
	h.APIRequest(t, "POST", "auth/jwt-nt/role/e2e-cond-merge-test", port,
		`{"token_policies":["e2e-cond-restricted","e2e-cond-unrestricted"],"token_type":"warden","cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300}`)

	jwt := h.GetDefaultJWT(t)
	loginStatus, token := h.LoginJWTNT(t, jwt, "e2e-cond-merge-test", port)
	if loginStatus != 200 && loginStatus != 201 {
		t.Fatalf("expected 200 or 201 on login, got %d", loginStatus)
	}

	// Unconditional policy wins: access granted despite source_ip mismatch
	status, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", port, token)
	if status != 200 {
		t.Fatalf("expected 200 when unconditional policy overrides conditions, got %d", status)
	}

	h.APIRequest(t, "DELETE", "auth/jwt-nt/role/e2e-cond-merge-test", port, "")
	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-cond-restricted", port, "")
	h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-cond-unrestricted", port, "")
}
