//go:build e2e

package auth

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

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

// TestConditionsSourceIPDenied verifies that a policy with source_ip condition
// NOT matching the request IP denies even with correct capabilities (T-070).
func TestConditionsSourceIPDenied(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "POST", "sys/policies/cbp/e2e-cond-deny", port,
		`{"policy":"path \"vault/role/e2e-reader/gateway/*\" {\n  capabilities = [\"read\",\"list\"]\n  conditions {\n    source_ip = [\"10.0.0.0/8\"]\n  }\n}"}`)
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

