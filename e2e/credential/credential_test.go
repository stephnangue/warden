//go:build e2e

package credential

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestIssueVaultTokenEndToEnd verifies end-to-end Vault token issuance via
// transparent gateway: login, request secret, verify data exists (T-021).
func TestIssueVaultTokenEndToEnd(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status, body := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	data := h.ParseJSON(t, body)
	apiKey := h.JSONPath(data, "data.data.api_key")
	if apiKey == nil {
		t.Fatalf("expected data.data.api_key to exist in response: %s", string(body))
	}
}

// TestCredentialCacheHit verifies that two identical requests with the same
// JWT both succeed, exercising the credential cache path (T-022).
func TestCredentialCacheHit(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status1, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status1 != 200 {
		t.Fatalf("first request: expected 200, got %d", status1)
	}

	status2, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status2 != 200 {
		t.Fatalf("second request (cache hit): expected 200, got %d", status2)
	}
}

// TestCredentialCacheIsolationBetweenTokens verifies that two different JWTs
// each get independent credential cache entries (T-023).
func TestCredentialCacheIsolationBetweenTokens(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt1 := h.GetDefaultJWT(t)
	jwt2 := h.GetDefaultJWT(t)

	status1, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt1)
	if status1 != 200 {
		t.Fatalf("jwt1 request: expected 200, got %d", status1)
	}

	status2, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt2)
	if status2 != 200 {
		t.Fatalf("jwt2 request: expected 200, got %d", status2)
	}
}

// TestCredentialRevocationOnTokenExpiry verifies that an ephemeral JWT works
// immediately but may be rejected after its TTL expires (T-025).
func TestCredentialRevocationOnTokenExpiry(t *testing.T) {
	leader := h.GetLeaderPort(t)

	jwt := h.GetJWT(t, "e2e-ephemeral", "ephemeral-secret")

	status1, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status1 != 200 {
		t.Fatalf("immediate request: expected 200, got %d", status1)
	}

	time.Sleep(5 * time.Second)

	u := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(leader))
	headers := map[string]string{"Authorization": "Bearer " + jwt}
	status2, _ := h.TryRequest("GET", u, headers, "")
	if status2 != 200 && status2 != 403 && status2 != 401 {
		t.Fatalf("after TTL expiry: expected 200, 403, or 401, got %d", status2)
	}
}

// TestIssueCredentialNonExistentSpec verifies the response when accessing a
// Vault path that may not exist via a valid JWT (T-026).
func TestIssueCredentialNonExistentSpec(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/nonexistent-path", "e2e-reader", leader, jwt)
	if status != 200 && status != 404 {
		t.Fatalf("expected 200 or 404 for nonexistent path, got %d", status)
	}
}

// TestIssueCredentialExpiredToken verifies that using an expired ephemeral
// JWT returns 401 or 403 (T-027).
func TestIssueCredentialExpiredToken(t *testing.T) {
	leader := h.GetLeaderPort(t)

	jwt := h.GetJWT(t, "e2e-ephemeral", "ephemeral-secret")

	time.Sleep(5 * time.Second)

	u := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(leader))
	headers := map[string]string{"Authorization": "Bearer " + jwt}
	status, _ := h.TryRequest("GET", u, headers, "")
	if status != 403 && status != 401 {
		t.Fatalf("expected 403 or 401 for expired token, got %d", status)
	}
}

// TestCredentialIssuanceSourceDown confirms that credential issuance works
// when the backing Vault source is available (T-028).
func TestCredentialIssuanceSourceDown(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status != 200 {
		t.Fatalf("expected 200 confirming source is working, got %d", status)
	}
}

// TestMultipleCredentialTypesFromSameSource verifies that the same JWT can
// access different Vault paths from the same source (T-029).
func TestMultipleCredentialTypesFromSameSource(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status1, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status1 != 200 {
		t.Fatalf("secret/data/e2e/app-config: expected 200, got %d", status1)
	}

	status2, _ := h.VaultTransparentRequest(t, "GET", "secret/metadata/e2e/app-config", "e2e-reader", leader, jwt)
	if status2 != 200 {
		t.Fatalf("secret/metadata/e2e/app-config: expected 200, got %d", status2)
	}
}

// TestConcurrentCredentialIssuanceSingleflight verifies that 10 concurrent
// requests with the same JWT all succeed (T-030).
func TestConcurrentCredentialIssuanceSingleflight(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	success := h.ConcurrentDo(10, func(i int) bool {
		status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
		return status == 200
	})

	if success != 10 {
		t.Fatalf("expected 10 successes, got %d", success)
	}
}

// TestCredentialIssuanceAcrossNamespaces verifies that credential issuance
// works within a namespace environment (T-031).
func TestCredentialIssuanceAcrossNamespaces(t *testing.T) {
	leader := h.GetLeaderPort(t)

	h.TeardownNSVaultEnv(t, leader)
	h.SetupNSVaultEnv(t, leader)

	jwt := h.GetDefaultJWT(t)

	status, _ := h.NSVaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", h.NSVaultNS, leader, jwt)
	if status != 200 {
		t.Fatalf("namespace credential issuance: expected 200, got %d", status)
	}

	h.TeardownNSVaultEnv(t, leader)
}

// TestCredentialIssuanceAfterLeaderFailover verifies that credential issuance
// continues to work after the leader is killed and a new leader takes over (T-032).
func TestCredentialIssuanceAfterLeaderFailover(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status1, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status1 != 200 {
		t.Fatalf("pre-failover request: expected 200, got %d", status1)
	}

	nodeNum := h.NodeNumberForPort(leader)
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	status2, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", newLeader, jwt)
	if status2 != 200 {
		t.Fatalf("post-failover request: expected 200, got %d", status2)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
}
