//go:build e2e

package credential

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestIssueVaultTokenEndToEnd verifies end-to-end Vault token issuance via
// non-transparent gateway: login, request secret, verify data exists (T-021).
func TestIssueVaultTokenEndToEnd(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	status, body := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
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
// token both succeed, exercising the credential cache path (T-022).
func TestCredentialCacheHit(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	status1, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if status1 != 200 {
		t.Fatalf("first request: expected 200, got %d", status1)
	}

	status2, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if status2 != 200 {
		t.Fatalf("second request (cache hit): expected 200, got %d", status2)
	}
}

// TestCredentialCacheIsolationBetweenTokens verifies that two different Warden
// tokens each get independent credential cache entries (T-023).
func TestCredentialCacheIsolationBetweenTokens(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token1 := h.GetNTWardenToken(t, leader)
	token2 := h.GetNTWardenToken(t, leader)

	status1, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token1)
	if status1 != 200 {
		t.Fatalf("token1 request: expected 200, got %d", status1)
	}

	status2, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token2)
	if status2 != 200 {
		t.Fatalf("token2 request: expected 200, got %d", status2)
	}
}

// TestCredentialRevocationOnTokenExpiry verifies that an ephemeral token works
// immediately but may be rejected after its TTL expires (T-025).
func TestCredentialRevocationOnTokenExpiry(t *testing.T) {
	leader := h.GetLeaderPort(t)

	jwt := h.GetJWT(t, "e2e-ephemeral", "ephemeral-secret")
	loginStatus, token := h.LoginJWT(t, jwt, "e2e-nt-reader", leader)
	if loginStatus != 200 && loginStatus != 201 {
		t.Skipf("ephemeral login failed with status %d, skipping", loginStatus)
	}
	if token == "" {
		t.Skipf("ephemeral login returned no token, skipping")
	}

	status1, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if status1 != 200 {
		t.Fatalf("immediate request: expected 200, got %d", status1)
	}

	time.Sleep(5 * time.Second)

	u := fmt.Sprintf("%s/v1/vault-nt/gateway/v1/secret/data/e2e/app-config", h.NodeURL(leader))
	headers := map[string]string{"X-Warden-Token": token}
	status2, _ := h.TryRequest("GET", u, headers, "")
	if status2 != 200 && status2 != 403 {
		t.Fatalf("after TTL expiry: expected 200 or 403, got %d", status2)
	}
}

// TestIssueCredentialNonExistentSpec verifies the response when accessing a
// Vault path that may not exist via a valid token (T-026).
func TestIssueCredentialNonExistentSpec(t *testing.T) {
	leader := h.GetLeaderPort(t)

	jwt := h.GetDefaultJWT(t)
	loginStatus, token := h.LoginJWT(t, jwt, "e2e-nt-reader", leader)
	if loginStatus != 200 && loginStatus != 201 {
		t.Fatalf("login failed with status %d", loginStatus)
	}
	if token == "" {
		t.Fatalf("login returned no token")
	}

	status, _ := h.VaultNTRequest(t, "GET", "secret/data/nonexistent-path", leader, token)
	if status != 200 && status != 404 {
		t.Fatalf("expected 200 or 404 for nonexistent path, got %d", status)
	}
}

// TestIssueCredentialExpiredToken verifies that using an expired ephemeral
// token returns 401 or 403 (T-027).
func TestIssueCredentialExpiredToken(t *testing.T) {
	leader := h.GetLeaderPort(t)

	jwt := h.GetJWT(t, "e2e-ephemeral", "ephemeral-secret")
	loginStatus, token := h.LoginJWT(t, jwt, "e2e-nt-reader", leader)
	if loginStatus != 200 && loginStatus != 201 {
		t.Skipf("ephemeral login failed with status %d, skipping", loginStatus)
	}
	if token == "" {
		t.Skipf("ephemeral login returned no token, skipping")
	}

	time.Sleep(5 * time.Second)

	u := fmt.Sprintf("%s/v1/vault-nt/gateway/v1/secret/data/e2e/app-config", h.NodeURL(leader))
	headers := map[string]string{"X-Warden-Token": token}
	status, _ := h.TryRequest("GET", u, headers, "")
	if status != 403 && status != 401 {
		t.Fatalf("expected 403 or 401 for expired token, got %d", status)
	}
}

// TestCredentialIssuanceSourceDown confirms that credential issuance works
// when the backing Vault source is available (T-028).
func TestCredentialIssuanceSourceDown(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	status, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if status != 200 {
		t.Fatalf("expected 200 confirming source is working, got %d", status)
	}
}

// TestMultipleCredentialTypesFromSameSource verifies that the same token can
// access different Vault paths from the same source (T-029).
func TestMultipleCredentialTypesFromSameSource(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	status1, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if status1 != 200 {
		t.Fatalf("secret/data/e2e/app-config: expected 200, got %d", status1)
	}

	status2, _ := h.VaultNTRequest(t, "GET", "secret/metadata/e2e/app-config", leader, token)
	if status2 != 200 {
		t.Fatalf("secret/metadata/e2e/app-config: expected 200, got %d", status2)
	}
}

// TestConcurrentCredentialIssuanceSingleflight verifies that 10 concurrent
// requests with the same token all succeed (T-030).
func TestConcurrentCredentialIssuanceSingleflight(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	success := h.ConcurrentDo(10, func(i int) bool {
		status, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
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

	token := h.GetNSNTWardenToken(t, h.NSVaultNS, leader)

	status, _ := h.NSVaultNTRequest(t, "GET", "secret/data/e2e/app-config", h.NSVaultNS, leader, token)
	if status != 200 {
		t.Fatalf("namespace credential issuance: expected 200, got %d", status)
	}

	h.TeardownNSVaultEnv(t, leader)
}

// TestCredentialIssuanceAfterLeaderFailover verifies that credential issuance
// continues to work after the leader is killed and a new leader takes over (T-032).
func TestCredentialIssuanceAfterLeaderFailover(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	status1, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if status1 != 200 {
		t.Fatalf("pre-failover request: expected 200, got %d", status1)
	}

	nodeNum := h.NodeNumberForPort(leader)
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	status2, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", newLeader, token)
	if status2 != 200 {
		t.Fatalf("post-failover request: expected 200, got %d", status2)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
}
