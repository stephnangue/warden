//go:build e2e

package provider

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestVaultTransparentReadKVSecret verifies transparent gateway reads a KV secret (T-069).
func TestVaultTransparentReadKVSecret(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status, body := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}

	data := h.ParseJSON(t, body)
	apiKey := h.JSONPath(data, "data.data.api_key")
	if apiKey == nil {
		t.Fatalf("data.data.api_key not found in response: %s", string(body))
	}
}

// TestVaultTransparentWriteKVSecret verifies a secret written directly to Vault
// can be read back through the transparent gateway (T-070).
func TestVaultTransparentWriteKVSecret(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	// Write directly to Vault
	writeStatus, _ := h.VaultDirectRequest(t, "POST", "secret/data/e2e/write-test",
		`{"data":{"test_key":"test_value_from_e2e"}}`)
	if writeStatus != 200 && writeStatus != 204 {
		t.Fatalf("vault write: expected 200 or 204, got %d", writeStatus)
	}

	// Read back through transparent gateway
	readStatus, readResp := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/write-test", "e2e-reader", leader, jwt)
	if readStatus != 200 {
		t.Fatalf("read: expected 200, got %d: %s", readStatus, string(readResp))
	}

	val := h.JSONString(t, readResp, "data.data.test_key")
	if val != "test_value_from_e2e" {
		t.Fatalf("expected test_value_from_e2e, got %q", val)
	}

	// Cleanup
	h.VaultDirectRequest(t, "DELETE", "secret/data/e2e/write-test", "")
}

// TestVaultTransparentListSecrets verifies transparent gateway can list secrets (T-071).
func TestVaultTransparentListSecrets(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	listURL := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/metadata/e2e/", h.NodeURL(leader))
	headers := map[string]string{"Authorization": "Bearer " + jwt}

	status, body := h.DoRequest(t, "LIST", listURL, headers, "")
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}
}

// TestVaultGatewayDeleteSecret verifies a secret written and deleted via Vault
// is no longer readable through the gateway (T-073).
func TestVaultGatewayDeleteSecret(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	// Write directly to Vault
	writeStatus, _ := h.VaultDirectRequest(t, "POST", "secret/data/e2e/delete-test",
		`{"data":{"delete_key":"delete_value"}}`)
	if writeStatus != 200 && writeStatus != 204 {
		t.Fatalf("vault write: expected 200 or 204, got %d", writeStatus)
	}

	// Verify readable through gateway
	readStatus, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/delete-test", "e2e-reader", leader, jwt)
	if readStatus != 200 {
		t.Fatalf("read: expected 200, got %d", readStatus)
	}

	// Delete via Vault
	h.VaultDirectRequest(t, "DELETE", "secret/data/e2e/delete-test", "")

	// Verify no longer readable through gateway
	afterStatus, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/delete-test", "e2e-reader", leader, jwt)
	if afterStatus == 200 {
		t.Fatalf("expected non-200 after delete, got 200")
	}
}

// TestVaultGatewayAfterLeaderFailover verifies vault gateway works after leader failover (T-074).
func TestVaultGatewayAfterLeaderFailover(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	// Verify gateway works on standby before failover
	standby := h.GetStandbyPort(t)
	preStatus, preBody := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", standby, token)
	if preStatus != 200 {
		t.Fatalf("pre-failover standby request: expected 200, got %d: %s", preStatus, string(preBody))
	}

	// Kill the leader
	leaderNode := h.NodeNumberForPort(leader)
	h.KillNode(t, leaderNode, "TERM")
	time.Sleep(8 * time.Second)

	// Wait for a new leader
	newLeader := h.WaitForLeader(t, 15, 2*time.Second)

	// Get a fresh token from the new leader
	freshToken := h.GetNTWardenToken(t, newLeader)

	// Verify gateway on the new leader
	leaderStatus, leaderBody := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", newLeader, freshToken)
	if leaderStatus != 200 {
		t.Fatalf("post-failover leader request: expected 200, got %d: %s", leaderStatus, string(leaderBody))
	}

	// Restore cluster
	h.RestartNode(t, leaderNode)
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestTransparentModeTokenReuse verifies concurrent transparent requests all succeed (T-075).
func TestTransparentModeTokenReuse(t *testing.T) {
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

// TestTransparentModeWrongRole verifies transparent gateway rejects a nonexistent role (T-077).
func TestTransparentModeWrongRole(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "nonexistent-role", leader, jwt)
	if status == 200 {
		t.Fatalf("expected non-200 for nonexistent role, got 200")
	}
}

// TestGatewayResponseContentType verifies gateway responses include application/json content type (T-078).
func TestGatewayResponseContentType(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	reqURL := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(leader))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected Content-Type to contain application/json, got %q", ct)
	}
}

// TestBothTransparentAndNonTransparentSameSecret verifies both gateway modes access the same secret (T-079).
func TestBothTransparentAndNonTransparentSameSecret(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)
	token := h.GetNTWardenToken(t, leader)

	transparentStatus, transparentBody := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
	if transparentStatus != 200 {
		t.Fatalf("transparent: expected 200, got %d: %s", transparentStatus, string(transparentBody))
	}

	ntStatus, ntBody := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if ntStatus != 200 {
		t.Fatalf("non-transparent: expected 200, got %d: %s", ntStatus, string(ntBody))
	}
}

// TestGatewayWithRotationEnabledSource verifies the gateway works with a rotation-enabled credential source (T-080).
func TestGatewayWithRotationEnabledSource(t *testing.T) {
	leader := h.GetLeaderPort(t)
	token := h.GetNTWardenToken(t, leader)

	status, body := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", leader, token)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}
}
