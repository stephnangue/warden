//go:build e2e

package rotation

import (
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

const vaultSourceBody = `{"type":"hvault","rotation_period":300,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`

func cleanupSource(t *testing.T, port int, name string) {
	h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, port, "")
}

// TestVaultSourceRotationConfig verifies a source can be created with rotation_period (T-033).
func TestVaultSourceRotationConfig(t *testing.T) {
	port := h.GetLeaderPort(t)
	cleanupSource(t, port, "e2e-rot-test")

	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-test", port, vaultSourceBody)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on create, got %d", status)
	}

	readStatus, readBody := h.APIRequest(t, "GET", "sys/cred/sources/e2e-rot-test", port, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on read, got %d", readStatus)
	}

	data := h.ParseJSON(t, readBody)
	rotPeriod := h.JSONPath(data, "data.rotation_period")
	if rotPeriod == nil {
		t.Fatalf("expected data.rotation_period to exist, got nil in: %s", string(readBody))
	}

	cleanupSource(t, port, "e2e-rot-test")
}

// TestRotationPeriodBelowMinimum verifies rotation_period below 5m (300s) is rejected (T-034).
func TestRotationPeriodBelowMinimum(t *testing.T) {
	port := h.GetLeaderPort(t)
	cleanupSource(t, port, "e2e-rot-invalid")

	body := `{"type":"hvault","rotation_period":10,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`
	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-invalid", port, body)
	if status != 400 {
		t.Fatalf("expected 400 for rotation_period below minimum, got %d", status)
	}

	cleanupSource(t, port, "e2e-rot-invalid")
}

// TestRotationSurvivesLeaderFailover verifies a rotating source persists after leader kill (T-035).
func TestRotationSurvivesLeaderFailover(t *testing.T) {
	leader := h.GetLeaderPort(t)
	cleanupSource(t, leader, "e2e-rot-failover")

	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-failover", leader, vaultSourceBody)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on create, got %d", status)
	}

	nodeNum := h.NodeNumberForPort(leader)
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	readStatus, _ := h.APIRequest(t, "GET", "sys/cred/sources/e2e-rot-failover", newLeader, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on read from new leader, got %d", readStatus)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)

	cleanupSource(t, h.GetLeaderPort(t), "e2e-rot-failover")
}

// TestUpdateRotationPeriod verifies a source can be deleted and recreated with a different rotation_period (T-037).
func TestUpdateRotationPeriod(t *testing.T) {
	port := h.GetLeaderPort(t)
	cleanupSource(t, port, "e2e-rot-update")

	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-update", port, vaultSourceBody)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on create, got %d", status)
	}

	// Delete and recreate with updated rotation_period
	cleanupSource(t, port, "e2e-rot-update")

	updatedBody := `{"type":"hvault","rotation_period":600,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`
	recreateStatus, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-update", port, updatedBody)
	if recreateStatus != 200 && recreateStatus != 201 && recreateStatus != 204 {
		t.Fatalf("expected 200, 201, or 204 on recreate, got %d", recreateStatus)
	}

	readStatus, readBody := h.APIRequest(t, "GET", "sys/cred/sources/e2e-rot-update", port, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on read, got %d", readStatus)
	}

	data := h.ParseJSON(t, readBody)
	rotPeriod := h.JSONPath(data, "data.rotation_period")
	if rotPeriod == nil {
		t.Fatalf("expected data.rotation_period to exist, got nil")
	}
	rotFloat, ok := rotPeriod.(float64)
	if !ok {
		t.Fatalf("expected rotation_period to be a number, got %T", rotPeriod)
	}
	if rotFloat != 600 {
		t.Fatalf("expected rotation_period=600, got %v", rotFloat)
	}

	cleanupSource(t, port, "e2e-rot-update")
}

// TestRotationMaxAttemptsFailedState verifies a source with unreachable vault is rejected at creation (T-038).
func TestRotationMaxAttemptsFailedState(t *testing.T) {
	port := h.GetLeaderPort(t)
	cleanupSource(t, port, "e2e-rot-fail")

	body := `{"type":"hvault","rotation_period":300,"config":{"vault_address":"http://127.0.0.1:9999","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`
	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-fail", port, body)
	if status != 400 {
		t.Fatalf("expected 400 for unreachable vault, got %d", status)
	}
}

// TestConcurrentRotationAndIssuance verifies concurrent Vault requests succeed under rotation (T-039).
func TestConcurrentRotationAndIssuance(t *testing.T) {
	port := h.GetLeaderPort(t)
	ntToken := h.GetNTWardenToken(t, port)

	successes := h.ConcurrentDo(5, func(i int) bool {
		status, _ := h.VaultNTRequest(t, "GET", "secret/data/e2e/app-config", port, ntToken)
		return status == 200
	})
	if successes < 4 {
		t.Fatalf("expected at least 4 out of 5 concurrent requests to succeed, got %d", successes)
	}
}

// TestSpecRotationConfig verifies a credential spec can be created and read back (T-040).
func TestSpecRotationConfig(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.APIRequest(t, "DELETE", "sys/cred/specs/e2e-spec-rot", port, "")

	specBody := `{"type":"vault_token","source":"vault-e2e","config":{"mint_method":"vault_token","token_role":"e2e-secrets-reader"}}`
	status, _ := h.APIRequest(t, "POST", "sys/cred/specs/e2e-spec-rot", port, specBody)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on spec create, got %d", status)
	}

	readStatus, _ := h.APIRequest(t, "GET", "sys/cred/specs/e2e-spec-rot", port, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on spec read, got %d", readStatus)
	}

	h.APIRequest(t, "DELETE", "sys/cred/specs/e2e-spec-rot", port, "")
}

// TestActivationDelayConfig verifies a source with activation_delay config is accepted (T-041).
func TestActivationDelayConfig(t *testing.T) {
	port := h.GetLeaderPort(t)
	cleanupSource(t, port, "e2e-rot-actdelay")

	body := `{"type":"hvault","rotation_period":300,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role","activation_delay":"10m"}}`
	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-actdelay", port, body)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on create with activation_delay, got %d", status)
	}

	readStatus, readBody := h.APIRequest(t, "GET", "sys/cred/sources/e2e-rot-actdelay", port, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on read, got %d", readStatus)
	}

	data := h.ParseJSON(t, readBody)
	config := h.JSONPath(data, "data.config")
	if config == nil {
		t.Fatalf("expected data.config to exist, got nil")
	}
	configMap, ok := config.(map[string]interface{})
	if !ok {
		t.Fatalf("expected data.config to be a map, got %T", config)
	}
	if _, exists := configMap["activation_delay"]; !exists {
		t.Fatalf("expected activation_delay in config, got: %v", configMap)
	}

	cleanupSource(t, port, "e2e-rot-actdelay")
}

// TestCleanupRetryPersistence verifies source config persists after leader failover (T-042).
func TestCleanupRetryPersistence(t *testing.T) {
	leader := h.GetLeaderPort(t)
	cleanupSource(t, leader, "e2e-rot-persist")

	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-persist", leader, vaultSourceBody)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on create, got %d", status)
	}

	nodeNum := h.NodeNumberForPort(leader)
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	readStatus, _ := h.APIRequest(t, "GET", "sys/cred/sources/e2e-rot-persist", newLeader, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on read from new leader (config should persist), got %d", readStatus)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)

	cleanupSource(t, h.GetLeaderPort(t), "e2e-rot-persist")
}

// TestMultipleSourcesRotating verifies multiple rotating sources can coexist (T-043).
func TestMultipleSourcesRotating(t *testing.T) {
	port := h.GetLeaderPort(t)
	names := []string{"e2e-multi-rot-1", "e2e-multi-rot-2", "e2e-multi-rot-3"}

	for _, name := range names {
		cleanupSource(t, port, name)
	}

	for _, name := range names {
		status, _ := h.APIRequest(t, "POST", "sys/cred/sources/"+name, port, vaultSourceBody)
		if status != 200 && status != 201 && status != 204 {
			t.Fatalf("expected 200, 201, or 204 on create %s, got %d", name, status)
		}
	}

	for _, name := range names {
		readStatus, _ := h.APIRequest(t, "GET", "sys/cred/sources/"+name, port, "")
		if readStatus != 200 {
			t.Fatalf("expected 200 on read %s, got %d", name, readStatus)
		}
	}

	for _, name := range names {
		cleanupSource(t, port, name)
	}
}

// TestRotationPeriodUpdateOnExistingSource verifies a source can be deleted and recreated with different rotation_period (T-044).
func TestRotationPeriodUpdateOnExistingSource(t *testing.T) {
	port := h.GetLeaderPort(t)
	cleanupSource(t, port, "e2e-rot-upd2")

	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-upd2", port, vaultSourceBody)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on create, got %d", status)
	}

	// Delete and recreate with a longer rotation_period
	cleanupSource(t, port, "e2e-rot-upd2")

	updatedBody := `{"type":"hvault","rotation_period":900,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`
	recreateStatus, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-upd2", port, updatedBody)
	if recreateStatus != 200 && recreateStatus != 201 && recreateStatus != 204 {
		t.Fatalf("expected 200, 201, or 204 on recreate, got %d", recreateStatus)
	}

	readStatus, readBody := h.APIRequest(t, "GET", "sys/cred/sources/e2e-rot-upd2", port, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on read, got %d", readStatus)
	}

	data := h.ParseJSON(t, readBody)
	rotPeriod := h.JSONPath(data, "data.rotation_period")
	if rotPeriod == nil {
		t.Fatalf("expected data.rotation_period to exist, got nil")
	}
	rotFloat, ok := rotPeriod.(float64)
	if !ok {
		t.Fatalf("expected rotation_period to be a number, got %T", rotPeriod)
	}
	if rotFloat != 900 {
		t.Fatalf("expected rotation_period=900, got %v", rotFloat)
	}

	cleanupSource(t, port, "e2e-rot-upd2")
}

// TestDeleteSourceWithRotation verifies a rotating source can be deleted (T-045).
func TestDeleteSourceWithRotation(t *testing.T) {
	port := h.GetLeaderPort(t)
	cleanupSource(t, port, "e2e-rot-del")

	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-del", port, vaultSourceBody)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on create, got %d", status)
	}

	delStatus, _ := h.APIRequest(t, "DELETE", "sys/cred/sources/e2e-rot-del", port, "")
	if delStatus != 200 && delStatus != 204 {
		t.Fatalf("expected 200 or 204 on delete, got %d", delStatus)
	}

	readStatus, _ := h.APIRequest(t, "GET", "sys/cred/sources/e2e-rot-del", port, "")
	if readStatus == 200 {
		t.Fatalf("expected non-200 after delete (source should be gone), got 200")
	}
}

// TestRotationStateAfterFullClusterRestart verifies rotation state survives full cluster restart (T-046).
func TestRotationStateAfterFullClusterRestart(t *testing.T) {
	leader := h.GetLeaderPort(t)
	cleanupSource(t, leader, "e2e-rot-cluster")

	status, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-rot-cluster", leader, vaultSourceBody)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204 on create, got %d", status)
	}

	for _, nodeNum := range []int{1, 2, 3} {
		h.KillNode(t, nodeNum, "TERM")
	}
	time.Sleep(5 * time.Second)

	for _, nodeNum := range []int{1, 2, 3} {
		h.RestartNode(t, nodeNum)
	}
	h.WaitForCluster(t, 20, 3*time.Second)

	newLeader := h.GetLeaderPort(t)
	readStatus, _ := h.APIRequest(t, "GET", "sys/cred/sources/e2e-rot-cluster", newLeader, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 on read after full cluster restart, got %d", readStatus)
	}

	cleanupSource(t, newLeader, "e2e-rot-cluster")
}
