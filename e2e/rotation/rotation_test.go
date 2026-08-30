//go:build e2e

package rotation

import (
	"fmt"
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

// TestRotationPeriodBelowMinimum verifies a rotation_period below the configured
// floor is rejected (T-034).
//
// The floor is min_cred_source_rotation_period in the node config, and this
// cluster runs a deliberately low one so other suites can watch a rotation
// complete rather than infer it. The period below is therefore small; keep it
// under whatever that config says, or this stops testing a refusal.
func TestRotationPeriodBelowMinimum(t *testing.T) {
	port := h.GetLeaderPort(t)
	cleanupSource(t, port, "e2e-rot-invalid")

	body := `{"type":"hvault","rotation_period":5,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`
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
	jwt := h.GetDefaultJWT(t)

	successes := h.ConcurrentDo(5, func(i int) bool {
		status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", port, jwt)
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

// TestRotationScheduleFollowsInPlaceUpdate drives the schedule, not just the
// stored config: a rotation period changed or cleared through the update API must
// reach the rotation manager.
//
// The two neighbouring rows named for updating a period both delete and recreate
// the source, because updating one in place was not possible — the update handler
// preserved whatever period the source was created with. Nothing therefore covered
// the manager's side of an update, which is where the schedule actually lives.
//
// next_rotation is the observable: the source read reports it only while an entry
// is registered, so its disappearance is the assertion that clearing the period
// unregistered the entry rather than leaving one firing on a period the source no
// longer carries.
func TestRotationScheduleFollowsInPlaceUpdate(t *testing.T) {
	port := h.GetLeaderPort(t)
	const name = "e2e-rot-inplace"
	cleanupSource(t, port, name)
	t.Cleanup(func() { cleanupSource(t, port, name) })

	// POST creates and refuses an existing name; PUT is the update verb. The two
	// neighbouring rows never needed the distinction, having only ever created.
	mustWrite := func(method, what, body string) {
		t.Helper()
		status, resp := h.APIRequest(t, method, "sys/cred/sources/"+name, port, body)
		if status != 200 && status != 201 && status != 204 {
			t.Fatalf("%s: status %d: %s", what, status, string(resp))
		}
	}

	// Returns the stored period and the scheduled next rotation, the latter empty
	// when the source is not enrolled.
	read := func(t *testing.T) (float64, string) {
		t.Helper()
		status, body := h.APIRequest(t, "GET", "sys/cred/sources/"+name, port, "")
		if status != 200 {
			t.Fatalf("read: status %d: %s", status, string(body))
		}
		data := h.ParseJSON(t, body)
		period, _ := h.JSONPath(data, "data.rotation_period").(float64)
		next, _ := h.JSONPath(data, "data.next_rotation").(string)
		return period, next
	}

	// A local source, not the hvault one the rest of this file uses: hvault is
	// required to carry a rotation_period, so clearing one is refused before it
	// could reach the manager. Enrolment does not depend on the type — any source
	// with a period is registered — so this covers the same lifecycle.
	const body = `{"type":"local","rotation_period":%d,"config":{"key":"value"}}`

	mustWrite("POST", "create", fmt.Sprintf(body, 300))
	period, firstNext := read(t)
	if period != 300 {
		t.Fatalf("rotation_period = %v, want 300 after create", period)
	}
	if firstNext == "" {
		t.Fatal("no next_rotation after create: the source was never enrolled")
	}

	// Change it in place. The config is untouched, so this is the case that used to
	// leave the manager on the period the source was created with.
	mustWrite("PUT", "update period", fmt.Sprintf(body, 600))

	period, secondNext := read(t)
	if period != 600 {
		t.Fatalf("rotation_period = %v, want 600 after update", period)
	}
	if secondNext == "" {
		t.Fatal("no next_rotation after updating the period: the entry was dropped")
	}
	// Rescheduled from now against a longer period, so the next action must move
	// later. Comparing the strings is enough: both are RFC3339 in UTC.
	if secondNext <= firstNext {
		t.Errorf("next_rotation did not move for a lengthened period: %s then %s", firstNext, secondNext)
	}

	// Clear it. The entry must go, not linger on the old schedule.
	mustWrite("PUT", "clear period", fmt.Sprintf(body, 0))

	period, clearedNext := read(t)
	if period != 0 {
		t.Fatalf("rotation_period = %v, want 0 after clearing", period)
	}
	if clearedNext != "" {
		t.Errorf("next_rotation still reported after clearing the period (%s): the entry is still enrolled", clearedNext)
	}
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
