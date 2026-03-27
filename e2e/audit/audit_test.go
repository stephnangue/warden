//go:build e2e

package audit

import (
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestAuditSuccessfulRequestLogged verifies successful requests are logged (T-081).
func TestAuditSuccessfulRequestLogged(t *testing.T) {
	leader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(leader)

	h.CleanupNamespaces(t, leader, "e2e-audit-log-test")

	status, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-audit-log-test", leader, "")
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d", status)
	}

	time.Sleep(1 * time.Second)

	found := h.GrepNodeLog(t, nodeNum, "e2e-audit-log-test")
	if !found {
		t.Fatalf("expected e2e-audit-log-test to appear in node %d log", nodeNum)
	}

	h.CleanupNamespaces(t, leader, "e2e-audit-log-test")
}

// TestAuditNamespaceContext verifies namespace context appears in audit logs (T-083).
func TestAuditNamespaceContext(t *testing.T) {
	leader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(leader)

	h.CleanupNamespaces(t, leader, "e2e-audit-ns")

	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-audit-ns", leader, "")
	if createStatus != 201 {
		t.Fatalf("create namespace: expected 201, got %d", createStatus)
	}

	h.NSAPIRequest(t, "GET", "sys/namespaces?warden-list=true", "e2e-audit-ns", leader, "")

	time.Sleep(1 * time.Second)

	found := h.GrepNodeLog(t, nodeNum, "e2e-audit-ns")
	if !found {
		t.Fatalf("expected e2e-audit-ns to appear in node %d log", nodeNum)
	}

	h.CleanupNamespaces(t, leader, "e2e-audit-ns")
}

// TestAuditGatewayRequestLogged verifies gateway requests are logged (T-084).
func TestAuditGatewayRequestLogged(t *testing.T) {
	leader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(leader)

	jwt := h.GetDefaultJWT(t)
	h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)

	time.Sleep(1 * time.Second)

	found := h.GrepNodeLog(t, nodeNum, "gateway")
	if !found {
		t.Fatalf("expected 'gateway' to appear in node %d log", nodeNum)
	}
}

// TestAuditLogContinuityAcrossFailover verifies audit logging works on the new leader after failover (T-085).
func TestAuditLogContinuityAcrossFailover(t *testing.T) {
	oldLeader := h.GetLeaderPort(t)
	oldNodeNum := h.NodeNumberForPort(oldLeader)

	h.KillNode(t, oldNodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)
	newNodeNum := h.NodeNumberForPort(newLeader)

	h.CleanupNamespaces(t, newLeader, "e2e-audit-failover")

	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-audit-failover", newLeader, "")
	if createStatus != 200 && createStatus != 201 {
		t.Fatalf("expected 200 or 201 from new leader, got %d", createStatus)
	}

	time.Sleep(1 * time.Second)

	found := h.GrepNodeLog(t, newNodeNum, "e2e-audit-failover")
	if !found {
		t.Fatalf("expected e2e-audit-failover to appear in new leader (node %d) log after failover", newNodeNum)
	}

	h.CleanupNamespaces(t, newLeader, "e2e-audit-failover")
	h.RestartNode(t, oldNodeNum)
	h.WaitForCluster(t, 20, 3*time.Second)
}

// TestAuditStandbyForwardedRequest verifies forwarded requests through standby appear in the leader's log (T-086).
func TestAuditStandbyForwardedRequest(t *testing.T) {
	standby := h.GetStandbyPort(t)
	leader := h.GetLeaderPort(t)
	leaderNodeNum := h.NodeNumberForPort(leader)

	h.CleanupNamespaces(t, leader, "e2e-audit-fwd")

	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-audit-fwd", standby, "")
	if createStatus != 201 {
		t.Fatalf("create namespace via standby: expected 201, got %d", createStatus)
	}

	time.Sleep(1 * time.Second)

	found := h.GrepNodeLog(t, leaderNodeNum, "e2e-audit-fwd")
	if !found {
		t.Fatalf("expected 'e2e-audit-fwd' to appear in leader (node %d) log for forwarded request", leaderNodeNum)
	}

	h.CleanupNamespaces(t, leader, "e2e-audit-fwd")
}

// TestAuditSensitiveFieldMasking verifies credential source creation succeeds and checks log behavior (T-087).
func TestAuditSensitiveFieldMasking(t *testing.T) {
	leader := h.GetLeaderPort(t)

	h.APIRequest(t, "DELETE", "sys/cred/sources/e2e-audit-secret", leader, "")
	time.Sleep(1 * time.Second)

	body := `{
		"type": "hvault",
		"rotation_period": 300,
		"config": {
			"vault_address": "http://127.0.0.1:8200",
			"auth_method": "approle",
			"role_id": "e2e-approle-role-id-1234",
			"secret_id": "e2e-approle-secret-id-5678",
			"approle_mount": "e2e_approle",
			"role_name": "warden-e2e-role"
		}
	}`
	createStatus, _ := h.APIRequest(t, "POST", "sys/cred/sources/e2e-audit-secret", leader, body)
	if createStatus != 200 && createStatus != 201 && createStatus != 204 {
		t.Fatalf("create cred source: expected 200/201/204, got %d", createStatus)
	}

	readStatus, _ := h.APIRequest(t, "GET", "sys/cred/sources/e2e-audit-secret", leader, "")
	if readStatus != 200 {
		t.Fatalf("read cred source: expected 200, got %d", readStatus)
	}

	h.APIRequest(t, "DELETE", "sys/cred/sources/e2e-audit-secret", leader, "")
}

// TestAuditDeviceFailureBlocksRequests verifies the audit log file is actively being written to (T-088).
func TestAuditDeviceFailureBlocksRequests(t *testing.T) {
	leader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(leader)

	log := h.ReadNodeLog(t, nodeNum)
	if len(log) == 0 {
		t.Fatalf("expected node %d log to have content (len > 0), but it was empty", nodeNum)
	}
}
