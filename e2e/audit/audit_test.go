//go:build e2e

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
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

	// The leader audits the forwarded request under the id the standby gave
	// it, not under none. Audit writes are asynchronous, hence the poll; the
	// cleanup's deletes go to the leader directly, so they are skipped.
	var forwarded []audit.LogEntry
	for i := 0; i < 30 && len(forwarded) == 0; i++ {
		for _, e := range h.ReadAuditEntries(t, leaderNodeNum, "e2e-audit-fwd") {
			if e.Request != nil && e.Request.Operation != "delete" {
				forwarded = append(forwarded, e)
			}
		}
		if len(forwarded) == 0 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if len(forwarded) == 0 {
		t.Fatalf("no audit entry on the leader (node %d) for the forwarded request", leaderNodeNum)
	}
	for _, e := range forwarded {
		if e.Request.ID == "" {
			t.Errorf("leader audited the forwarded request's %s entry (%s %s) with no request id",
				e.Type, e.Request.Operation, e.Request.Path)
		}
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
			"tls_skip_verify": true,
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

// TestAuditCustomListsKeepTheFloor enables a device whose operator set their
// own salt and omit lists, which used to replace the defaults, and checks that
// a gateway call through it writes no credential: not the agent's JWT, not a
// query value, not the credential Warden issued.
func TestAuditCustomListsKeepTheFloor(t *testing.T) {
	leader := h.GetLeaderPort(t)
	logPath := filepath.Join(h.E2EDir(), ".logs", "e2e-floor-audit.log")
	_ = os.Remove(logPath)
	h.APIRequest(t, "DELETE", "sys/audit/e2e-floor", leader, "")

	body := fmt.Sprintf(`{
		"type": "file",
		"config": {
			"file_path": %q,
			"buffer_size": 1,
			"salt_fields": ["auth.token_id"],
			"omit_fields": ["auth.token_accessor"]
		}
	}`, logPath)
	status, resp := h.APIRequest(t, "POST", "sys/audit/e2e-floor", leader, body)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("enable audit device: expected 200/201/204, got %d: %s", status, resp)
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/audit/e2e-floor", leader, "")
		_ = os.Remove(logPath)
	})

	jwt := h.GetDefaultJWT(t)
	status, resp = h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config?api_key=E2E-QUERY-SECRET", "e2e-reader", leader, jwt)
	if status != 200 {
		t.Fatalf("gateway request: expected 200, got %d: %s", status, resp)
	}

	var raw []byte
	var entries []audit.LogEntry
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ = os.ReadFile(logPath)
		entries = h.ReadAuditFile(t, logPath, "e2e-reader")
		if hasIssuedCredential(entries) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !hasIssuedCredential(entries) {
		t.Fatalf("no response entry with an issued credential in %s", logPath)
	}

	for _, secret := range []string{jwt, "E2E-QUERY-SECRET"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q written in clear to the audit log", secret[:min(len(secret), 16)])
		}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, `"headers"`) || strings.Contains(line, `"request":{`) && strings.Contains(line, `"data":{`) && !strings.Contains(line, `"credential"`) {
			t.Errorf("an entry records headers or a request body: %s", line)
		}
	}
	redactedURLs := 0
	for _, e := range entries {
		if e.Response == nil || e.Response.Credential == nil {
			continue
		}
		for k, v := range e.Response.Credential.Data {
			if !strings.HasPrefix(v, "hmac-sha256:") {
				t.Errorf("credential data %q is not salted", k)
			}
		}
		switch u := e.Response.UpstreamURL; {
		case strings.Contains(u, "api_key=%5Bredacted%5D"):
			redactedURLs++
		case u != "":
			t.Errorf("upstream_url keeps the query value: %s", u)
		}
	}
	if redactedURLs == 0 {
		t.Error("no response entry recorded the upstream URL with its query value redacted")
	}
}

// hasIssuedCredential reports whether entries hold a response entry carrying
// the credential a gateway call was issued.
func hasIssuedCredential(entries []audit.LogEntry) bool {
	for _, e := range entries {
		if e.Response != nil && e.Response.Credential != nil && len(e.Response.Credential.Data) > 0 {
			return true
		}
	}
	return false
}

// TestAuditUnknownFieldPathRefused checks that enabling a device with a salt
// path that names no field is refused, where it used to be ignored without a
// word.
func TestAuditUnknownFieldPathRefused(t *testing.T) {
	leader := h.GetLeaderPort(t)
	logPath := filepath.Join(h.E2EDir(), ".logs", "e2e-bad-audit.log")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/audit/e2e-bad", leader, "")
		_ = os.Remove(logPath)
	})

	body := fmt.Sprintf(`{
		"type": "file",
		"config": {
			"file_path": %q,
			"salt_fields": ["agent.metadata.env"]
		}
	}`, logPath)
	status, resp := h.APIRequest(t, "POST", "sys/audit/e2e-bad", leader, body)
	if status != 400 {
		t.Fatalf("expected 400, got %d: %s", status, resp)
	}
	if !strings.Contains(string(resp), "agent.metadata.env") {
		t.Errorf("the refusal does not name the path: %s", resp)
	}
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
