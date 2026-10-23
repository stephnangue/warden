//go:build e2e

package ha

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Roles, groups and admissions across a failover. Role and group snapshots, the
// count of auth roles left in storage and the admission cache all live on the
// active node alone: a node that steps up rebuilds the first three from storage
// and admits a cached credential afresh. The kubernetes mount makes the second
// observable: its TokenReview stub counts every admission.

const (
	failoverK8sMount    = "auth/e2e-ha-k8s/"
	failoverLegacyMount = "auth/e2e-ha-legacy/"
	failoverProvider    = "e2e-ha-vault"
	failoverPolicy      = "e2e-ha-access"
	failoverRole        = "e2e-ha-reader"
	failoverGroup       = "e2e-ha-readers"
)

// waitForNewLeader waits until a node other than old is active.
func waitForNewLeader(t *testing.T, old int) int {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		for _, port := range h.NodePorts {
			if port == old {
				continue
			}
			if status, _ := h.TryRequest("GET", h.NodeURL(port)+"/v1/sys/health", nil, ""); status == 200 {
				return port
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no node other than :%d became active", old)
	return 0
}

func failoverRequest(t *testing.T, port int, token string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/%s/role/%s/gateway/v1/secret/data/e2e/app-config", h.NodeURL(port), failoverProvider, failoverRole)
	return h.DoRequest(t, "GET", u, map[string]string{"Authorization": "Bearer " + token}, "")
}

func failoverRules(serviceAccount string) []map[string][]string {
	return []map[string][]string{{"mount": {failoverK8sMount}, "service_account_name": {serviceAccount}}}
}

// TestFailover_RolesGroupsAndAdmissions steps the active node down and checks
// what the node that steps up rebuilds: the role and group snapshots (a cached
// workload is granted its role there, and a group edit there applies on the
// next request), the count of auth roles left in storage (seeded while the old
// node was active, so only a recount can find them), and the admission cache
// (the first request on the new node admits the credential again, once).
func TestFailover_RolesGroupsAndAdmissions(t *testing.T) {
	leader := h.GetLeaderPort(t)
	reviewer := h.StartTokenReviewer(t)

	h.EnableKubernetesAuth(t, leader, "", failoverK8sMount, reviewer, map[string]any{
		"bound_audiences": []string{h.HydraAudience},
	})
	h.APIRequest(t, "DELETE", "sys/providers/"+failoverProvider, leader, "")
	h.MustNS(t, leader, "", "POST", "sys/providers/"+failoverProvider, `{"type":"vault"}`)
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/providers/"+failoverProvider, h.GetLeaderPort(t), "") })
	h.MustNS(t, leader, "", "POST", failoverProvider+"/config", fmt.Sprintf(
		`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"timeout":"30s","auto_auth_path":%q}`, failoverK8sMount))
	h.MustNS(t, leader, "", "POST", "sys/policies/cbp/"+failoverPolicy, fmt.Sprintf(
		`{"policy":"path \"%s/role/+/gateway*\" {\n  capabilities = [\"read\"]\n}"}`, failoverProvider))
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/policies/cbp/"+failoverPolicy, h.GetLeaderPort(t), "") })
	h.WriteRoleInNS(t, leader, "", failoverRole, h.Role{Policies: []string{failoverPolicy}, CredSpec: "vault-token-reader"})
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/roles/"+failoverRole, h.GetLeaderPort(t), "") })
	h.WriteGroupInNS(t, leader, "", failoverGroup, h.Group{Roles: []string{failoverRole}, Rules: failoverRules("ha-agent")})

	// An auth mount holding an auth role an earlier release stored, written
	// while this node is active: it counted leftovers at its unseal, before
	// this one existed.
	legacySys := "sys/" + strings.TrimSuffix(failoverLegacyMount, "/")
	h.APIRequest(t, "DELETE", legacySys, leader, "")
	h.MustNS(t, leader, "", "POST", legacySys, `{"type":"jwt"}`)
	t.Cleanup(func() { h.APIRequest(t, "DELETE", legacySys, h.GetLeaderPort(t), "") })
	storage := h.OpenClusterStorage(t)
	storage.PutJSON(t, h.AuthMountStorage(storage.AuthMountUUID(t, failoverLegacyMount))+"role/old-reader",
		map[string]any{"name": "old-reader", "token_policies": []string{failoverPolicy}, "token_ttl": "1h"})
	const leftover = "auth/e2e-ha-legacy/: 1 auth roles are no longer used"
	leftoverWarned := func(port int) bool {
		status, body := h.APIRequest(t, "GET", "sys/auth?warden-list=true", port, "")
		if status != 200 {
			t.Fatalf("sys/auth list: status %d: %s", status, body)
		}
		return strings.Contains(string(body), leftover)
	}
	if leftoverWarned(leader) {
		t.Fatalf("the active node warns about an auth role written after its unseal; the recount below would prove nothing")
	}

	token := reviewer.Issue(t, h.ServiceAccount{
		Namespace: "ci", Name: "ha-agent", UID: "uid-ha-agent", Audiences: []string{h.HydraAudience},
	}, "https://kubernetes.e2e.example", true)

	for i := 0; i < 2; i++ {
		if status, body := failoverRequest(t, leader, token); status != 200 {
			t.Fatalf("request %d on the active node: status %d: %s", i+1, status, body)
		}
	}
	if got := reviewer.Reviews(); got != 1 {
		t.Fatalf("two requests on one node cost %d TokenReviews, want 1 (the second is served from the admission cache)", got)
	}

	oldNode := h.NodeNumberForPort(leader)
	offsets := map[int]int{}
	for n := 1; n <= 3; n++ {
		offsets[n] = h.NodeLogSize(t, n)
	}
	h.StepDown(t, leader)
	newLeader := waitForNewLeader(t, leader)
	t.Cleanup(func() { h.WaitForCluster(t, 30, 2*time.Second) })
	newNode := h.NodeNumberForPort(newLeader)
	t.Logf("active node moved from node %d to node %d", oldNode, newNode)

	// Through the old node, now a standby, and through the new one: both reach
	// the new active node, which admits the credential once.
	if status, body := failoverRequest(t, leader, token); status != 200 {
		t.Fatalf("first request after the failover, through the old node: status %d: %s", status, body)
	}
	if status, body := failoverRequest(t, newLeader, token); status != 200 {
		t.Fatalf("second request after the failover: status %d: %s", status, body)
	}
	if got := reviewer.Reviews(); got != 2 {
		t.Fatalf("after the failover the reviews count %d, want 2: the new active node admits the credential once", got)
	}

	// The group snapshot on the new node is live: an edit there refuses the
	// next request on the cached admission, and restoring it allows it again.
	h.WriteGroupInNS(t, newLeader, "", failoverGroup, h.Group{Roles: []string{failoverRole}, Rules: failoverRules("someone-else")})
	status, body := failoverRequest(t, newLeader, token)
	if status != http.StatusForbidden || !strings.Contains(h.ErrorText(body), "not assumable") {
		t.Errorf("after the group stopped naming the workload: status %d, want 403 not assumable: %s", status, body)
	}
	h.WriteGroupInNS(t, newLeader, "", failoverGroup, h.Group{Roles: []string{failoverRole}, Rules: failoverRules("ha-agent")})
	if status, body := failoverRequest(t, newLeader, token); status != 200 {
		t.Errorf("after the group named the workload again: status %d: %s", status, body)
	}
	if got := reviewer.Reviews(); got != 2 {
		t.Errorf("group edits on the new node cost TokenReviews: %d, want 2", got)
	}

	if !leftoverWarned(newLeader) {
		t.Errorf("the new active node does not warn about the auth role left in storage: want %q", leftover)
	}
	logged := false
	for _, line := range h.NodeLogSince(t, newNode, offsets[newNode]) {
		logged = logged || strings.Contains(line, leftover)
	}
	if !logged {
		t.Errorf("node %d did not log %q when it stepped up", newNode, leftover)
	}
}
