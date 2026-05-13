//go:build e2e

// Package skill holds end-to-end tests for the /v1/sys/skills API.
package skill

import (
	"encoding/json"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// listResp matches the shape returned by GET /v1/sys/skills.
type listResp struct {
	Data struct {
		Skills []map[string]interface{} `json:"skills"`
	} `json:"data"`
}

// readResp matches the shape returned by GET /v1/sys/skills/<name>.
type readResp struct {
	Data map[string]interface{} `json:"data"`
}

func listSkills(t *testing.T, port int) []map[string]interface{} {
	t.Helper()
	status, body := h.APIRequest(t, "GET", "sys/skills?warden-list=true", port, "")
	if status != 200 {
		t.Fatalf("list skills: status %d, body %s", status, string(body))
	}
	var out listResp
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal list: %v\nbody: %s", err, string(body))
	}
	return out.Data.Skills
}

func skillNames(skills []map[string]interface{}) map[string]bool {
	names := make(map[string]bool, len(skills))
	for _, s := range skills {
		if n, ok := s["name"].(string); ok {
			names[n] = true
		}
	}
	return names
}

// TestSkill_FoundationSkillsArePresent verifies the discovery, foundation,
// and troubleshooting skills are seeded at first unseal and visible via the
// list endpoint.
func TestSkill_FoundationSkillsArePresent(t *testing.T) {
	port := h.GetLeaderPort(t)
	names := skillNames(listSkills(t, port))

	for _, want := range []string{"discovery", "foundation", "troubleshooting"} {
		if !names[want] {
			t.Errorf("foundation skill %q missing from /v1/sys/skills (got %v)", want, names)
		}
	}
}

// TestSkill_ProviderSkillSeededOnMount verifies that mounting a provider
// type seeds the type's skill into the global catalog. The e2e setup
// mounts a vault provider as part of step 9, so by the time tests run,
// the "vault" skill must already be present.
func TestSkill_ProviderSkillSeededOnMount(t *testing.T) {
	port := h.GetLeaderPort(t)
	names := skillNames(listSkills(t, port))

	if !names["vault"] {
		t.Fatalf("provider skill \"vault\" missing — seed-on-mount did not fire (got %v)", names)
	}

	// Confirm the record has the right provenance.
	status, body := h.APIRequest(t, "GET", "sys/skills/vault", port, "")
	if status != 200 {
		t.Fatalf("read vault skill: status %d, body %s", status, string(body))
	}
	var rd readResp
	if err := json.Unmarshal(body, &rd); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rd.Data["origin"] != "seed" {
		t.Errorf("vault origin = %v, want \"seed\"", rd.Data["origin"])
	}
	if rd.Data["provider"] != "vault" {
		t.Errorf("vault provider field = %v, want \"vault\"", rd.Data["provider"])
	}
	if rd.Data["category"] != "provider-guide" {
		t.Errorf("vault category = %v, want \"provider-guide\"", rd.Data["category"])
	}
}

// TestSkill_ReadFoundationSkillReturnsBody verifies that a known foundation
// skill comes back with its full markdown body via the read endpoint.
func TestSkill_ReadFoundationSkillReturnsBody(t *testing.T) {
	port := h.GetLeaderPort(t)
	status, body := h.APIRequest(t, "GET", "sys/skills/discovery", port, "")
	if status != 200 {
		t.Fatalf("read discovery: status %d, body %s", status, string(body))
	}
	var out readResp
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, string(body))
	}
	bodyStr, _ := out.Data["body"].(string)
	if !strings.Contains(bodyStr, "Discovering what you can do") {
		t.Errorf("discovery body does not contain expected heading; got %q", bodyStr)
	}
	if out.Data["origin"] != "seed" {
		t.Errorf("origin = %v, want \"seed\"", out.Data["origin"])
	}
}

// TestSkill_ListOmitsBody verifies that the list endpoint returns short-form
// records (no body) so the catalog stays cheap to scan.
func TestSkill_ListOmitsBody(t *testing.T) {
	port := h.GetLeaderPort(t)
	skills := listSkills(t, port)
	if len(skills) == 0 {
		t.Fatal("expected at least one skill in the catalog")
	}
	for _, s := range skills {
		if _, hasBody := s["body"]; hasBody {
			t.Errorf("list response for %v includes body field (should be omitted)", s["name"])
		}
	}
}

// TestSkillCRUD_RoundTrip exercises create/read/update/delete for an
// operator-owned skill.
func TestSkillCRUD_RoundTrip(t *testing.T) {
	port := h.GetLeaderPort(t)
	const name = "e2e-runbook"

	// Belt-and-braces cleanup in case a previous run left the skill behind.
	h.APIRequest(t, "DELETE", "sys/skills/"+name, port, "")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/skills/"+name, port, "")
	})

	createPayload := mustJSON(t, map[string]interface{}{
		"name":        name,
		"description": "operator-owned runbook",
		"category":    "custom",
		"body":        "# runbook\nstep 1\n",
	})
	status, body := h.APIRequest(t, "POST", "sys/skills/"+name, port, createPayload)
	if status != 201 {
		t.Fatalf("create: expected 201, got %d, body %s", status, string(body))
	}

	status, body = h.APIRequest(t, "GET", "sys/skills/"+name, port, "")
	if status != 200 {
		t.Fatalf("read: expected 200, got %d, body %s", status, string(body))
	}
	var rd readResp
	if err := json.Unmarshal(body, &rd); err != nil {
		t.Fatalf("unmarshal read: %v", err)
	}
	if rd.Data["description"] != "operator-owned runbook" {
		t.Errorf("description = %v", rd.Data["description"])
	}
	if rd.Data["origin"] != "user" {
		t.Errorf("origin = %v, want \"user\"", rd.Data["origin"])
	}

	updatePayload := mustJSON(t, map[string]interface{}{
		"description": "patched",
	})
	status, body = h.APIRequest(t, "PUT", "sys/skills/"+name, port, updatePayload)
	if status != 200 {
		t.Fatalf("update: expected 200, got %d, body %s", status, string(body))
	}
	if err := json.Unmarshal(body, &rd); err != nil {
		t.Fatalf("unmarshal update: %v", err)
	}
	if rd.Data["description"] != "patched" {
		t.Errorf("after update, description = %v", rd.Data["description"])
	}
	if v, _ := rd.Data["version"].(float64); v != 2 {
		t.Errorf("version = %v, want 2", rd.Data["version"])
	}

	status, _ = h.APIRequest(t, "DELETE", "sys/skills/"+name, port, "")
	if status != 200 {
		t.Fatalf("delete: expected 200, got %d", status)
	}

	status, _ = h.APIRequest(t, "GET", "sys/skills/"+name, port, "")
	if status != 404 {
		t.Errorf("read after delete: expected 404, got %d", status)
	}
}

// TestSkillCreate_DuplicateConflicts verifies a second create with the
// same name returns 409.
func TestSkillCreate_DuplicateConflicts(t *testing.T) {
	port := h.GetLeaderPort(t)
	const name = "e2e-dup"

	h.APIRequest(t, "DELETE", "sys/skills/"+name, port, "")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/skills/"+name, port, "")
	})

	payload := mustJSON(t, map[string]interface{}{
		"name":        name,
		"description": "first",
		"category":    "custom",
		"body":        "# x\n",
	})
	status, _ := h.APIRequest(t, "POST", "sys/skills/"+name, port, payload)
	if status != 201 {
		t.Fatalf("first create: expected 201, got %d", status)
	}

	status, _ = h.APIRequest(t, "POST", "sys/skills/"+name, port, payload)
	if status != 409 {
		t.Errorf("duplicate create: expected 409, got %d", status)
	}
}

// TestSkillCreate_ValidationRejects verifies that invalid payloads produce 400.
func TestSkillCreate_ValidationRejects(t *testing.T) {
	port := h.GetLeaderPort(t)

	cases := []struct {
		name    string
		path    string
		payload map[string]interface{}
	}{
		{
			name: "bad category",
			path: "e2e-bad-category",
			payload: map[string]interface{}{
				"description": "x",
				"category":    "not-a-real-category",
				"body":        "# x\n",
			},
		},
		{
			name: "empty body",
			path: "e2e-empty-body",
			payload: map[string]interface{}{
				"description": "x",
				"category":    "custom",
				"body":        "",
			},
		},
		{
			name: "provider-guide without provider",
			path: "e2e-needs-provider",
			payload: map[string]interface{}{
				"description": "x",
				"category":    "provider-guide",
				"body":        "# x\n",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.APIRequest(t, "DELETE", "sys/skills/"+tc.path, port, "")
			t.Cleanup(func() {
				h.APIRequest(t, "DELETE", "sys/skills/"+tc.path, port, "")
			})
			tc.payload["name"] = tc.path
			body := mustJSON(t, tc.payload)
			status, _ := h.APIRequest(t, "POST", "sys/skills/"+tc.path, port, body)
			if status != 400 {
				t.Errorf("expected 400, got %d", status)
			}
		})
	}
}

// TestSkill_GlobalReadFromSubNamespace verifies the read+list endpoints
// return the same global catalog regardless of namespace scope.
func TestSkill_GlobalReadFromSubNamespace(t *testing.T) {
	port := h.GetLeaderPort(t)
	const ns = "e2e-skill-read"

	h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/"+ns, port, "")
	if createStatus != 201 && createStatus != 200 {
		t.Fatalf("create namespace: expected 201/200, got %d", createStatus)
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	})

	// LIST under the sub-namespace token must succeed and include foundation skills.
	status, body := h.NSAPIRequest(t, "GET", "sys/skills?warden-list=true", ns, port, "")
	if status != 200 {
		t.Fatalf("list under sub-namespace: expected 200, got %d, body %s", status, string(body))
	}
	var lr listResp
	if err := json.Unmarshal(body, &lr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	names := skillNames(lr.Data.Skills)
	for _, want := range []string{"discovery", "foundation", "troubleshooting"} {
		if !names[want] {
			t.Errorf("foundation skill %q missing from sub-namespace list", want)
		}
	}

	// READ under the sub-namespace token must succeed.
	status, _ = h.NSAPIRequest(t, "GET", "sys/skills/discovery", ns, port, "")
	if status != 200 {
		t.Errorf("read discovery from sub-namespace: expected 200, got %d", status)
	}
}

// TestSkill_WriteFromSubNamespaceRejected verifies that mutations from a
// non-root namespace are rejected with 403.
func TestSkill_WriteFromSubNamespaceRejected(t *testing.T) {
	port := h.GetLeaderPort(t)
	const ns = "e2e-skill-write-denied"
	const name = "e2e-should-not-create"

	h.APIRequest(t, "DELETE", "sys/skills/"+name, port, "")
	h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/"+ns, port, "")
	if createStatus != 201 && createStatus != 200 {
		t.Fatalf("create namespace: expected 201/200, got %d", createStatus)
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/skills/"+name, port, "")
		h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	})

	payload := mustJSON(t, map[string]interface{}{
		"name":        name,
		"description": "should not land",
		"category":    "custom",
		"body":        "# x\n",
	})
	status, body := h.NSAPIRequest(t, "POST", "sys/skills/"+name, ns, port, payload)
	if status != 403 {
		t.Errorf("create from sub-namespace: expected 403, got %d, body %s", status, string(body))
	}

	// The global catalog must NOT contain the rejected name.
	for _, s := range listSkills(t, port) {
		if s["name"] == name {
			t.Errorf("rejected skill %q appeared in catalog: %v", name, s)
		}
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
