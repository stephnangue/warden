//go:build e2e

package skill

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// wardenCLI is a small wrapper that auto-supplies WARDEN_TOKEN so each
// test reads like a single CLI invocation.
func wardenCLI(t *testing.T, port int, args ...string) (string, error) {
	t.Helper()
	return h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, args...)
}

func TestCLI_SkillList_TableAndJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Table output should mention at least one foundation skill.
	tableOut, err := wardenCLI(t, port, "skill", "list", "-o", "table")
	if err != nil {
		t.Fatalf("skill list -o table failed: %v\noutput: %s", err, tableOut)
	}
	if !strings.Contains(tableOut, "discovery") {
		t.Errorf("expected 'discovery' in table output, got:\n%s", tableOut)
	}

	// JSON output must parse and include the same skill.
	jsonOut, err := wardenCLI(t, port, "skill", "list", "-o", "json")
	if err != nil {
		t.Fatalf("skill list -o json failed: %v\noutput: %s", err, jsonOut)
	}
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonOut), &items); err != nil {
		t.Fatalf("unmarshal JSON: %v\noutput: %s", err, jsonOut)
	}
	if len(items) == 0 {
		t.Fatal("expected at least one skill in JSON output")
	}
	found := false
	for _, item := range items {
		if item["name"] == "discovery" {
			found = true
			break
		}
	}
	if !found {
		t.Error("'discovery' missing from JSON list output")
	}
}

func TestCLI_SkillRead_RawAndStructured(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Structured JSON read must include the markdown body inline.
	jsonOut, err := wardenCLI(t, port, "skill", "read", "discovery", "-o", "json")
	if err != nil {
		t.Fatalf("skill read discovery -o json failed: %v\noutput: %s", err, jsonOut)
	}
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(jsonOut), &rec); err != nil {
		t.Fatalf("unmarshal JSON: %v\noutput: %s", err, jsonOut)
	}
	body, _ := rec["body"].(string)
	if !strings.Contains(body, "Discovering what you can do") {
		t.Errorf("JSON body missing expected heading; got %q", body)
	}

	// --raw must emit just the markdown.
	rawOut, err := wardenCLI(t, port, "skill", "read", "discovery", "--raw")
	if err != nil {
		t.Fatalf("skill read discovery --raw failed: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(rawOut), "# Discovering what you can do") {
		// Limit the snippet so a huge body doesn't dominate the failure log.
		snippet := rawOut
		if len(snippet) > 100 {
			snippet = snippet[:100]
		}
		t.Errorf("--raw output should start with the discovery heading; got first 100 chars: %q", snippet)
	}
	// --raw must NOT contain any JSON envelope markers.
	if strings.Contains(rawOut, `"data":`) || strings.HasPrefix(strings.TrimSpace(rawOut), "{") {
		t.Errorf("--raw output should not include JSON envelope; got:\n%s", rawOut)
	}
}

func TestCLI_SkillCreate_TypedFlags(t *testing.T) {
	port := h.GetLeaderPort(t)
	const name = "e2e-cli-runbook"

	// Cleanup any leftover state.
	wardenCLI(t, port, "skill", "delete", name, "--force")
	t.Cleanup(func() {
		wardenCLI(t, port, "skill", "delete", name, "--force")
	})

	bodyFile := filepath.Join(t.TempDir(), "body.md")
	if err := os.WriteFile(bodyFile, []byte("# runbook\nstep 1\n"), 0o600); err != nil {
		t.Fatalf("write body file: %v", err)
	}

	out, err := wardenCLI(t, port, "skill", "create",
		"--name="+name,
		"--description=cli-created",
		"--category=custom",
		"--body-file="+bodyFile,
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("skill create failed: %v\noutput: %s", err, out)
	}
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("unmarshal create output: %v\noutput: %s", err, out)
	}
	if rec["created"] != true || rec["name"] != name {
		t.Errorf("create response missing markers: %v", rec)
	}

	// Verify via read.
	readOut, err := wardenCLI(t, port, "skill", "read", name, "-o", "json")
	if err != nil {
		t.Fatalf("read after create failed: %v\noutput: %s", err, readOut)
	}
	var read map[string]interface{}
	if err := json.Unmarshal([]byte(readOut), &read); err != nil {
		t.Fatalf("unmarshal read: %v", err)
	}
	if read["description"] != "cli-created" {
		t.Errorf("description = %v, want cli-created", read["description"])
	}
	if read["origin"] != "user" {
		t.Errorf("origin = %v, want user", read["origin"])
	}
}

func TestCLI_SkillCreate_JSONFile(t *testing.T) {
	port := h.GetLeaderPort(t)
	const name = "e2e-cli-json"

	wardenCLI(t, port, "skill", "delete", name, "--force")
	t.Cleanup(func() {
		wardenCLI(t, port, "skill", "delete", name, "--force")
	})

	payload := map[string]interface{}{
		"name":        name,
		"description": "json-created",
		"category":    "custom",
		"body":        "# json body\n",
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "skill.json")
	if err := os.WriteFile(tmp, bytes, 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	out, err := wardenCLI(t, port, "skill", "create", name, "--json", "@"+tmp, "-o", "json")
	if err != nil {
		t.Fatalf("skill create --json failed: %v\noutput: %s", err, out)
	}
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec["name"] != name {
		t.Errorf("name = %v, want %s", rec["name"], name)
	}
}

func TestCLI_SkillCreate_JSONFlagsExclusivity(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := wardenCLI(t, port, "skill", "create", "x",
		"--name=x", "--json", `{"name":"x"}`,
	)
	if err == nil {
		t.Fatalf("expected error for --name + --json, got success.\noutput: %s", out)
	}
	if !strings.Contains(out, "-json cannot be combined with") {
		t.Errorf("output does not mention the exclusivity error; got:\n%s", out)
	}
}

func TestCLI_SkillUpdate_MergeSemantics(t *testing.T) {
	port := h.GetLeaderPort(t)
	const name = "e2e-cli-merge"

	wardenCLI(t, port, "skill", "delete", name, "--force")
	t.Cleanup(func() {
		wardenCLI(t, port, "skill", "delete", name, "--force")
	})

	bodyFile := filepath.Join(t.TempDir(), "body.md")
	if err := os.WriteFile(bodyFile, []byte("# original\n"), 0o600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if out, err := wardenCLI(t, port, "skill", "create",
		"--name="+name,
		"--description=before",
		"--category=custom",
		"--body-file="+bodyFile,
	); err != nil {
		t.Fatalf("create: %v\noutput: %s", err, out)
	}

	// Patch only description — body must survive.
	if out, err := wardenCLI(t, port, "skill", "update", name,
		"--description=after",
		"-o", "json",
	); err != nil {
		t.Fatalf("update: %v\noutput: %s", err, out)
	}

	readOut, err := wardenCLI(t, port, "skill", "read", name, "-o", "json")
	if err != nil {
		t.Fatalf("read: %v\noutput: %s", err, readOut)
	}
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(readOut), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec["description"] != "after" {
		t.Errorf("description = %v, want 'after'", rec["description"])
	}
	if body, _ := rec["body"].(string); !strings.Contains(body, "# original") {
		t.Errorf("body lost across update; got %q", body)
	}
	if v, _ := rec["version"].(float64); v != 2 {
		t.Errorf("version = %v, want 2", rec["version"])
	}
}

func TestCLI_SkillList_FiltersAreClientSide(t *testing.T) {
	port := h.GetLeaderPort(t)

	cases := []struct {
		name     string
		args     []string
		// allowed values for the field — every returned record must match one.
		matchKey string
		want     []string
	}{
		{
			name:     "by category",
			args:     []string{"--category=agent-flow"},
			matchKey: "category",
			want:     []string{"agent-flow"},
		},
		{
			name:     "by origin",
			args:     []string{"--origin=seed"},
			matchKey: "origin",
			want:     []string{"seed"},
		},
		{
			name:     "by provider",
			args:     []string{"--provider=vault"},
			matchKey: "provider",
			want:     []string{"vault"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"skill", "list"}, tc.args...)
			args = append(args, "-o", "json")

			out, err := wardenCLI(t, port, args...)
			if err != nil {
				t.Fatalf("skill list %v failed: %v\noutput: %s", tc.args, err, out)
			}
			var items []map[string]interface{}
			if err := json.Unmarshal([]byte(out), &items); err != nil {
				t.Fatalf("unmarshal: %v\noutput: %s", err, out)
			}
			// Foundation + provider seeds mean every test case should match
			// at least one record. A 0-length response means the filter is
			// either broken or the cluster missed a seed.
			if len(items) == 0 {
				t.Fatalf("expected at least one record matching filter %v", tc.args)
			}
			for _, item := range items {
				got, _ := item[tc.matchKey].(string)
				matched := false
				for _, w := range tc.want {
					if got == w {
						matched = true
						break
					}
				}
				if !matched {
					t.Errorf("record %v has %s=%q, want one of %v",
						item["name"], tc.matchKey, got, tc.want)
				}
			}
		})
	}
}

func TestCLI_SkillDelete_Force(t *testing.T) {
	port := h.GetLeaderPort(t)
	const name = "e2e-cli-delete"

	wardenCLI(t, port, "skill", "delete", name, "--force")
	t.Cleanup(func() {
		wardenCLI(t, port, "skill", "delete", name, "--force")
	})

	bodyFile := filepath.Join(t.TempDir(), "body.md")
	if err := os.WriteFile(bodyFile, []byte("# x\n"), 0o600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if out, err := wardenCLI(t, port, "skill", "create",
		"--name="+name, "--description=x", "--category=custom",
		"--body-file="+bodyFile,
	); err != nil {
		t.Fatalf("create: %v\noutput: %s", err, out)
	}

	if out, err := wardenCLI(t, port, "skill", "delete", name, "--force"); err != nil {
		t.Fatalf("delete --force: %v\noutput: %s", err, out)
	}

	// Read after delete must report an error.
	if _, err := wardenCLI(t, port, "skill", "read", name); err == nil {
		t.Error("expected read-after-delete to error, got success")
	}
}

