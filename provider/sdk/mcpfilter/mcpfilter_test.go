package mcpfilter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// denyPrefix returns a keep-predicate that drops names with the given prefix,
// mimicking a denied_tools = ["<prefix>*"] policy gate.
func denyPrefix(prefix string) func(string) bool {
	return func(name string) bool { return !strings.HasPrefix(name, prefix) }
}

// allowOnly returns a keep-predicate that keeps only the listed names,
// mimicking an allowed_* allow-list.
func allowOnly(names ...string) func(string) bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return func(name string) bool { return set[name] }
}

// parseTools returns the tool names in a filtered tools/list body.
func parseTools(t *testing.T, body []byte) []string {
	t.Helper()
	var env struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal filtered body: %v\nbody: %s", err, body)
	}
	out := make([]string, len(env.Result.Tools))
	for i, tool := range env.Result.Tools {
		out[i] = tool.Name
	}
	return out
}

func TestFilterJSON_DropsDeniedTools(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` +
		`{"name":"get_repo","description":"a"},` +
		`{"name":"delete_repo","description":"b"},` +
		`{"name":"get_issue","description":"c"}` +
		`]}}`)

	out, changed, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	got := parseTools(t, out)
	want := []string{"get_repo", "get_issue"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tools = %v, want %v", got, want)
	}
}

func TestFilterJSON_AllowList(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` +
		`{"name":"get_repo"},{"name":"list_issues"},{"name":"delete_repo"}]}}`)

	out, changed, err := FilterListResponse("tools/list", "application/json", body, allowOnly("get_repo", "list_issues"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	got := parseTools(t, out)
	if strings.Join(got, ",") != "get_repo,list_issues" {
		t.Fatalf("tools = %v", got)
	}
}

func TestFilterJSON_NoChangeReturnsOriginal(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_repo"}]}}`)
	out, changed, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false")
	}
	if string(out) != string(body) {
		t.Fatalf("expected original body returned verbatim")
	}
}

func TestFilterJSON_PreservesNextCursorAndUnknownFields(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":7,"result":{"tools":[` +
		`{"name":"get_repo"},{"name":"delete_repo"}],"nextCursor":"abc","_meta":{"x":1}}}`)

	out, changed, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	var env struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			NextCursor string          `json:"nextCursor"`
			Meta       json.RawMessage `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.JSONRPC != "2.0" || env.ID != 7 {
		t.Fatalf("envelope fields not preserved: %+v", env)
	}
	if env.Result.NextCursor != "abc" {
		t.Fatalf("nextCursor not preserved: %q", env.Result.NextCursor)
	}
	if string(env.Result.Meta) != `{"x":1}` {
		t.Fatalf("_meta not preserved: %s", env.Result.Meta)
	}
}

func TestFilterJSON_ResourcesMatchByURI(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"resources":[` +
		`{"uri":"github://repo/readme","name":"readme"},` +
		`{"uri":"github://secrets/token","name":"token"}]}}`)

	out, changed, err := FilterListResponse("resources/list", "application/json", body, denyPrefix("github://secrets/"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	var env struct {
		Result struct {
			Resources []struct {
				URI string `json:"uri"`
			} `json:"resources"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.Result.Resources) != 1 || env.Result.Resources[0].URI != "github://repo/readme" {
		t.Fatalf("resources = %+v", env.Result.Resources)
	}
}

func TestFilterJSON_PromptsMatchByName(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"prompts":[` +
		`{"name":"summarize"},{"name":"sudo_reset"}]}}`)
	out, changed, err := FilterListResponse("prompts/list", "application/json", body, denyPrefix("sudo_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if strings.Contains(string(out), "sudo_reset") {
		t.Fatalf("denied prompt leaked: %s", out)
	}
}

func TestFilterJSON_ErrorResponsePassesThrough(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`)
	out, changed, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("x"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false for error response")
	}
	if string(out) != string(body) {
		t.Fatalf("error response not passed through verbatim")
	}
}

func TestFilterJSON_NoArrayPassesThrough(t *testing.T) {
	// result present but no tools array (empty capabilities result shape).
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"nextCursor":"z"}}`)
	out, changed, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("x"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false")
	}
	if string(out) != string(body) {
		t.Fatalf("expected verbatim passthrough")
	}
}

func TestFilterJSON_DropsUnnamedItem(t *testing.T) {
	// An item missing the name field cannot be verified → dropped (fail closed).
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` +
		`{"name":"get_repo"},{"description":"no name here"}]}}`)
	out, changed, err := FilterListResponse("tools/list", "application/json", body, func(string) bool { return true })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true (unnamed item dropped)")
	}
	got := parseTools(t, out)
	if strings.Join(got, ",") != "get_repo" {
		t.Fatalf("tools = %v, want [get_repo]", got)
	}
}

func TestFilterJSON_UnparseableFailsClosed(t *testing.T) {
	// Simulates a still-compressed / garbled body: must error, not passthrough.
	body := []byte("\x1f\x8b\x08\x00 not json at all")
	_, _, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("x"))
	if err == nil {
		t.Fatalf("expected fail-closed error on unparseable body")
	}
}

func TestFilterJSON_ResultNotObjectFailsClosed(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":"unexpected"}`)
	_, _, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("x"))
	if err == nil {
		t.Fatalf("expected fail-closed error when result is not an object")
	}
}

func TestFilterListResponse_UnknownMethodFailsClosed(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	_, _, err := FilterListResponse("resources/templates/list", "application/json", body, denyPrefix("x"))
	if err == nil {
		t.Fatalf("expected error for unsupported list method")
	}
}

func TestFilterJSON_DenyAllProducesEmptyArrayNotNull(t *testing.T) {
	// Every tool denied must yield "tools":[] — a null would break clients
	// that iterate the array, and would misrepresent the result shape.
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_a"},{"name":"delete_b"}]}}`)
	out, changed, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if !strings.Contains(string(out), `"tools":[]`) {
		t.Fatalf("expected empty array, got: %s", out)
	}
	if strings.Contains(string(out), "null") {
		t.Fatalf("array must not be null: %s", out)
	}
}

func TestFilterSSE_MultiEventFiltersOnlyResult(t *testing.T) {
	// A notification event precedes the tools/list response event; only the
	// result event is rewritten, the notification passes through.
	body := []byte("event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"p\":1}}\n\n" +
		"event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_x\"},{\"name\":\"delete_x\"}]}}\n\n")

	out, changed, err := FilterListResponse("tools/list", "text/event-stream", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	s := string(out)
	if strings.Contains(s, "delete_x") {
		t.Fatalf("denied tool leaked: %s", s)
	}
	if !strings.Contains(s, "notifications/progress") {
		t.Fatalf("notification event dropped: %s", s)
	}
	if !strings.Contains(s, "get_x") {
		t.Fatalf("allowed tool missing: %s", s)
	}
}

func TestFilterSSE_DropsDeniedTools(t *testing.T) {
	body := []byte("event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_repo\"},{\"name\":\"delete_repo\"}]}}\n\n")

	out, changed, err := FilterListResponse("tools/list", "text/event-stream", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if strings.Contains(string(out), "delete_repo") {
		t.Fatalf("denied tool leaked in SSE: %s", out)
	}
	if !strings.Contains(string(out), "get_repo") {
		t.Fatalf("allowed tool missing: %s", out)
	}
	if !strings.Contains(string(out), "event: message") {
		t.Fatalf("event framing lost: %s", out)
	}
}

func TestFilterSSE_CharsetParam(t *testing.T) {
	body := []byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"delete_x\"}]}}\n\n")
	out, changed, err := FilterListResponse("tools/list", "text/event-stream; charset=utf-8", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if strings.Contains(string(out), "delete_x") {
		t.Fatalf("denied tool leaked: %s", out)
	}
}

func TestFilterSSE_NonResultEventPassesThrough(t *testing.T) {
	// A ping/notification event with no result must pass through untouched, and
	// with nothing filterable the original body is returned verbatim.
	body := []byte("event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n")
	out, changed, err := FilterListResponse("tools/list", "text/event-stream", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false")
	}
	if string(out) != string(body) {
		t.Fatalf("expected verbatim passthrough")
	}
}

func TestFilterSSE_CRLFFraming(t *testing.T) {
	body := []byte("event: message\r\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_x\"},{\"name\":\"delete_x\"}]}}\r\n\r\n")
	out, changed, err := FilterListResponse("tools/list", "text/event-stream", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if strings.Contains(string(out), "delete_x") {
		t.Fatalf("denied tool leaked: %s", out)
	}
}

// =============================================================================
// cacheScope
// =============================================================================

func resultOf(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(env["result"], &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return result
}

// A listing pruned for one principal is not the document another principal
// would get, so an upstream "public" — which explicitly authorises a shared
// intermediary to serve the same bytes to anyone — has to be narrowed.
func TestFilterJSON_ForcesCacheScopePrivate(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_x"},{"name":"delete_x"}],"cacheScope":"public","ttlMs":60000}}`)

	out, changed, err := FilterListResponse("tools/list", "application/json", body, denyPrefix("delete_"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}

	result := resultOf(t, out)
	if got := string(result["cacheScope"]); got != `"private"` {
		t.Errorf("cacheScope = %s, want \"private\"", got)
	}
	if got := string(result["ttlMs"]); got != "60000" {
		t.Errorf("ttlMs = %s, want 60000 — freshness is the upstream's call, not ours", got)
	}
}

// The rewrite counts as a change on its own. "Nothing was dropped for THIS
// principal" is not "this document is the same for everyone", and letting the
// body pass through byte-identical would leave the public scope on the wire.
func TestFilterJSON_CacheScopeRewriteAloneCountsAsChanged(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_x"}],"cacheScope":"public"}}`)

	out, changed, err := FilterListResponse("tools/list", "application/json", body, func(string) bool { return true })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true — nothing dropped, but the scope was narrowed")
	}
	if got := string(resultOf(t, out)["cacheScope"]); got != `"private"` {
		t.Errorf("cacheScope = %s, want \"private\"", got)
	}
}

// Inventing a field the upstream never sent would put something on the wire
// the server did not say, which strict clients may object to. An absent
// cacheScope already means the conservative thing.
func TestFilterJSON_DoesNotAddCacheScope(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_x"}]}}`)

	out, changed, err := FilterListResponse("tools/list", "application/json", body, func(string) bool { return true })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false — nothing to drop and no scope to narrow")
	}
	if _, ok := resultOf(t, out)["cacheScope"]; ok {
		t.Error("cacheScope was invented on a response that carried none")
	}
}

func TestFilterJSON_AlreadyPrivateCacheScopeIsLeftAlone(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_x"}],"cacheScope":"private"}}`)

	out, changed, err := FilterListResponse("tools/list", "application/json", body, func(string) bool { return true })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false — already private")
	}
	if string(out) != string(body) {
		t.Error("body was rewritten despite nothing needing to change")
	}
}

// A non-string cacheScope is a shape the spec does not define. Guessing at it
// risks corrupting a field we do not understand; the Cache-Control header
// still covers the response.
func TestFilterJSON_NonStringCacheScopeLeftAlone(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_x"}],"cacheScope":{"scope":"public"}}}`)

	_, changed, err := FilterListResponse("tools/list", "application/json", body, func(string) bool { return true })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false")
	}
}

// The SSE shape goes through the same result rewrite, so it must narrow the
// scope too — an event-stream listing is cacheable in exactly the same way.
func TestFilterSSE_ForcesCacheScopePrivate(t *testing.T) {
	body := []byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_x\"}],\"cacheScope\":\"public\"}}\n\n")

	out, changed, err := FilterListResponse("tools/list", "text/event-stream", body, func(string) bool { return true })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if !strings.Contains(string(out), `"cacheScope":"private"`) {
		t.Errorf("SSE block did not carry the narrowed scope:\n%s", out)
	}
	if !strings.Contains(string(out), "event: message") {
		t.Error("non-data lines must survive the rewrite")
	}
}

// ---------------------------------------------------------------------------
// Skills extension (SEP-2640)
// ---------------------------------------------------------------------------

// skillsListBody is a skills/list page: a multi-file skill, a single-file
// skill, and a dynamically generated one, plus the pagination and caching
// attributes a 2026-07-28 server sends.
const skillsListBody = `{"jsonrpc":"2.0","id":1,"result":{"skills":[` +
	`{"uri":"skill://pdf-processing/SKILL.md","frontmatter":{"name":"pdf-processing","description":"a"},"resources":[` +
	`{"uri":"skill://pdf-processing/SKILL.md","digest":"sha256:aa","size":10},` +
	`{"uri":"skill://pdf-processing/scripts/extract.py","digest":"sha256:bb","size":20}]},` +
	`{"uri":"skill://git-workflow/SKILL.md","frontmatter":{"name":"git-workflow","description":"b"},"resources":[` +
	`{"uri":"skill://git-workflow/SKILL.md","digest":"sha256:cc","size":30}]},` +
	`{"uri":"skill://report/SKILL.md","frontmatter":{"name":"report","description":"c"},"resources":"dynamic"}` +
	`],"nextCursor":"page-2","ttlMs":60000,"cacheScope":"public"}}`

// skillEntries returns the filtered skills keyed by uri, each as raw JSON.
func skillEntries(t *testing.T, body []byte) (map[string]json.RawMessage, map[string]json.RawMessage) {
	t.Helper()
	var env struct {
		Result map[string]json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal filtered body: %v\nbody: %s", err, body)
	}
	var skills []json.RawMessage
	if err := json.Unmarshal(env.Result["skills"], &skills); err != nil {
		t.Fatalf("unmarshal skills: %v", err)
	}
	out := make(map[string]json.RawMessage, len(skills))
	for _, s := range skills {
		var e struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(s, &e); err != nil {
			t.Fatalf("unmarshal entry: %v", err)
		}
		out[e.URI] = s
	}
	return out, env.Result
}

// jsonEqual reports whether two JSON documents decode to the same value.
func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		t.Fatalf("unmarshal %s: %v", a, err)
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	return reflect.DeepEqual(va, vb)
}

// A skills/list entry is kept or dropped whole, by its SKILL.md uri. The
// nested resources array of a kept entry must come back with the same
// content: SEP-2640 requires it complete, and a host verifying a trimmed one
// would reject the skill.
func TestFilterJSON_SkillsList_DropsWholeEntries(t *testing.T) {
	out, changed, err := FilterListResponse("skills/list", "application/json", []byte(skillsListBody),
		allowOnly("skill://pdf-processing/SKILL.md", "skill://report/SKILL.md"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	entries, result := skillEntries(t, out)
	if len(entries) != 2 {
		t.Fatalf("kept %d entries, want 2: %s", len(entries), out)
	}
	if _, ok := entries["skill://git-workflow/SKILL.md"]; ok {
		t.Fatalf("denied skill leaked: %s", out)
	}

	// The kept entries are unchanged in content. Compared as decoded JSON:
	// re-encoding compacts whitespace and HTML-escapes, which no host check
	// observes.
	var orig struct {
		Result struct {
			Skills []json.RawMessage `json:"skills"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(skillsListBody), &orig); err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, entries["skill://pdf-processing/SKILL.md"], orig.Result.Skills[0]) {
		t.Errorf("multi-file entry changed:\n got %s\nwant %s", entries["skill://pdf-processing/SKILL.md"], orig.Result.Skills[0])
	}
	if !jsonEqual(t, entries["skill://report/SKILL.md"], orig.Result.Skills[2]) {
		t.Errorf("dynamic entry changed:\n got %s\nwant %s", entries["skill://report/SKILL.md"], orig.Result.Skills[2])
	}

	if got := string(result["nextCursor"]); got != `"page-2"` {
		t.Errorf("nextCursor = %s, want \"page-2\"", got)
	}
	if got := string(result["ttlMs"]); got != `60000` {
		t.Errorf("ttlMs = %s, want 60000", got)
	}
	if got := string(result["cacheScope"]); got != `"private"` {
		t.Errorf("cacheScope = %s, want \"private\"", got)
	}
}

// An entry whose uri cannot be read cannot be proven allowed.
func TestFilterJSON_SkillsList_DropsEntryWithoutURI(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"skills":[` +
		`{"frontmatter":{"name":"x"},"resources":"dynamic"},` +
		`{"uri":42,"resources":"dynamic"},` +
		`{"uri":"skill://ok/SKILL.md","resources":"dynamic"}]}}`)

	out, _, err := FilterListResponse("skills/list", "application/json", body, func(string) bool { return true })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	entries, _ := skillEntries(t, out)
	if len(entries) != 1 {
		t.Fatalf("kept %d entries, want only the one with a readable uri: %s", len(entries), out)
	}
}

// A skills value that is not an array cannot be verified; null and absent
// carry nothing to leak and pass through.
func TestFilterJSON_SkillsList_Shapes(t *testing.T) {
	for _, bad := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"skills":"dynamic"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"skills":{"uri":"skill://x/SKILL.md"}}}`,
	} {
		if _, _, err := FilterListResponse("skills/list", "application/json", []byte(bad), allowOnly()); err == nil {
			t.Errorf("expected a fail-closed error for %s", bad)
		}
	}

	for _, ok := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"skills":null}}`,
		`{"jsonrpc":"2.0","id":1,"result":{}}`,
	} {
		out, changed, err := FilterListResponse("skills/list", "application/json", []byte(ok), allowOnly())
		if err != nil {
			t.Errorf("unexpected error for %s: %v", ok, err)
		}
		if changed || string(out) != ok {
			t.Errorf("expected %s to pass through unchanged, got %s", ok, out)
		}
	}

	// An absent skills array still had its scope narrowed: the result
	// described a per-principal answer.
	out, changed, err := FilterListResponse("skills/list", "application/json",
		[]byte(`{"jsonrpc":"2.0","id":1,"result":{"cacheScope":"public"}}`), allowOnly())
	if err != nil || !changed || !strings.Contains(string(out), `"cacheScope":"private"`) {
		t.Errorf("cacheScope not narrowed: changed=%v err=%v out=%s", changed, err, out)
	}
}

func TestFilterSSE_SkillsList(t *testing.T) {
	body := []byte("event: message\n" +
		"data: " + skillsListBody + "\n\n")

	out, changed, err := FilterListResponse("skills/list", "text/event-stream", body,
		allowOnly("skill://pdf-processing/SKILL.md"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	s := string(out)
	if strings.Contains(s, "git-workflow") || strings.Contains(s, "skill://report/") {
		t.Fatalf("denied skill leaked in SSE: %s", s)
	}
	if !strings.Contains(s, "skill://pdf-processing/scripts/extract.py") {
		t.Fatalf("kept entry lost its resources: %s", s)
	}
}

// A directory read returns a page of Resource objects; children, including
// sub-directories, are filtered by uri as resources/list items are.
func TestFilterJSON_DirectoryRead_FiltersChildrenByURI(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"resources":[` +
		`{"uri":"skill://pdf-processing/templates/invoice.md","name":"invoice.md"},` +
		`{"uri":"skill://pdf-processing/templates/internal.md","name":"internal.md"},` +
		`{"uri":"skill://pdf-processing/templates/regional","name":"regional","mimeType":"inode/directory"}` +
		`],"nextCursor":"c2"}}`)

	out, changed, err := FilterListResponse("resources/directory/read", "application/json", body,
		denyPrefix("skill://pdf-processing/templates/internal"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	s := string(out)
	if strings.Contains(s, "internal.md") {
		t.Fatalf("denied child leaked: %s", s)
	}
	if !strings.Contains(s, "templates/regional") || !strings.Contains(s, "invoice.md") {
		t.Fatalf("allowed child missing: %s", s)
	}
	if !strings.Contains(s, `"nextCursor":"c2"`) {
		t.Fatalf("nextCursor lost: %s", s)
	}
}
