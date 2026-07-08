package mcpfilter

import (
	"encoding/json"
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
