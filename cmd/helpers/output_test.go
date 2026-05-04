package helpers

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// setupCapture swaps the package-level writers for in-memory buffers and
// registers cleanup to restore them. Returns (stdout, stderr).
func setupCapture(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	SetOutputWriter(stdout)
	SetErrorWriter(stderr)
	t.Cleanup(ResetWriters)
	return stdout, stderr
}

// --- Format resolution ---

func TestResolveFormat_Flag(t *testing.T) {
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("ndjson")
	if got := ResolveFormat(); got != FormatNDJSON {
		t.Fatalf("ResolveFormat() = %q; want %q", got, FormatNDJSON)
	}
}

func TestResolveFormat_FlagBeatsEnv(t *testing.T) {
	t.Cleanup(func() { SetOutputFormat("") })
	t.Setenv("WARDEN_OUTPUT", "json")
	SetOutputFormat("text")
	if got := ResolveFormat(); got != FormatText {
		t.Fatalf("ResolveFormat() = %q; want %q (flag should beat env)", got, FormatText)
	}
}

func TestResolveFormat_EnvFallback(t *testing.T) {
	t.Cleanup(func() { SetOutputFormat("") })
	t.Setenv("WARDEN_OUTPUT", "JSON")
	if got := ResolveFormat(); got != FormatJSON {
		t.Fatalf("ResolveFormat() = %q; want %q (env should win when flag unset)", got, FormatJSON)
	}
}

func TestValidateFormat(t *testing.T) {
	for _, f := range []Format{FormatTable, FormatJSON, FormatNDJSON, FormatText} {
		if err := ValidateFormat(f); err != nil {
			t.Errorf("ValidateFormat(%q) returned error: %v", f, err)
		}
	}
	if err := ValidateFormat("yaml"); err == nil {
		t.Error("ValidateFormat(\"yaml\") returned nil; want error")
	}
}

// --- Field-flag parsing ---

func TestResolveFields_Empty(t *testing.T) {
	t.Cleanup(func() { SetFields("") })
	SetFields("")
	if got := ResolveFields(); got != nil {
		t.Fatalf("ResolveFields() = %#v; want nil", got)
	}
}

func TestResolveFields_FlagAndTrimming(t *testing.T) {
	t.Cleanup(func() { SetFields("") })
	SetFields("name, metadata.created_at ,policies")
	want := []string{"name", "metadata.created_at", "policies"}
	if got := ResolveFields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveFields() = %#v; want %#v", got, want)
	}
}

func TestResolveFields_EnvFallback(t *testing.T) {
	t.Cleanup(func() { SetFields("") })
	t.Setenv("WARDEN_FIELDS", "id,uuid")
	want := []string{"id", "uuid"}
	if got := ResolveFields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveFields() = %#v; want %#v", got, want)
	}
}

func TestResolveFields_OnlyWhitespace(t *testing.T) {
	t.Cleanup(func() { SetFields("") })
	SetFields(" , , ")
	if got := ResolveFields(); got != nil {
		t.Fatalf("ResolveFields() = %#v; want nil for whitespace-only input", got)
	}
}

// --- ProjectMap ---

func TestProjectMap_TopLevelScalar(t *testing.T) {
	src := map[string]any{"name": "alice", "secret": "shh", "age": 30}
	got := ProjectMap(src, []string{"name", "age"})
	want := map[string]any{"name": "alice", "age": 30}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestProjectMap_NestedDotPath(t *testing.T) {
	src := map[string]any{
		"name":     "alice",
		"metadata": map[string]any{"created_at": "2026-01-01", "extra": "ignored"},
	}
	got := ProjectMap(src, []string{"metadata.created_at"})
	want := map[string]any{
		"metadata": map[string]any{"created_at": "2026-01-01"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestProjectMap_MissingPathSilentlyOmitted(t *testing.T) {
	src := map[string]any{"name": "alice"}
	got := ProjectMap(src, []string{"name", "nonexistent", "metadata.absent"})
	want := map[string]any{"name": "alice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestProjectMap_StarOnSliceOfMaps(t *testing.T) {
	src := map[string]any{
		"tokens": []any{
			map[string]any{"id": "t1", "secret": "x"},
			map[string]any{"id": "t2", "secret": "y"},
		},
	}
	got := ProjectMap(src, []string{"tokens.*.id"})
	want := map[string]any{
		"tokens": []any{
			map[string]any{"id": "t1"},
			map[string]any{"id": "t2"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestProjectMap_StarOnMapValues(t *testing.T) {
	src := map[string]any{
		"by_name": map[string]any{
			"alice": map[string]any{"id": 1, "extra": "x"},
			"bob":   map[string]any{"id": 2, "extra": "y"},
		},
	}
	got := ProjectMap(src, []string{"by_name.*.id"})
	want := map[string]any{
		"by_name": map[string]any{
			"alice": map[string]any{"id": 1},
			"bob":   map[string]any{"id": 2},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestProjectMap_MultiplePathsMergeSubtrees(t *testing.T) {
	src := map[string]any{
		"metadata": map[string]any{"a": 1, "b": 2, "c": 3},
	}
	got := ProjectMap(src, []string{"metadata.a", "metadata.c"})
	want := map[string]any{
		"metadata": map[string]any{"a": 1, "c": 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestProjectMap_ScalarWithDeeperPathOmitted(t *testing.T) {
	src := map[string]any{"name": "alice"}
	got := ProjectMap(src, []string{"name.nope"})
	if len(got) != 0 {
		t.Fatalf("got %#v; want empty (scalar can't descend)", got)
	}
}

// --- RenderList: empty cases (Issue 1 from review) ---

func TestRenderList_NilInJSONEmitsEmptyArray(t *testing.T) {
	stdout, _ := setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("json")

	if err := RenderList(nil, func() { t.Fatal("tableFn must not be called in json mode") }); err != nil {
		t.Fatalf("RenderList: %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	if got != "[]" {
		t.Fatalf("RenderList(nil) in json mode = %q; want %q", got, "[]")
	}
}

func TestRenderList_NilInNDJSONEmitsNothing(t *testing.T) {
	stdout, _ := setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("ndjson")

	if err := RenderList(nil, func() { t.Fatal("tableFn must not be called in ndjson mode") }); err != nil {
		t.Fatalf("RenderList: %v", err)
	}

	if stdout.Len() != 0 {
		t.Fatalf("RenderList(nil) in ndjson mode wrote %q; want empty", stdout.String())
	}
}

func TestRenderList_NilInTableModeCallsTableFn(t *testing.T) {
	stdout, _ := setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("table")

	called := false
	err := RenderList(nil, func() {
		called = true
		// Production code prints to fmt.Println which goes to real os.Stdout,
		// not our captured writer. We just verify the closure ran.
		_ = stdout
	})
	if err != nil {
		t.Fatalf("RenderList: %v", err)
	}
	if !called {
		t.Fatal("tableFn was not called in table mode for empty list")
	}
}

// --- RenderMap: success envelope (Issue 2 from review) ---

func TestRenderMap_SuccessEnvelopeJSON(t *testing.T) {
	stdout, _ := setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("json")

	envelope := map[string]any{"path": "aws/config", "written": true}
	if err := RenderMap(envelope, func() { t.Fatal("tableFn must not be called in json mode") }); err != nil {
		t.Fatalf("RenderMap: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("emitted invalid JSON: %v\noutput: %s", err, stdout.String())
	}
	if got["path"] != "aws/config" || got["written"] != true {
		t.Fatalf("unexpected envelope: %#v", got)
	}
}

func TestRenderMap_TableModeCallsTableFn(t *testing.T) {
	_, _ = setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("table")

	called := false
	if err := RenderMap(map[string]any{"x": 1}, func() { called = true }); err != nil {
		t.Fatalf("RenderMap: %v", err)
	}
	if !called {
		t.Fatal("tableFn was not called in table mode")
	}
}

// --- Field projection in table mode (Issue 3 from review) ---

func TestRenderMap_FieldsInTableModeBypassesTableFnAndWarns(t *testing.T) {
	_, stderr := setupCapture(t)
	t.Cleanup(func() {
		SetOutputFormat("")
		SetFields("")
	})
	SetOutputFormat("table")
	SetFields("name")

	called := false
	if err := RenderMap(map[string]any{"name": "alice", "secret": "shh"}, func() { called = true }); err != nil {
		t.Fatalf("RenderMap: %v", err)
	}
	if called {
		t.Error("tableFn should be bypassed when --fields is set in table mode")
	}
	if !strings.Contains(stderr.String(), "warning: --fields with table output") {
		t.Errorf("expected stderr warning, got: %q", stderr.String())
	}
}

func TestRenderList_FieldsInTableModeBypassesTableFnAndWarns(t *testing.T) {
	_, stderr := setupCapture(t)
	t.Cleanup(func() {
		SetOutputFormat("")
		SetFields("")
	})
	SetOutputFormat("table")
	SetFields("name,id")

	called := false
	items := []map[string]any{{"name": "a", "id": 1}, {"name": "b", "id": 2}}
	if err := RenderList(items, func() { called = true }); err != nil {
		t.Fatalf("RenderList: %v", err)
	}
	if called {
		t.Error("tableFn should be bypassed when --fields is set in table mode")
	}
	if !strings.Contains(stderr.String(), "warning: --fields with table output") {
		t.Errorf("expected stderr warning, got: %q", stderr.String())
	}
}

// --- collapseForCell ---

func TestCollapseForCell(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want any
	}{
		{"scalar string", "alice", "alice"},
		{"scalar int", 42, 42},
		{"single-key map collapses to leaf", map[string]any{"city": "Paris"}, "Paris"},
		{"nested single-key chain collapses to leaf", map[string]any{"address": map[string]any{"city": "Paris"}}, "Paris"},
		{"slice of scalars joins with commas", []any{"a", "b", "c"}, "a, b, c"},
		{"multi-key map joins with commas", map[string]any{"a": 1, "b": 2}, "a=1, b=2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := collapseForCell(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("collapseForCell(%#v) = %#v; want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestProjectForCell_MissingPathReturnsEmptyString(t *testing.T) {
	got := projectForCell(map[string]any{"name": "alice"}, "absent.path")
	if got != "" {
		t.Errorf("projectForCell(missing) = %#v; want empty string", got)
	}
}

// --- logfmt quoting in writeText ---

func TestLogfmtValue(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"bare token", "alice", "alice"},
		{"int unquoted", 42, "42"},
		{"bool unquoted", true, "true"},
		{"empty quoted", "", `""`},
		{"contains space quoted", "hello world", `"hello world"`},
		{"contains equals quoted", "k=v", `"k=v"`},
		{"contains quote escaped", `say "hi"`, `"say \"hi\""`},
		{"contains backslash escaped", `a\b`, `"a\\b"`},
		{"nil renders empty", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logfmtValue(tt.in); got != tt.want {
				t.Errorf("logfmtValue(%#v) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRenderMap_TextFormatQuotesAmbiguousValues(t *testing.T) {
	stdout, _ := setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("text")

	data := map[string]any{
		"description": "AWS config",
		"max_body":    10485760,
		"timeout":     "60s",
	}
	if err := RenderMap(data, nil); err != nil {
		t.Fatalf("RenderMap: %v", err)
	}
	got := strings.TrimSpace(stdout.String())
	want := `description="AWS config" max_body=10485760 timeout=60s`
	if got != want {
		t.Fatalf("RenderMap(text) = %q; want %q", got, want)
	}
}

// --- ProjectMap pre-existing tests above remain in place ---
