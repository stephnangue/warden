// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestParseJSONRPCStrict_ValidSingle(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	reqs, err := ParseJSONRPCStrict(body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Method != "tools/list" {
		t.Errorf("Method = %q, want tools/list", reqs[0].Method)
	}
	if reqs[0].Name != "" {
		t.Errorf("Name = %q, want empty (tools/list has no name)", reqs[0].Name)
	}
}

func TestParseJSONRPCStrict_ValidBatch(t *testing.T) {
	body := []byte(`[
		{"jsonrpc":"2.0","method":"tools/list","id":1},
		{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_repos"},"id":2},
		{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"repo://foo"},"id":3}
	]`)
	reqs, err := ParseJSONRPCStrict(body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(reqs) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(reqs))
	}
	if reqs[1].Name != "search_repos" {
		t.Errorf("reqs[1].Name = %q, want search_repos", reqs[1].Name)
	}
	if reqs[2].Name != "repo://foo" {
		t.Errorf("reqs[2].Name = %q, want repo://foo", reqs[2].Name)
	}
}

func TestParseJSONRPCStrict_ValidToolsCallWithArgs(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/foo","count":5}},"id":1}`)
	reqs, err := ParseJSONRPCStrict(body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if reqs[0].Name != "read_file" {
		t.Errorf("Name = %q, want read_file", reqs[0].Name)
	}
	if reqs[0].Arguments == nil {
		t.Fatalf("Arguments is nil, want populated")
	}
	if got := string(reqs[0].Arguments["path"]); got != `"/tmp/foo"` {
		t.Errorf("arguments.path = %s, want %q", got, `"/tmp/foo"`)
	}
	if got := string(reqs[0].Arguments["count"]); got != "5" {
		t.Errorf("arguments.count = %s, want 5", got)
	}
}

// Adversarial / fail-closed table. Every case must yield the named
// ParseErrorKind. These are the bytes a compromised agent could send.
func TestParseJSONRPCStrict_Adversarial(t *testing.T) {
	cases := []struct {
		name string
		body string
		want ParseErrorKind
	}{
		{"empty body", "", ErrKindMalformedJSONRPC},
		{"whitespace only", "   \n\t  ", ErrKindMalformedJSONRPC},
		{"utf-8 bom", "\xEF\xBB\xBF" + `{"jsonrpc":"2.0","method":"tools/list"}`, ErrKindMalformedJSONRPC},
		{"non-object non-array top level", `"hello"`, ErrKindMalformedJSONRPC},
		{"top-level number", `42`, ErrKindMalformedJSONRPC},
		{"trailing data after object", `{"jsonrpc":"2.0","method":"tools/list"}garbage`, ErrKindMalformedJSONRPC},
		{"trailing data after batch", `[{"jsonrpc":"2.0","method":"tools/list"}]extra`, ErrKindMalformedJSONRPC},
		{"empty batch", `[]`, ErrKindBatchEmpty},
		{"missing jsonrpc", `{"method":"tools/list"}`, ErrKindMalformedJSONRPC},
		{"missing method", `{"jsonrpc":"2.0","id":1}`, ErrKindMalformedJSONRPC},
		{"jsonrpc wrong version", `{"jsonrpc":"1.0","method":"tools/list"}`, ErrKindMalformedJSONRPC},
		{"jsonrpc number not string", `{"jsonrpc":2.0,"method":"tools/list"}`, ErrKindMalformedJSONRPC},
		{"method empty string", `{"jsonrpc":"2.0","method":""}`, ErrKindMalformedJSONRPC},
		{"method is number", `{"jsonrpc":"2.0","method":42}`, ErrKindMalformedJSONRPC},
		{"method is object", `{"jsonrpc":"2.0","method":{"x":1}}`, ErrKindMalformedJSONRPC},
		{"unknown top-level key", `{"jsonrpc":"2.0","method":"tools/list","extra":1}`, ErrKindMalformedJSONRPC},
		{"duplicate top-level key", `{"jsonrpc":"2.0","method":"tools/list","method":"tools/call"}`, ErrKindDuplicateKey},
		{"duplicate jsonrpc", `{"jsonrpc":"2.0","jsonrpc":"2.0","method":"tools/list"}`, ErrKindDuplicateKey},
		{"duplicate nested key in params", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"a","name":"b"}}`, ErrKindDuplicateKey},
		{"duplicate key in arguments", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"path":"a","path":"b"}}}`, ErrKindDuplicateKey},
		{"duplicate deeply nested", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"cfg":{"a":1,"a":2}}}}`, ErrKindDuplicateKey},

		// tools/call shape requirements.
		{"tools/call missing params", `{"jsonrpc":"2.0","method":"tools/call"}`, ErrKindMalformedParams},
		{"tools/call params is array", `{"jsonrpc":"2.0","method":"tools/call","params":["a"]}`, ErrKindMalformedParams},
		{"tools/call params is string", `{"jsonrpc":"2.0","method":"tools/call","params":"x"}`, ErrKindMalformedParams},
		{"tools/call missing params.name", `{"jsonrpc":"2.0","method":"tools/call","params":{}}`, ErrKindMalformedParams},
		{"tools/call params.name is object", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":{"x":1}}}`, ErrKindMalformedParams},
		{"tools/call params.name is number", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":42}}`, ErrKindMalformedParams},
		{"tools/call params.name empty", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":""}}`, ErrKindMalformedParams},
		{"tools/call arguments is array", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":["a"]}}`, ErrKindMalformedParams},
		{"tools/call arguments is string", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":"y"}}`, ErrKindMalformedParams},

		// resources/read shape.
		{"resources/read missing params", `{"jsonrpc":"2.0","method":"resources/read"}`, ErrKindMalformedParams},
		{"resources/read missing params.uri", `{"jsonrpc":"2.0","method":"resources/read","params":{}}`, ErrKindMalformedParams},
		{"resources/read uri is array", `{"jsonrpc":"2.0","method":"resources/read","params":{"uri":["x"]}}`, ErrKindMalformedParams},
		{"resources/read uri empty", `{"jsonrpc":"2.0","method":"resources/read","params":{"uri":""}}`, ErrKindMalformedParams},

		// prompts/get shape.
		{"prompts/get missing params", `{"jsonrpc":"2.0","method":"prompts/get"}`, ErrKindMalformedParams},
		{"prompts/get missing params.name", `{"jsonrpc":"2.0","method":"prompts/get","params":{}}`, ErrKindMalformedParams},
		{"prompts/get name is null", `{"jsonrpc":"2.0","method":"prompts/get","params":{"name":null}}`, ErrKindMalformedParams},

		// Batch.
		{"batch one entry malformed", `[{"jsonrpc":"2.0","method":"tools/list"},{"jsonrpc":"2.0"}]`, ErrKindMalformedJSONRPC},
		{"batch with empty batch element", `[[]]`, ErrKindMalformedJSONRPC},
		{"batch with primitive entry", `[1]`, ErrKindMalformedJSONRPC},
		{"batch with string entry", `["x"]`, ErrKindMalformedJSONRPC},
		{"batch with null entry", `[null]`, ErrKindMalformedJSONRPC},
		{"batch dup key in one element", `[{"jsonrpc":"2.0","method":"tools/list"},{"jsonrpc":"2.0","method":"a","method":"b"}]`, ErrKindDuplicateKey},

		// params: null for name-bearing methods — currently denied via
		// the "missing params.<key>" path; pinning the contract.
		{"tools/call params null", `{"jsonrpc":"2.0","method":"tools/call","params":null}`, ErrKindMalformedParams},
		{"resources/read params null", `{"jsonrpc":"2.0","method":"resources/read","params":null}`, ErrKindMalformedParams},
		{"prompts/get params null", `{"jsonrpc":"2.0","method":"prompts/get","params":null}`, ErrKindMalformedParams},

		// Leading bytes that aren't JSON whitespace (RFC 8259 set is
		// only SP/HT/LF/CR). VT and FF look like whitespace in some
		// contexts but JSON rejects them as leading bytes.
		{"vertical tab leading", "\x0b" + `{"jsonrpc":"2.0","method":"tools/list"}`, ErrKindMalformedJSONRPC},
		{"form feed leading", "\x0c" + `{"jsonrpc":"2.0","method":"tools/list"}`, ErrKindMalformedJSONRPC},
		{"utf-16 le bom prefix", "\xff\xfe" + `{"jsonrpc":"2.0","method":"tools/list"}`, ErrKindMalformedJSONRPC},

		// Trailing whitespace then garbage.
		{"trailing whitespace then garbage", `{"jsonrpc":"2.0","method":"tools/list"}` + "   garbage", ErrKindMalformedJSONRPC},

		// Duplicate key directly inside id-as-object.
		{"id object with duplicate keys", `{"jsonrpc":"2.0","method":"tools/list","id":{"a":1,"a":2}}`, ErrKindDuplicateKey},

		// id permits primitives only; complex ids carrying dup keys are rejected by the walker.
		{"id is array of dup keys", `{"jsonrpc":"2.0","method":"tools/list","id":[{"a":1,"a":2}]}`, ErrKindDuplicateKey},

		// Malformed JSON.
		{"malformed JSON unclosed", `{"jsonrpc":"2.0","method":"tools/list"`, ErrKindMalformedJSONRPC},
		{"malformed JSON garbage", `{`, ErrKindMalformedJSONRPC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs, perr := ParseJSONRPCStrict([]byte(tc.body))
			if perr == nil {
				t.Fatalf("expected ParseError of kind %q, got nil (reqs=%v)", tc.want, reqs)
			}
			if perr.Kind != tc.want {
				t.Errorf("ParseError.Kind = %q, want %q (msg=%q)", perr.Kind, tc.want, perr.Msg)
			}
		})
	}
}

// Methods outside the name-bearing trio leave Name empty and accept
// any params shape (including array-style by-position params).
func TestParseJSONRPCStrict_NonNameMethodsAcceptArrayParams(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"initialize","params":[1,2,3],"id":1}`)
	reqs, perr := ParseJSONRPCStrict(body)
	if perr != nil {
		t.Fatalf("expected no error, got %v", perr)
	}
	if reqs[0].Name != "" {
		t.Errorf("Name = %q, want empty for initialize", reqs[0].Name)
	}
	if reqs[0].Arguments != nil {
		t.Errorf("Arguments populated for non-tools/call: %v", reqs[0].Arguments)
	}
}

// Notifications (no id) parse cleanly. The parser does not differentiate
// them; the matcher gates them like any other request.
func TestParseJSONRPCStrict_Notification(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled"}`)
	reqs, perr := ParseJSONRPCStrict(body)
	if perr != nil {
		t.Fatalf("expected no error, got %v", perr)
	}
	if reqs[0].Method != "notifications/cancelled" {
		t.Errorf("Method = %q", reqs[0].Method)
	}
}

// JSON-RPC ids may be string, number, or null. All accepted; none
// inspected.
func TestParseJSONRPCStrict_IDShapes(t *testing.T) {
	for _, idLit := range []string{`"abc"`, `42`, `null`, `0`, `-1`} {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":` + idLit + `}`)
		if _, perr := ParseJSONRPCStrict(body); perr != nil {
			t.Errorf("id=%s: expected no error, got %v", idLit, perr)
		}
	}
}

// Depth bound: at the limit accepts, one over rejects. params occupies
// depth 1; arguments adds depth 2; each x-wrapper adds one more.
// maxJSONDepth = 32, so 30 x-wrappers reach the deepest acceptable
// level and 31 wrappers exceed it.
func TestParseJSONRPCStrict_DepthBound(t *testing.T) {
	build := func(n int) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			sb.WriteString(`{"x":`)
		}
		sb.WriteString(`0`)
		for i := 0; i < n; i++ {
			sb.WriteString(`}`)
		}
		return sb.String()
	}
	pass := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":` + build(30) + `}}`
	if _, perr := ParseJSONRPCStrict([]byte(pass)); perr != nil {
		t.Errorf("at depth limit: expected accept, got %v", perr)
	}
	fail := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":` + build(31) + `}}`
	_, perr := ParseJSONRPCStrict([]byte(fail))
	if perr == nil {
		t.Fatalf("over depth limit: expected ParseError, got nil")
	}
	if perr.Kind != ErrKindMalformedJSONRPC {
		t.Errorf("over depth limit: kind = %q, want malformed_jsonrpc", perr.Kind)
	}
}

// Leading whitespace is fine (JSON allows it); trailing whitespace
// after the value is also fine (encoding/json tolerates it before EOF).
func TestParseJSONRPCStrict_Whitespace(t *testing.T) {
	body := []byte("\n\t   " + `{"jsonrpc":"2.0","method":"tools/list"}` + "\n  ")
	if _, perr := ParseJSONRPCStrict(body); perr != nil {
		t.Errorf("whitespace-padded body rejected: %v", perr)
	}
}

// RawParams captures the verbatim params bytes for matcher-internal
// use. Must be non-empty for any request that had a params field.
func TestParseJSONRPCStrict_RawParamsCaptured(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"a":1}}}`)
	reqs, perr := ParseJSONRPCStrict(body)
	if perr != nil {
		t.Fatalf("unexpected error: %v", perr)
	}
	if len(reqs[0].RawParams) == 0 {
		t.Errorf("RawParams empty, want verbatim bytes")
	}
	var v any
	if err := json.Unmarshal(reqs[0].RawParams, &v); err != nil {
		t.Errorf("RawParams not valid JSON: %v", err)
	}
}

// Method is preserved verbatim on the descriptor — callers lowercase
// only at match time. Name extraction dispatch IS case-insensitive
// though: a body with method "Tools/Call" still routes through the
// tools/call extractor so params.name reaches the descriptor. The
// matcher then lowercases both for comparison, giving consistent
// semantics from wire to decision.
func TestParseJSONRPCStrict_MethodCasePreserved(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"Tools/Call","params":{"name":"X"}}`)
	reqs, perr := ParseJSONRPCStrict(body)
	if perr != nil {
		t.Fatalf("unexpected error: %v", perr)
	}
	if reqs[0].Method != "Tools/Call" {
		t.Errorf("Method = %q, want verbatim Tools/Call", reqs[0].Method)
	}
	// Name extracted via case-insensitive method dispatch — params.name
	// is the tools/call value regardless of method casing.
	if reqs[0].Name != "X" {
		t.Errorf("Name = %q, want X (case-insensitive method dispatch extracts params.name)", reqs[0].Name)
	}
}

// arguments: null is parsed without error and leaves Arguments == nil —
// indistinguishable from "arguments field absent". Pinning the
// behaviour as the documented contract for MatchArgs.
func TestParseJSONRPCStrict_ArgumentsNullEquivalentToAbsent(t *testing.T) {
	bodyNull := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":null}}`)
	reqsNull, perr := ParseJSONRPCStrict(bodyNull)
	if perr != nil {
		t.Fatalf("arguments:null: unexpected error: %v", perr)
	}
	if reqsNull[0].Arguments != nil {
		t.Errorf("arguments:null produced Arguments=%v, want nil", reqsNull[0].Arguments)
	}

	bodyAbsent := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}`)
	reqsAbsent, perr := ParseJSONRPCStrict(bodyAbsent)
	if perr != nil {
		t.Fatalf("arguments absent: unexpected error: %v", perr)
	}
	if reqsAbsent[0].Arguments != nil {
		t.Errorf("arguments absent produced Arguments=%v, want nil", reqsAbsent[0].Arguments)
	}

	bodyEmpty := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{}}}`)
	reqsEmpty, perr := ParseJSONRPCStrict(bodyEmpty)
	if perr != nil {
		t.Fatalf("arguments:{}: unexpected error: %v", perr)
	}
	if reqsEmpty[0].Arguments == nil {
		t.Errorf("arguments:{} produced Arguments=nil, want non-nil empty map")
	}
	if len(reqsEmpty[0].Arguments) != 0 {
		t.Errorf("arguments:{} produced Arguments=%v, want empty", reqsEmpty[0].Arguments)
	}
}

// id may be a complex value (object/array) as long as the value itself
// is structurally sound (no duplicate keys at any depth). Strict JSON-RPC
// 2.0 §4 restricts id to string/number/null; we accept more leniently
// because id is not consulted for policy and rejecting it would break
// MCP clients that have been observed wrapping ids. Strict-dup-key
// detection inside complex ids still applies — see Adversarial.
func TestParseJSONRPCStrict_LenientComplexID(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"tools/list","id":{}}`,
		`{"jsonrpc":"2.0","method":"tools/list","id":{"trace":"x"}}`,
		`{"jsonrpc":"2.0","method":"tools/list","id":[1,2]}`,
	} {
		if _, perr := ParseJSONRPCStrict([]byte(body)); perr != nil {
			t.Errorf("body=%s: unexpected error: %v", body, perr)
		}
	}
}

// Numeric ids preserve precision via json.Number — Decode into
// RawMessage never coerces to float64. A 19-digit integer would lose
// precision under default decoding.
func TestParseJSONRPCStrict_LargeNumericIDPreserved(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":12345678901234567890}`)
	if _, perr := ParseJSONRPCStrict(body); perr != nil {
		t.Errorf("large numeric id rejected: %v", perr)
	}
}

// Notifications can carry params per JSON-RPC 2.0 §4.1. The parser
// doesn't differentiate notifications from id-bearing requests; only
// the matcher cares.
func TestParseJSONRPCStrict_NotificationWithParams(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"abc","value":50}}`)
	reqs, perr := ParseJSONRPCStrict(body)
	if perr != nil {
		t.Fatalf("notification with params rejected: %v", perr)
	}
	if reqs[0].Method != "notifications/progress" {
		t.Errorf("Method = %q", reqs[0].Method)
	}
}

// Unicode escapes in method strings decode correctly (Go normalises
// during Token()). The matcher's lowercase compare sees the post-
// decode runes, matching the upstream MCP server's view.
func TestParseJSONRPCStrict_UnicodeEscapes(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}`)
	reqs, perr := ParseJSONRPCStrict(body)
	if perr != nil {
		t.Fatalf("unicode-escaped method rejected: %v", perr)
	}
	if reqs[0].Method != "tools/call" {
		t.Errorf("Method = %q, want tools/call", reqs[0].Method)
	}
}

// Fuzz seeds exercise strict-parse against arbitrary bytes. Invariant:
// ParseJSONRPCStrict never panics regardless of input. This is the
// panic-safety net the extractor relies on — a parser panic would
// propagate into the goroutine handling the request.
func FuzzParseJSONRPCStrict(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","method":"tools/list"}`,
		`[{"jsonrpc":"2.0","method":"tools/list"}]`,
		`{}`,
		`[`,
		`{"a":1,"a":2}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"a":1}}}`,
		string([]byte{0xEF, 0xBB, 0xBF, '{', '}'}),
		``,
		`{"jsonrpc":"2.0","method":"tools/list","id":null,"id":1}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":[]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parser panicked on input %q: %v", body, r)
			}
		}()
		_, _ = ParseJSONRPCStrict(body)
	})
}

// ---------- benchmarks ----------

// Typical single-request body: tools/list with id. Tiny — measures
// per-request overhead floor.
func BenchmarkParseJSONRPCStrict_Small(b *testing.B) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseJSONRPCStrict(body); err != nil {
			b.Fatal(err)
		}
	}
}

// Typical tools/call with a handful of scalar arguments. Closest to
// the median production payload size.
func BenchmarkParseJSONRPCStrict_ToolsCall(b *testing.B) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/foo","encoding":"utf-8","limit":1024,"offset":0}},"id":42}`)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseJSONRPCStrict(body); err != nil {
			b.Fatal(err)
		}
	}
}

// Larger arguments object: still bounded but exercises the per-object
// duplicate-key seen-set growth and the recursive walker on a non-
// trivial structure.
func BenchmarkParseJSONRPCStrict_LargeArguments(b *testing.B) {
	var args strings.Builder
	args.WriteString(`{`)
	for i := 0; i < 64; i++ {
		if i > 0 {
			args.WriteString(`,`)
		}
		fmt.Fprintf(&args, `"key_%02d":"value_%02d"`, i, i)
	}
	args.WriteString(`}`)
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"big_tool","arguments":` + args.String() + `},"id":1}`)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseJSONRPCStrict(body); err != nil {
			b.Fatal(err)
		}
	}
}

// Batch of 16 mixed-shape requests. Exercises the batch loop and
// allocates a request slice.
func BenchmarkParseJSONRPCStrict_Batch16(b *testing.B) {
	const one = `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_repos","arguments":{"q":"foo"}},"id":1}`
	var sb strings.Builder
	sb.WriteString(`[`)
	for i := 0; i < 16; i++ {
		if i > 0 {
			sb.WriteString(`,`)
		}
		sb.WriteString(one)
	}
	sb.WriteString(`]`)
	body := []byte(sb.String())
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseJSONRPCStrict(body); err != nil {
			b.Fatal(err)
		}
	}
}

// Deny-path: duplicate key in nested arguments. Measures the cost of
// the failure path (matters because adversarial traffic might saturate
// it).
func BenchmarkParseJSONRPCStrict_DuplicateKey(b *testing.B) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"a":1,"a":2}}}`)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseJSONRPCStrict(body); err == nil {
			b.Fatal("expected ParseError")
		}
	}
}

// Deny-path: malformed JSON-RPC envelope (unknown top-level key).
// Cheapest deny — single field validation before bail.
func BenchmarkParseJSONRPCStrict_UnknownTopLevel(b *testing.B) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","unexpected":42}`)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseJSONRPCStrict(body); err == nil {
			b.Fatal("expected ParseError")
		}
	}
}

// =============================================================================
// subscriptions/listen resource subscriptions
// =============================================================================

func TestParseJSONRPCStrict_SubscriptionsListen(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "resource subscriptions extracted",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["repo://a","repo://b"]}},"id":1}`,
			want: []string{"repo://a", "repo://b"},
		},
		{
			// A list-changed-only listen names no resource. Legitimate and
			// common — it is what the go-sdk opens when a client registers a
			// list-changed handler — and it is governed by the method gate
			// alone.
			name: "list-changed only yields no URIs",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}},"id":1}`,
			want: nil,
		},
		{
			name: "notifications absent",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{},"id":1}`,
			want: nil,
		},
		{
			name: "notifications null",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":null},"id":1}`,
			want: nil,
		},
		{
			name: "resourceSubscriptions null",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":null}},"id":1}`,
			want: nil,
		},
		{
			name: "params absent entirely",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","id":1}`,
			want: nil,
		},
		{
			name: "empty array",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":[]}},"id":1}`,
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs, err := ParseJSONRPCStrict([]byte(tc.body))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if len(reqs[0].URIs) != len(tc.want) {
				t.Fatalf("URIs = %v, want %v", reqs[0].URIs, tc.want)
			}
			for i := range tc.want {
				if reqs[0].URIs[i] != tc.want[i] {
					t.Errorf("URIs[%d] = %q, want %q", i, reqs[0].URIs[i], tc.want[i])
				}
			}
		})
	}
}

// A present-but-wrong-typed subscription list fails closed rather than being
// silently ignored: the field decides what the caller gets to watch, so
// dropping it would grant a stream nobody gated.
func TestParseJSONRPCStrict_SubscriptionsListen_FailsClosed(t *testing.T) {
	oversized := make([]string, maxResourceSubscriptions+1)
	for i := range oversized {
		oversized[i] = `"repo://x"`
	}

	cases := []struct {
		name string
		body string
	}{
		{"params not an object", `{"jsonrpc":"2.0","method":"subscriptions/listen","params":[1,2],"id":1}`},
		{"notifications not an object", `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":"all"},"id":1}`},
		{"subscriptions not an array", `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":"repo://a"}},"id":1}`},
		{"subscription element not a string", `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":[{"uri":"repo://a"}]}},"id":1}`},
		{"empty subscription URI", `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["repo://a",""]}},"id":1}`},
		{
			// One request must not buy an unbounded amount of pattern
			// matching against the resources family.
			name: "too many subscriptions",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":[` +
				strings.Join(oversized, ",") + `]}},"id":1}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseJSONRPCStrict([]byte(tc.body))
			if err == nil {
				t.Fatalf("expected a parse error, got none")
			}
			if err.Kind != ErrKindMalformedParams {
				t.Errorf("Kind = %q, want %q", err.Kind, ErrKindMalformedParams)
			}
		})
	}
}

// =============================================================================
// Case-variant key smuggling
// =============================================================================

// Warden judges the body and then forwards it verbatim, and Go's
// encoding/json matches object keys to struct fields case-insensitively — so
// an upstream built on it honours "Arguments" and "Notifications" exactly as
// it honours the canonical spelling. Reading only the exact spelling would
// mean the gate never sees what the upstream acts on. For the OPTIONAL fields
// that is a silent bypass rather than a denial, which is what makes it sharp.
func TestParseJSONRPCStrict_CaseVariantKeysAreRead(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		check func(t *testing.T, req JSONRPCRequest)
	}{
		{
			name: "tools/call Arguments",
			body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"deploy","Arguments":{"env":"prod"}},"id":1}`,
			check: func(t *testing.T, req JSONRPCRequest) {
				if got := string(req.Arguments["env"]); got != `"prod"` {
					t.Errorf("arguments.env = %s, want %q — a CEL condition would judge nothing", got, `"prod"`)
				}
			},
		},
		{
			name: "tools/call NAME",
			body: `{"jsonrpc":"2.0","method":"tools/call","params":{"NAME":"deploy"},"id":1}`,
			check: func(t *testing.T, req JSONRPCRequest) {
				if req.Name != "deploy" {
					t.Errorf("Name = %q, want deploy", req.Name)
				}
			},
		},
		{
			name: "listen Notifications",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"Notifications":{"resourceSubscriptions":["repo://secret"]}},"id":1}`,
			check: func(t *testing.T, req JSONRPCRequest) {
				if len(req.URIs) != 1 || req.URIs[0] != "repo://secret" {
					t.Errorf("URIs = %v, want [repo://secret] — the subscription would go ungated", req.URIs)
				}
			},
		},
		{
			name: "listen ResourceSubscriptions",
			body: `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"ResourceSubscriptions":["repo://secret"]}},"id":1}`,
			check: func(t *testing.T, req JSONRPCRequest) {
				if len(req.URIs) != 1 {
					t.Errorf("URIs = %v, want one URI", req.URIs)
				}
			},
		},
		{
			name: "resources/read URI",
			body: `{"jsonrpc":"2.0","method":"resources/read","params":{"URI":"repo://secret"},"id":1}`,
			check: func(t *testing.T, req JSONRPCRequest) {
				if req.Name != "repo://secret" {
					t.Errorf("Name = %q, want repo://secret", req.Name)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs, err := ParseJSONRPCStrict([]byte(tc.body))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			tc.check(t, reqs[0])
		})
	}
}

// Two spellings at once is unresolvable — Go's decoder picks one by map
// order — so it fails closed rather than gating whichever Warden happened to
// read. The duplicate-key walk does not catch these: they are distinct keys.
func TestParseJSONRPCStrict_AmbiguousCaseVariantsFailClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"two spellings of arguments", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"env":"dev"},"Arguments":{"env":"prod"}},"id":1}`},
		{"two spellings of name", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"safe","Name":"dangerous"},"id":1}`},
		{"two spellings of notifications", `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"NOTIFICATIONS":{"resourceSubscriptions":["repo://secret"]}},"id":1}`},
		{"two spellings of resourceSubscriptions", `{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":[],"ResourceSubscriptions":["repo://secret"]}},"id":1}`},
		{"two spellings of uri", `{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"repo://public","URI":"repo://secret"},"id":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseJSONRPCStrict([]byte(tc.body))
			if err == nil {
				t.Fatalf("expected a parse error, got none")
			}
			if err.Kind != ErrKindMalformedParams {
				t.Errorf("Kind = %q, want %q", err.Kind, ErrKindMalformedParams)
			}
		})
	}
}

// resources/subscribe is the legacy-era route to the same
// notifications/resources/updated stream subscriptions/listen carries, so its
// URI must reach the descriptor for the resources family to gate it.
func TestParseJSONRPCStrict_ResourcesSubscribe(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"resources/subscribe","params":{"uri":"repo://myorg/api"},"id":1}`)
	reqs, err := ParseJSONRPCStrict(body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if reqs[0].Name != "repo://myorg/api" {
		t.Errorf("Name = %q, want repo://myorg/api", reqs[0].Name)
	}

	if _, err := ParseJSONRPCStrict([]byte(`{"jsonrpc":"2.0","method":"resources/subscribe","params":{},"id":1}`)); err == nil {
		t.Errorf("a subscribe with no uri must fail closed")
	}
}
