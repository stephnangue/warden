// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stephnangue/warden/logical"
)

// fakeBackend is the minimal logical.Backend stub used to drive
// extractMCPDescriptor without spinning up a full mount. It implements
// MCPPolicyEnforced when enforced is non-nil so we can probe both
// branches of the type assertion.
type fakeBackend struct {
	logical.Backend
	enforced *fakeMCPHook
}

type fakeMCPHook struct {
	enforce bool
	cap     int64
}

// mcpBackend wraps fakeBackend with the marker interface — used when a
// test wants the type assertion to succeed.
type mcpBackend struct {
	fakeBackend
}

func (b *mcpBackend) ShouldEnforceMCPPolicy(req *logical.Request) (bool, int64) {
	if b.enforced == nil {
		return false, 0
	}
	return b.enforced.enforce, b.enforced.cap
}

func newReq(t *testing.T, body string) *logical.Request {
	t.Helper()
	httpReq, err := http.NewRequest(http.MethodPost, "/v1/mcp_github/gateway/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	return &logical.Request{
		HTTPRequest: httpReq,
	}
}

// Non-MCP backend: type assertion fails, descriptor stays nil.
func TestExtractMCPDescriptor_NotMCPBackend(t *testing.T) {
	c := &Core{}
	req := newReq(t, `{"jsonrpc":"2.0","method":"tools/list"}`)
	c.extractMCPDescriptor(context.Background(), req, &fakeBackend{})
	if req.MCPDescriptor != nil {
		t.Fatalf("descriptor = %+v, want nil for non-MCP backend", req.MCPDescriptor)
	}
}

// MCP backend opts out per-request: descriptor is the empty sentinel
// (non-nil, no Calls, no ParseErr). decideMCP uses this to distinguish
// "backend declined for this request shape" from "no MCP-aware backend
// at all", which lets MCP Streamable HTTP's GET/DELETE share the URL
// with the POST that mcp{} gates.
func TestExtractMCPDescriptor_OptsOutPerRequest(t *testing.T) {
	c := &Core{}
	req := newReq(t, `{"jsonrpc":"2.0","method":"tools/list"}`)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: false}
	c.extractMCPDescriptor(context.Background(), req, b)
	if req.MCPDescriptor == nil {
		t.Fatalf("descriptor = nil, want empty sentinel for opted-out request")
	}
	if req.MCPDescriptor.Calls != nil || req.MCPDescriptor.ParseErr != nil {
		t.Fatalf("descriptor = %+v, want empty sentinel (Calls nil, ParseErr nil) for opted-out request", req.MCPDescriptor)
	}
}

// MCP backend opts in with valid JSON-RPC: descriptor populated.
func TestExtractMCPDescriptor_ValidSingle(t *testing.T) {
	c := &Core{}
	req := newReq(t, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_repos","arguments":{"q":"foo"}}}`)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 1 << 20}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil {
		t.Fatal("descriptor is nil, want populated")
	}
	if desc.ParseErr != nil {
		t.Fatalf("ParseErr = %v, want nil", desc.ParseErr)
	}
	if len(desc.Calls) != 1 {
		t.Fatalf("Calls len = %d, want 1", len(desc.Calls))
	}
	if desc.Calls[0].Method != "tools/call" {
		t.Errorf("Method = %q, want tools/call", desc.Calls[0].Method)
	}
	if desc.Calls[0].Name != "search_repos" {
		t.Errorf("Name = %q, want search_repos", desc.Calls[0].Name)
	}
	if desc.Calls[0].BatchIndex != 0 {
		t.Errorf("BatchIndex = %d, want 0", desc.Calls[0].BatchIndex)
	}
	arg, ok := desc.Calls[0].MatchArgs["q"]
	if !ok {
		t.Fatalf("MatchArgs missing q: %v", desc.Calls[0].MatchArgs)
	}
	if arg.Kind != logical.ParamString || arg.Str != "foo" {
		t.Errorf("q arg = %+v, want String/foo", arg)
	}
}

// Batch: BatchIndex stamped per element.
func TestExtractMCPDescriptor_Batch(t *testing.T) {
	c := &Core{}
	req := newReq(t, `[
		{"jsonrpc":"2.0","method":"tools/list"},
		{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}
	]`)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 1 << 20}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr != nil {
		t.Fatalf("descriptor = %+v, ParseErr should be nil", desc)
	}
	if len(desc.Calls) != 2 {
		t.Fatalf("Calls len = %d, want 2", len(desc.Calls))
	}
	if desc.Calls[0].BatchIndex != 0 || desc.Calls[1].BatchIndex != 1 {
		t.Errorf("BatchIndex = [%d, %d], want [0, 1]", desc.Calls[0].BatchIndex, desc.Calls[1].BatchIndex)
	}
}

// Oversized body: cap+1 bytes triggers oversized_body.
func TestExtractMCPDescriptor_OversizedBody(t *testing.T) {
	c := &Core{}
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"big":"` +
		strings.Repeat("A", 256) + `"}}}`
	req := newReq(t, body)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: int64(len(body) - 1)}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr == nil {
		t.Fatalf("descriptor = %+v, want ParseErr", desc)
	}
	if desc.ParseErr.Kind != logical.MCPParseKindOversizedBody {
		t.Errorf("ParseErr.Kind = %q, want oversized_body", desc.ParseErr.Kind)
	}
}

// Malformed JSON-RPC: descriptor.ParseErr.Kind = malformed_jsonrpc.
func TestExtractMCPDescriptor_MalformedBody(t *testing.T) {
	c := &Core{}
	req := newReq(t, `{not json`)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 1 << 20}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr == nil {
		t.Fatalf("descriptor = %+v, want ParseErr", desc)
	}
	if desc.ParseErr.Kind != logical.MCPParseKindMalformedJSONRPC {
		t.Errorf("ParseErr.Kind = %q, want malformed_jsonrpc", desc.ParseErr.Kind)
	}
}

// Duplicate key: descriptor.ParseErr.Kind = duplicate_key.
func TestExtractMCPDescriptor_DuplicateKey(t *testing.T) {
	c := &Core{}
	req := newReq(t, `{"jsonrpc":"2.0","method":"tools/list","method":"tools/call"}`)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 1 << 20}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr == nil {
		t.Fatalf("descriptor = %+v, want ParseErr", desc)
	}
	if desc.ParseErr.Kind != logical.MCPParseKindDuplicateKey {
		t.Errorf("ParseErr.Kind = %q, want duplicate_key", desc.ParseErr.Kind)
	}
}

// After extraction, the body must still be readable for the downstream
// proxy and must yield the original bytes byte-for-byte. Load-bearing
// for the streaming-branch claim that the extractor restores the body.
func TestExtractMCPDescriptor_BodyByteIdentity(t *testing.T) {
	c := &Core{}
	original := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"a":1}}}`
	req := newReq(t, original)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 1 << 20}
	c.extractMCPDescriptor(context.Background(), req, b)
	if req.HTTPRequest.Body == nil {
		t.Fatal("Body is nil after extraction")
	}
	got, err := io.ReadAll(req.HTTPRequest.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !bytes.Equal(got, []byte(original)) {
		t.Errorf("restored body differs from original\nwant: %q\ngot:  %q", original, string(got))
	}
}

// Cap fallback: cap=0 from the hook falls back to framework default.
// A small body fits under the default and parses successfully.
func TestExtractMCPDescriptor_CapZeroFallsBack(t *testing.T) {
	c := &Core{}
	req := newReq(t, `{"jsonrpc":"2.0","method":"tools/list"}`)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 0}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr != nil {
		t.Fatalf("descriptor = %+v, want successful parse", desc)
	}
}

// Empty body when enforce=true: malformed_jsonrpc.
func TestExtractMCPDescriptor_EmptyBody(t *testing.T) {
	c := &Core{}
	req := newReq(t, ``)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 1 << 20}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr == nil {
		t.Fatalf("descriptor = %+v, want ParseErr", desc)
	}
	if desc.ParseErr.Kind != logical.MCPParseKindMalformedJSONRPC {
		t.Errorf("ParseErr.Kind = %q, want malformed_jsonrpc", desc.ParseErr.Kind)
	}
}

// nil req and nil backend are no-ops (the handler guards before
// calling; defense in depth).
func TestExtractMCPDescriptor_NilGuards(t *testing.T) {
	c := &Core{}
	c.extractMCPDescriptor(context.Background(), nil, &mcpBackend{})
	req := newReq(t, `{}`)
	c.extractMCPDescriptor(context.Background(), req, nil)
	if req.MCPDescriptor != nil {
		t.Errorf("descriptor should stay nil when backend is nil")
	}
}

// Body sized exactly to cap parses successfully (not oversized) and
// the restored body bytes are byte-identical to the original. Pins
// the off-by-one boundary between the cap+1 read and the > cap check.
func TestExtractMCPDescriptor_ExactCapBoundary(t *testing.T) {
	c := &Core{}
	body := `{"jsonrpc":"2.0","method":"tools/list"}`
	req := newReq(t, body)
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: int64(len(body))}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr != nil {
		t.Fatalf("descriptor = %+v, want successful parse at exact cap", desc)
	}
	got, err := io.ReadAll(req.HTTPRequest.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !bytes.Equal(got, []byte(body)) {
		t.Errorf("restored body differs at exact-cap boundary")
	}
}

// enforce=true with HTTPRequest.Body=nil yields malformed_jsonrpc. The
// handler shouldn't reach this state in production, but defensive nil-
// safety matters for testability + future code paths.
func TestExtractMCPDescriptor_NilHTTPBody(t *testing.T) {
	c := &Core{}
	req := newReq(t, `{"jsonrpc":"2.0","method":"tools/list"}`)
	req.HTTPRequest.Body = nil
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 1 << 20}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr == nil {
		t.Fatalf("descriptor = %+v, want ParseErr", desc)
	}
	if desc.ParseErr.Kind != logical.MCPParseKindMalformedJSONRPC {
		t.Errorf("ParseErr.Kind = %q, want malformed_jsonrpc", desc.ParseErr.Kind)
	}
}

// A body reader that returns an I/O error mid-read populates ParseErr
// with malformed_jsonrpc.
func TestExtractMCPDescriptor_BodyReadError(t *testing.T) {
	c := &Core{}
	req := newReq(t, `{}`)
	req.HTTPRequest.Body = io.NopCloser(&errReader{err: errFakeRead})
	b := &mcpBackend{}
	b.enforced = &fakeMCPHook{enforce: true, cap: 1 << 20}
	c.extractMCPDescriptor(context.Background(), req, b)
	desc := req.MCPDescriptor
	if desc == nil || desc.ParseErr == nil {
		t.Fatalf("descriptor = %+v, want ParseErr", desc)
	}
	if desc.ParseErr.Kind != logical.MCPParseKindMalformedJSONRPC {
		t.Errorf("ParseErr.Kind = %q, want malformed_jsonrpc", desc.ParseErr.Kind)
	}
}

// errReader always errors on Read.
type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }

var errFakeRead = &fakeErr{msg: "synthetic read failure"}

type fakeErr struct{ msg string }

func (e *fakeErr) Error() string { return e.msg }

// classifyParam table for each JSON kind.
func TestClassifyParam(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantKnd logical.ParamKind
		wantStr string
	}{
		{"string", `"hello"`, logical.ParamString, "hello"},
		{"empty string", `""`, logical.ParamString, ""},
		{"number int", `42`, logical.ParamNumber, "42"},
		{"number float", `3.14`, logical.ParamNumber, "3.14"},
		{"number large", `12345678901234567890`, logical.ParamNumber, "12345678901234567890"},
		{"bool true", `true`, logical.ParamBool, "true"},
		{"bool false", `false`, logical.ParamBool, "false"},
		{"null", `null`, logical.ParamNull, ""},
		{"object", `{"x":1}`, logical.ParamObject, ""},
		{"array", `[1,2,3]`, logical.ParamArray, ""},
		{"whitespace then object", "  \n\t {}", logical.ParamObject, ""},
		{"empty", ``, logical.ParamMissing, ""},
		{"whitespace only", "   \t\n", logical.ParamMissing, ""},
		{"capital True (invalid JSON, fail-safe)", `True`, logical.ParamMissing, ""},
		{"capital Null", `Null`, logical.ParamMissing, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyParam(json.RawMessage(tc.raw))
			if got.Kind != tc.wantKnd {
				t.Errorf("Kind = %d, want %d", got.Kind, tc.wantKnd)
			}
			if got.Str != tc.wantStr {
				t.Errorf("Str = %q, want %q", got.Str, tc.wantStr)
			}
		})
	}
}

// classifyArgs preserves nil vs empty-map distinction so the matcher
// can later distinguish "no arguments field" from "arguments: {}".
func TestClassifyArgs_NilVsEmpty(t *testing.T) {
	if classifyArgs(nil) != nil {
		t.Error("classifyArgs(nil) != nil")
	}
	got := classifyArgs(map[string]json.RawMessage{})
	if got == nil {
		t.Error("classifyArgs(empty) returned nil, want empty map")
	}
	if len(got) != 0 {
		t.Errorf("classifyArgs(empty) len = %d, want 0", len(got))
	}
}
