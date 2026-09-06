// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	multierror "github.com/hashicorp/go-multierror"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// headerReq builds an MCP-shaped request carrying the given transport
// headers, with the descriptor produced by the real parser.
func headerReq(t testing.TB, body string, headers map[string]string) *logical.Request {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/mcp/gateway/", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	return &logical.Request{
		Path:          "mcp/gateway/",
		Operation:     logical.UpdateOperation,
		HTTPRequest:   httpReq,
		MCPDescriptor: synthesizeMCPDescriptorFromBody([]byte(body)),
	}
}

const toolsCallBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy"}}`

func TestValidateMCPHeaders(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		headers  map[string]string
		wantDeny bool
	}{
		{
			// The legacy skip branch. No version header at all means a
			// pre-2026-07-28 client, and requiring headers of it would brick
			// every legacy upstream Warden fronts.
			name:    "no version header, no other headers",
			body:    toolsCallBody,
			headers: nil,
		},
		{
			// The other half of that branch, and the one worth guarding: a
			// mismatch is never legitimate, so it is refused even from a
			// client that sent no version at all.
			name: "no version header but a mismatched method header",
			body: toolsCallBody,
			headers: map[string]string{
				mcpMethodHeader: "tools/list",
			},
			wantDeny: true,
		},
		{
			name: "old version, headers absent",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2025-11-25",
			},
		},
		{
			name: "old version, headers matching",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2025-11-25",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            "deploy",
			},
		},
		{
			name: "old version, method mismatched",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2025-11-25",
				mcpMethodHeader:          "tools/list",
			},
			wantDeny: true,
		},
		{
			name: "modern, complete and matching",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            "deploy",
			},
		},
		{
			name: "modern, method header missing",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpNameHeader:            "deploy",
			},
			wantDeny: true,
		},
		{
			name: "modern, name header missing on a name-bearing method",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
			},
			wantDeny: true,
		},
		{
			name: "modern, name header mismatched",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            "delete_everything",
			},
			wantDeny: true,
		},
		{
			// server/discover is not name-bearing, so no name is required of
			// it — and it is the first request a modern client sends, so
			// getting this wrong would break every one of them.
			name: "modern server/discover needs no name header",
			body: `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "server/discover",
			},
		},
		{
			name: "modern tools/list needs no name header",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/list",
			},
		},
		{
			// A notification has no id, and the spec leaves header rules for
			// that shape undefined — so presence is not required.
			name: "modern notification with no headers",
			body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
			},
		},
		{
			name: "modern notification with a mismatched method header",
			body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
			},
			wantDeny: true,
		},
		{
			// Case-sensitive on purpose: this compares a header against the
			// body, not against a policy pattern, so a difference in case is
			// the disagreement being detected.
			name: "modern, method differing only in case",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "Tools/Call",
				mcpNameHeader:            "deploy",
			},
			wantDeny: true,
		},
		{
			name: "sentinel-encoded name matching a UTF-8 tool name",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"café_deploy"}}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            base64SentinelPrefix + base64.StdEncoding.EncodeToString([]byte("café_deploy")) + base64SentinelSuffix,
			},
		},
		{
			name: "sentinel-encoded name that decodes to the wrong name",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            base64SentinelPrefix + base64.StdEncoding.EncodeToString([]byte("other")) + base64SentinelSuffix,
			},
			wantDeny: true,
		},
		{
			name: "sentinel with invalid base64",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            base64SentinelPrefix + "!!!not-base64!!!" + base64SentinelSuffix,
			},
			wantDeny: true,
		},
		{
			// A body declaring a different revision than the transport is
			// self-contradictory: something downstream will believe one of
			// the two, and it may not be the one Warden judged.
			name: "body _meta version contradicts the header",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            "deploy",
			},
			wantDeny: true,
		},
		{
			name: "body _meta version agrees with the header",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            "deploy",
			},
		},
		{
			// A version Warden cannot place is not read as "latest":
			// imposing modern requirements on traffic that may be far older
			// is the wrong direction to guess in.
			name: "unparseable version is not treated as modern",
			body: toolsCallBody,
			headers: map[string]string{
				mcpProtocolVersionHeader: "latest",
			},
		},
		{
			// One header cannot describe several calls, so a batch is not
			// required to carry any.
			name: "batch without transport headers is skipped",
			body: `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
			},
		},
		{
			// But one that arrives anyway describes something unverifiable.
			// Forwarding it would leave the mirrored-copy problem
			// permanently open for batch traffic, which the legacy era goes
			// on accepting.
			name: "batch carrying a method header denies",
			body: `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
			},
			wantDeny: true,
		},
		{
			// A one-element batch has exactly one method and name, so it is
			// validated like any single call rather than waved through.
			name: "single-element batch is validated",
			body: `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy"}}]`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/list",
			},
			wantDeny: true,
		},
		{
			// resources/subscribe is name-bearing to the policy layer but
			// carries no Mcp-Name on the wire — the go-sdk's Subscribe sends
			// the method header and nothing else. Requiring one would refuse
			// every modern subscribe.
			name: "modern resources/subscribe needs no name header",
			body: `{"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"repo://a"}}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "resources/subscribe",
			},
		},
		{
			// A body declaring the modern revision while the transport
			// declares none is a modern request wearing legacy clothes,
			// which is how a client would buy itself the era split's
			// leniency.
			name: "body _meta version with no transport version",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
			headers: map[string]string{
				mcpMethodHeader: "tools/call",
				mcpNameHeader:   "deploy",
			},
			wantDeny: true,
		},
		{
			// The go-sdk compares Mcp-Name raw and reserves the sentinel for
			// Mcp-Param-*; the spec defines it for names that are not
			// header-safe. Either reading agreeing is enough, so a tool
			// literally named like a sentinel is not falsely refused.
			name: "name literally spelled like a sentinel",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"=?base64?zzz?="}}`,
			headers: map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            "=?base64?zzz?=",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := headerReq(t, tc.body, tc.headers)
			require.Nil(t, req.MCPDescriptor.ParseErr, "test body must parse")

			d := validateMCPHeaders(req, req.MCPDescriptor)

			if !tc.wantDeny {
				assert.Nil(t, d)
				return
			}
			require.NotNil(t, d, "expected a header-mismatch deny")
			assert.Equal(t, "deny", d.Decision)
			assert.Equal(t, mcpRuleTypeHeaderMismatch, d.RuleType)
			assert.Empty(t, d.Method, "the decision must name no body or header value")
			assert.Empty(t, d.Name)
			// The audit detail is a closed set of constants, never anything
			// read off the wire.
			assert.Contains(t, []string{
				headerMismatchMethod, headerMismatchName, headerMismatchVersion,
				headerMismatchDuplicate, headerMismatchBatch,
			}, d.MatchedRule)
		})
	}
}

// The gate runs before any contract is consulted, so a request whose headers
// contradict its body is refused without asking whether the call it claims to
// be would have been allowed.
func TestMCPEval_HeaderMismatch_DeniesBeforeTheContract(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["*"] }
  tools { allowed = ["*"] }
}
`)
	req := headerReq(t, toolsCallBody, map[string]string{
		mcpProtocolVersionHeader: "2026-07-28",
		mcpMethodHeader:          "tools/list",
	})
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed, "a wide-open contract must not rescue a contradictory request")
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, mcpRuleTypeHeaderMismatch, res.MCPDecision.RuleType)
}

// Absence-deny wins where no contract is in scope: the validation never runs
// there, and the request is refused either way.
func TestMCPEval_HeaderMismatch_AbsenceDenyTakesPrecedence(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	req := headerReq(t, toolsCallBody, map[string]string{
		mcpProtocolVersionHeader: "2026-07-28",
		mcpMethodHeader:          "tools/list",
	})
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, mcpRuleTypeNoMCPPolicy, res.MCPDecision.RuleType)
}

func TestDecodeMCPHeaderValue(t *testing.T) {
	v, ok := decodeMCPHeaderValue("plain_name")
	assert.True(t, ok)
	assert.Equal(t, "plain_name", v)

	v, ok = decodeMCPHeaderValue(base64SentinelPrefix + base64.StdEncoding.EncodeToString([]byte("héllo")) + base64SentinelSuffix)
	assert.True(t, ok)
	assert.Equal(t, "héllo", v)

	// The markers are exact and lowercase; anything else is a literal value,
	// not a sentinel.
	v, ok = decodeMCPHeaderValue("=?BASE64?aGk=?=")
	assert.True(t, ok)
	assert.Equal(t, "=?BASE64?aGk=?=", v)

	_, ok = decodeMCPHeaderValue(base64SentinelPrefix + "%%%" + base64SentinelSuffix)
	assert.False(t, ok)
}

func TestIsHeaderEraRevision(t *testing.T) {
	assert.True(t, isHeaderEraRevision("2026-07-28"))
	assert.True(t, isHeaderEraRevision("2027-01-01"))
	assert.False(t, isHeaderEraRevision("2025-11-25"))
	assert.False(t, isHeaderEraRevision("2025-06-18"))
	assert.False(t, isHeaderEraRevision(""))
	assert.False(t, isHeaderEraRevision("latest"))
	assert.False(t, isHeaderEraRevision("2026-07-28-beta"))
	assert.False(t, isHeaderEraRevision("20260728"))
}

// The _meta cross-check must see what the upstream's decoder will see. Both
// of these hide the key from a raw byte scan of the body while every
// conforming decoder still resolves it, so a byte-level pre-check on the
// wire bytes is a bypass rather than an optimisation.
func TestValidateMCPHeaders_MetaVersionCannotHideFromTheCrossCheck(t *testing.T) {
	backslash := string(rune(92))
	cases := []struct {
		name string
		body string
	}{
		{
			// The key spelled with a unicode escape for '_': the bytes carry
			// no "_meta", the decoded key is exactly that.
			name: "escape-encoded _meta key",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","` +
				backslash + `u005fmeta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
		},
		{
			// A case variant, which a struct-decoding upstream matches to
			// the canonical field.
			name: "case-variant _Meta key",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","_Meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
		},
		{
			name: "case-variant protocol version key",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","_meta":{"IO.MODELCONTEXTPROTOCOL/PROTOCOLVERSION":"2025-11-25"}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := headerReq(t, tc.body, map[string]string{
				mcpProtocolVersionHeader: "2026-07-28",
				mcpMethodHeader:          "tools/call",
				mcpNameHeader:            "deploy",
			})
			require.Nil(t, req.MCPDescriptor.ParseErr)
			require.Equal(t, "2025-11-25", req.MCPDescriptor.Calls[0].MetaProtocolVersion,
				"the parser must resolve the key the same way the upstream decoder will")

			d := validateMCPHeaders(req, req.MCPDescriptor)
			require.NotNil(t, d, "a body declaring a different revision must be refused")
			assert.Equal(t, headerMismatchVersion, d.MatchedRule)
		})
	}
}

// A header sent twice is a header two readers can disagree about: Get
// returns the first, and a downstream taking the last or the joined value
// acts on something else.
func TestValidateMCPHeaders_DuplicateHeaderValuesDeny(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/mcp/gateway/", strings.NewReader(toolsCallBody))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(mcpProtocolVersionHeader, "2026-07-28")
	httpReq.Header.Add(mcpMethodHeader, "tools/call")
	httpReq.Header.Add(mcpMethodHeader, "tools/list")
	httpReq.Header.Set(mcpNameHeader, "deploy")

	req := &logical.Request{
		Path:          "mcp/gateway/",
		Operation:     logical.UpdateOperation,
		HTTPRequest:   httpReq,
		MCPDescriptor: synthesizeMCPDescriptorFromBody([]byte(toolsCallBody)),
	}

	d := validateMCPHeaders(req, req.MCPDescriptor)
	require.NotNil(t, d, "the first value matching must not rescue a second that does not")
	assert.Equal(t, headerMismatchDuplicate, d.MatchedRule)
}

// A non-object _meta, or a version that is not a string, declares nothing
// readable — nothing downstream reads it as a version either, so it is
// treated as absent rather than as a new reason to refuse legacy bodies.
func TestExtractMetaProtocolVersion_UnreadableShapesAreAbsent(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","_meta":"not-an-object"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","_meta":{"io.modelcontextprotocol/protocolVersion":7}}}`,
	} {
		reqs, err := ParseJSONRPCStrict([]byte(body))
		require.Nil(t, err, "body must still parse: %s", body)
		assert.Empty(t, reqs[0].MetaProtocolVersion)
	}
}

// The type split at the deny-wrapping site is the interception point the
// whole rendering decision hangs on: both refusals arrive as a deny
// MCPDecision, and if a header mismatch were wrapped as ErrMCPPolicyDenied
// the HTTP layer would answer with the OAuth-shaped 403 — telling a
// dual-era client to downgrade rather than to fix its headers. Nothing else
// covers it, so assert the discrimination directly.
func TestMCPHeaderMismatchError_IsDistinguishableFromAPolicyDeny(t *testing.T) {
	req := headerReq(t, toolsCallBody, map[string]string{
		mcpProtocolVersionHeader: "2026-07-28",
		mcpMethodHeader:          "tools/list",
	})
	decision := &logical.MCPDecision{
		Decision: "deny",
		RuleType: mcpRuleTypeHeaderMismatch,
	}

	wrapped := multierror.Append(nil, mcpHeaderMismatchError(req, decision))

	var headerErr *ErrMCPHeaderMismatch
	require.True(t, errors.As(wrapped, &headerErr), "must survive the multierror wrapping the handler applies")
	assert.Equal(t, "1", string(headerErr.RawID), "the id must reach the renderer to be echoed")
	assert.True(t, headerErr.IDPresent)

	var policyErr *ErrMCPPolicyDenied
	assert.False(t, errors.As(wrapped, &policyErr),
		"a header mismatch must not also satisfy the policy-deny branch, which is checked second")

	// Both still unwrap to the shared permission-denied sentinel, so every
	// existing errors.Is call site keeps working.
	assert.ErrorIs(t, wrapped, sdklogical.ErrPermissionDenied)
}

// A notification carries no id, and the renderer needs to know that rather
// than echo an empty value.
func TestMCPHeaderMismatchError_NotificationCarriesNoID(t *testing.T) {
	req := headerReq(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{
		mcpProtocolVersionHeader: "2026-07-28",
		mcpMethodHeader:          "tools/call",
	})

	err := mcpHeaderMismatchError(req, &logical.MCPDecision{Decision: "deny", RuleType: mcpRuleTypeHeaderMismatch})

	assert.False(t, err.IDPresent)
	assert.Empty(t, err.RawID)
}
