// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"encoding/base64"
	"strings"

	"github.com/stephnangue/warden/logical"
)

// MCP transport headers. From 2026-07-28 a client sends the protocol
// revision on every request, plus a duplicate of the method it is calling and
// — for the name-bearing methods — the name it is calling it on.
const (
	mcpProtocolVersionHeader = "MCP-Protocol-Version"
	mcpMethodHeader          = "Mcp-Method"
	mcpNameHeader            = "Mcp-Name"
)

// mcpRevisionHeaderEra is the first revision that requires the transport
// headers. Revisions are dates, so an ordinary string comparison orders them.
const mcpRevisionHeaderEra = "2026-07-28"

// base64Sentinel wraps a header value whose true content is not
// header-safe — a tool name carrying non-ASCII, say. The markers are exact
// and lowercase.
const (
	base64SentinelPrefix = "=?base64?"
	base64SentinelSuffix = "?="
)

// validateMCPHeaders enforces the spec's requirement that a server which
// processes the message body MUST validate that the transport headers match
// that body, rejecting a mismatch.
//
// Warden processes the body, so this is its rule to keep. The security case
// is the mirrored-copy problem: the headers duplicate exactly the fields
// Warden judges, so any component behind Warden that routes or authorises on
// headers would otherwise act on input Warden never evaluated.
//
// Returns nil when the request is consistent — or when it is from an era
// these rules do not govern. Those exemptions are fail-open by construction,
// so each one is narrow and deliberate:
//
//   - No version header, or one older than the header era: the headers are
//     not REQUIRED, because demanding them would brick every pre-2026-07-28
//     upstream Warden fronts. A header that is nonetheless present is still
//     held to the body. That split is deliberate: requiring headers is
//     compatibility, matching them is security, and only the first is
//     era-dependent. Skipping the match for a client that omits a version
//     header would leave the whole check bypassable by omission.
//   - A batch body: one header cannot describe several calls, so there is
//     nothing coherent to compare against.
//   - A notification: the spec leaves header rules for a body with no id
//     undefined, so presence is not required. A mismatch is still refused.
func validateMCPHeaders(req *logical.Request, desc *logical.MCPRequestDescriptor) *logical.MCPDecision {
	if req == nil || req.HTTPRequest == nil || desc == nil || len(desc.Calls) == 0 {
		return nil
	}

	// A header sent twice is a header two readers can disagree about: Get
	// returns the first, and a downstream taking the last or the joined value
	// acts on something else. Nothing legitimate sends these twice.
	for _, h := range []string{mcpProtocolVersionHeader, mcpMethodHeader, mcpNameHeader} {
		if len(req.HTTPRequest.Header.Values(h)) > 1 {
			return mcpHeaderDeny(headerMismatchDuplicate)
		}
	}

	version := strings.TrimSpace(req.HTTPRequest.Header.Get(mcpProtocolVersionHeader))
	headerMethod := req.HTTPRequest.Header.Get(mcpMethodHeader)
	rawHeaderName := req.HTTPRequest.Header.Get(mcpNameHeader)

	// A batch has no single method or name for a header to describe. Skipping
	// the check would leave the mirrored-copy problem permanently open for
	// batch traffic, which the legacy era keeps accepting — so a batch that
	// carries these headers at all is refused rather than forwarded with
	// claims nobody checked.
	if len(desc.Calls) > 1 {
		if headerMethod != "" || rawHeaderName != "" {
			return mcpHeaderDeny(headerMismatchBatch)
		}
		return nil
	}

	call := desc.Calls[0]

	// The version decides only whether the headers are REQUIRED. Whether the
	// ones actually sent must agree with the body is not a question of era: a
	// mismatch is never legitimate, and a client that sends a header at all
	// has volunteered it for checking. Reading "skip everything for a legacy
	// client" as skipping the match too would leave the mirrored-copy problem
	// wide open to anyone who simply omits a version header.
	modern := isHeaderEraRevision(version) && call.IDPresent

	if headerMethod == "" {
		if modern {
			return mcpHeaderDeny(headerMismatchMethod)
		}
	} else if headerMethod != call.Method {
		// Case-sensitive: the spec defines method names as case-sensitive,
		// and this compares a header against the body rather than against a
		// policy pattern. Warden's own gate lowercases so a case-mismatch
		// cannot route around policy; here, a difference in case IS the
		// disagreement being detected.
		return mcpHeaderDeny(headerMismatchMethod)
	}

	if requiresNameHeader(strings.ToLower(call.Method)) {
		if rawHeaderName == "" {
			if modern {
				return mcpHeaderDeny(headerMismatchName)
			}
		} else if !headerNameMatches(rawHeaderName, call.Name) {
			return mcpHeaderDeny(headerMismatchName)
		}
	}

	// The body may declare its own revision in params._meta, and when it does
	// that declaration is what a downstream reads to decide which protocol it
	// is speaking. So the transport must agree with it — and must be there to
	// agree: a body claiming a revision while the transport claims none is a
	// modern request wearing legacy clothes, which is exactly how a client
	// would buy itself the leniency the era split grants.
	if call.MetaProtocolVersion != "" && call.MetaProtocolVersion != version {
		return mcpHeaderDeny(headerMismatchVersion)
	}

	return nil
}

// Which half of the check refused, for the audit record. These are a closed
// set of constants, never anything read off the wire, so recording one
// carries no adversary-controlled bytes and gives an operator the detail the
// client response deliberately withholds.
const (
	headerMismatchMethod    = "method"
	headerMismatchName      = "name"
	headerMismatchVersion   = "version"
	headerMismatchDuplicate = "duplicate_header"
	headerMismatchBatch     = "batch_headers"
)

// mcpHeaderDeny builds the refusal. Beyond the rule type it carries only the
// closed-set reason above: naming the header value, or quoting what
// disagreed, would put adversary-controlled bytes into operator-visible
// output and hand a caller a probe for the shape of the check. Same
// fingerprint hygiene the other structural denies keep.
func mcpHeaderDeny(reason string) *logical.MCPDecision {
	return &logical.MCPDecision{
		Decision:    "deny",
		RuleType:    mcpRuleTypeHeaderMismatch,
		MatchedRule: reason,
	}
}

// requiresNameHeader reports whether the spec expects an Mcp-Name header for
// this method.
//
// Deliberately NOT isNameBearingMethod. That one answers the policy layer's
// question — which methods carry a name a contract gates — and includes
// resources/subscribe, whose URI answers to the same grant a read does. The
// transport header set is a different set of three. Conflating them would
// demand a header no client sends (the go-sdk's Subscribe sends Mcp-Method
// and no Mcp-Name), refusing every modern resources/subscribe as a mismatch.
// What policy gates and what the transport declares are separate questions
// that merely overlap.
func requiresNameHeader(method string) bool {
	switch method {
	case mcpMethodToolsCall, mcpMethodResourcesRead, mcpMethodPromptsGet:
		return true
	}
	return false
}

// mcpHeaderMismatchError builds the typed error the HTTP layer renders,
// recovering the request id from the descriptor. The id is read here rather
// than carried on the decision so MCPDecision stays free of
// adversary-controlled bytes.
func mcpHeaderMismatchError(req *logical.Request, decision *logical.MCPDecision) *ErrMCPHeaderMismatch {
	err := &ErrMCPHeaderMismatch{Decision: decision}
	if req != nil && req.MCPDescriptor != nil && len(req.MCPDescriptor.Calls) == 1 {
		call := req.MCPDescriptor.Calls[0]
		err.RawID = call.RawID
		err.IDPresent = call.IDPresent
	}
	return err
}

// isHeaderEraRevision reports whether a protocol version string names a
// revision at or after the one that introduced the transport headers.
//
// Revisions are ISO dates, so string ordering is date ordering. A value that
// is not shaped like one is not treated as modern: it is a client Warden
// cannot place, and reading an unparseable version as "latest" would impose
// requirements on traffic that may be far older.
func isHeaderEraRevision(version string) bool {
	if !isRevisionDate(version) {
		return false
	}
	return version >= mcpRevisionHeaderEra
}

func isRevisionDate(s string) bool {
	if len(s) != len("2026-07-28") {
		return false
	}
	for i, c := range s {
		switch i {
		case 4, 7:
			if c != '-' {
				return false
			}
		default:
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// headerNameMatches reports whether an Mcp-Name header describes the name in
// the body, accepting either spelling of it.
//
// The header is compared literally first, then — if that fails and the value
// wears the sentinel — as decoded base64. Accepting both is deliberate: the
// spec defines the sentinel for names that are not header-safe, while the
// go-sdk sets and compares Mcp-Name raw and reserves the sentinel for the
// Mcp-Param-* family. Insisting on either convention alone would refuse
// conforming clients of the other. Requiring only that ONE reading agrees
// costs nothing, since a caller who controls both header and body gains
// nothing by making them agree.
func headerNameMatches(header, name string) bool {
	if header == name {
		return true
	}
	decoded, ok := decodeMCPHeaderValue(header)
	return ok && decoded == name
}

// decodeMCPHeaderValue unwraps the base64 sentinel when present and returns
// the value verbatim when it is not. Reports false for a sentinel whose
// payload is not valid base64 — a value that cannot be decoded cannot be
// compared, and treating it as literal text would compare the wrapper
// instead of the name.
//
// The sentinel applies to Mcp-Name and the Mcp-Param-* family, never to
// Mcp-Method: method names are ASCII token syntax by definition.
func decodeMCPHeaderValue(v string) (string, bool) {
	if !strings.HasPrefix(v, base64SentinelPrefix) || !strings.HasSuffix(v, base64SentinelSuffix) {
		return v, true
	}
	payload := v[len(base64SentinelPrefix) : len(v)-len(base64SentinelSuffix)]
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}
