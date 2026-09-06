// Package mcpfilter rewrites MCP JSON-RPC list responses so that only the
// items a policy allows remain. It handles the three name-bearing list
// methods — tools/list, resources/list, prompts/list — for both the
// application/json and text/event-stream (SSE) shapes that MCP Streamable
// HTTP returns.
//
// The package is pure mechanics: it holds no policy state and takes a
// keep-predicate supplied by the caller. Policy semantics (which names are
// allowed) live in the core policy layer; this package only drops array
// elements the predicate rejects and re-serialises the envelope.
//
// Fail-closed contract: a body that cannot be parsed as the expected
// list-result shape returns an error so the gateway can refuse to stream
// it, rather than leaking an unfiltered (e.g. still-compressed) list.
package mcpfilter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// listFamily binds a list method to the result array key it returns and the
// per-item field that carries the name matched by the call-time policy gate.
// The name fields mirror the strict parser's call-side extraction:
// tools/call → params.name, resources/read → params.uri, prompts/get →
// params.name, so a list item is filtered by the same field the gate reads.
type listFamily struct {
	arrayKey  string
	nameField string
}

var listFamilies = map[string]listFamily{
	"tools/list":     {arrayKey: "tools", nameField: "name"},
	"resources/list": {arrayKey: "resources", nameField: "uri"},
	"prompts/list":   {arrayKey: "prompts", nameField: "name"},
}

// cacheScope is the result field by which a server tells intermediaries
// whether its answer may be shared. "public" explicitly authorises a shared
// cache to serve the same bytes to anyone.
const (
	cacheScopeKey     = "cacheScope"
	cacheScopePrivate = "private"
)

// FilterListResponse rewrites a list-method response body, dropping items
// whose name the keep predicate rejects.
//
//   - out is always the bytes the caller should send: the filtered body when
//     changed is true, or the original body unchanged when changed is false.
//     The caller must write out (it has already consumed the source stream).
//   - changed reports whether the body was rewritten — an item removed, or
//     a cacheScope narrowed to "private". The second counts even when
//     nothing was dropped: a listing pruned for one principal is not the
//     document another would get, so a shared cache must not be told it is.
//   - err is non-nil only when the body cannot be parsed as the expected
//     list-result shape. The caller must fail closed (never stream the
//     original) on an error, because an unparseable body cannot be proven
//     free of denied items.
//
// listMethod must be one of tools/list, resources/list, prompts/list — the
// only methods for which the core policy layer attaches a filter. An unknown
// method is treated as a fail-closed error.
func FilterListResponse(listMethod, contentType string, body []byte, keep func(name string) bool) (out []byte, changed bool, err error) {
	fam, ok := listFamilies[strings.ToLower(listMethod)]
	if !ok {
		return nil, false, fmt.Errorf("mcpfilter: unsupported list method %q", listMethod)
	}
	if isEventStream(contentType) {
		return filterSSE(body, fam, keep)
	}
	return filterJSON(body, fam, keep)
}

// isEventStream reports whether the content type is text/event-stream,
// ignoring any parameters (charset, boundary) and case.
func isEventStream(contentType string) bool {
	ct := contentType
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

// filterJSON handles an application/json JSON-RPC response.
func filterJSON(body []byte, fam listFamily, keep func(string) bool) ([]byte, bool, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		// Not a JSON object — could be a batch array, a compressed body,
		// or garbage. We cannot prove it carries no denied items. Fail closed.
		return nil, false, fmt.Errorf("mcpfilter: response is not a JSON object: %w", err)
	}

	resultRaw, ok := env["result"]
	if !ok {
		// No result (e.g. a JSON-RPC error response). Nothing to leak.
		return body, false, nil
	}

	newResult, changed, err := filterResult(resultRaw, fam, keep)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return body, false, nil
	}

	env["result"] = newResult
	out, err := json.Marshal(env)
	if err != nil {
		return nil, false, fmt.Errorf("mcpfilter: re-marshal envelope: %w", err)
	}
	return out, true, nil
}

// filterResult filters the array under fam.arrayKey inside a JSON-RPC result
// object, preserving every other field (nextCursor, ttlMs, unknown fields),
// and narrows cacheScope to "private". Returns the rewritten result and
// whether either changed it.
func filterResult(resultRaw json.RawMessage, fam listFamily, keep func(string) bool) (json.RawMessage, bool, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		// result present but not an object (null, array, scalar). We expected
		// a list result and cannot verify its contents. Fail closed.
		return nil, false, fmt.Errorf("mcpfilter: result is not an object: %w", err)
	}

	// Narrow the scope before the array lookup: a result that carries a
	// cacheScope but no family array still described a per-principal answer,
	// and returning early would leave a public scope on the wire.
	scopeChanged := privatizeCacheScope(result)

	arrRaw, ok := result[fam.arrayKey]
	if !ok {
		// Result carries no array for this family — nothing to filter.
		if !scopeChanged {
			return nil, false, nil
		}
		newResult, err := json.Marshal(result)
		if err != nil {
			return nil, false, fmt.Errorf("mcpfilter: re-marshal result: %w", err)
		}
		return newResult, true, nil
	}

	var items []json.RawMessage
	if err := json.Unmarshal(arrRaw, &items); err != nil {
		return nil, false, fmt.Errorf("mcpfilter: %s is not an array: %w", fam.arrayKey, err)
	}

	kept := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		name, ok := itemName(item, fam.nameField)
		if !ok {
			// An item whose name cannot be read cannot be proven allowed;
			// drop it (fail closed) rather than expose an unverifiable entry.
			continue
		}
		if keep(name) {
			kept = append(kept, item)
		}
	}

	if len(kept) == len(items) && !scopeChanged {
		return nil, false, nil
	}

	if len(kept) != len(items) {
		newArr, err := json.Marshal(kept)
		if err != nil {
			return nil, false, fmt.Errorf("mcpfilter: re-marshal %s: %w", fam.arrayKey, err)
		}
		result[fam.arrayKey] = newArr
	}
	newResult, err := json.Marshal(result)
	if err != nil {
		return nil, false, fmt.Errorf("mcpfilter: re-marshal result: %w", err)
	}
	return newResult, true, nil
}

// privatizeCacheScope rewrites a result's cacheScope to "private", reporting
// whether it changed anything.
//
// The listing this result carries was pruned for one principal, so it is not
// the same document another principal would get. An upstream that marked it
// "public" was describing its own unfiltered answer and is authorising shared
// intermediaries to serve it to anyone. Warden creates the variance, so
// Warden marks it.
//
// A rewrite counts as a change even when no item was dropped: "nothing was
// dropped for THIS principal" is not "this document is the same for
// everyone", and the whole point is to stop a shared cache assuming the
// latter.
//
// The field is never added when the upstream omitted it. Inventing one would
// put a field on the wire the server never sent, which strict clients are
// entitled to object to, and an absent cacheScope already means the
// conservative thing.
func privatizeCacheScope(result map[string]json.RawMessage) bool {
	raw, ok := result[cacheScopeKey]
	if !ok {
		return false
	}
	var scope string
	if err := json.Unmarshal(raw, &scope); err != nil {
		// Not a string. Leave it alone rather than guess at a shape the
		// spec does not define; the Cache-Control header still applies.
		return false
	}
	if scope == cacheScopePrivate {
		return false
	}
	result[cacheScopeKey] = json.RawMessage(`"` + cacheScopePrivate + `"`)
	return true
}

// itemName extracts the string value of nameField from a list item. Returns
// ok=false when the field is absent or not a string.
func itemName(item json.RawMessage, nameField string) (string, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(item, &obj); err != nil {
		return "", false
	}
	raw, ok := obj[nameField]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// filterSSE handles a text/event-stream response. MCP Streamable HTTP returns
// a request's response as one or more SSE events whose data payload is the
// JSON-RPC message. Events whose data parses to a JSON-RPC result carrying the
// family array are filtered; every other event (notifications, pings, control
// frames) passes through untouched. When no event is filterable the original
// body is returned unchanged.
func filterSSE(body []byte, fam listFamily, keep func(string) bool) ([]byte, bool, error) {
	// Normalise CRLF so event splitting is uniform; the rewritten output uses
	// LF framing, which is spec-legal.
	norm := strings.ReplaceAll(string(body), "\r\n", "\n")
	blocks := strings.Split(norm, "\n\n")

	anyChanged := false
	for i, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}
		newBlock, changed, err := filterSSEBlock(block, fam, keep)
		if err != nil {
			return nil, false, err
		}
		if changed {
			blocks[i] = newBlock
			anyChanged = true
		}
	}
	if !anyChanged {
		return body, false, nil
	}
	return []byte(strings.Join(blocks, "\n\n")), true, nil
}

// filterSSEBlock rewrites a single SSE event block. Non-data lines are kept in
// order; the run of data lines is replaced by a single data line carrying the
// filtered JSON. A block whose data does not parse as a JSON-RPC result with
// the family array is returned unchanged (it is not this method's response).
func filterSSEBlock(block string, fam listFamily, keep func(string) bool) (string, bool, error) {
	lines := strings.Split(block, "\n")
	var other []string
	var data strings.Builder
	hasData := false
	for _, line := range lines {
		if strings.HasPrefix(line, "data:") {
			hasData = true
			payload := strings.TrimPrefix(line, "data:")
			payload = strings.TrimPrefix(payload, " ")
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(payload)
			continue
		}
		other = append(other, line)
	}
	if !hasData {
		return block, false, nil
	}

	// Only attempt to filter data that looks like a JSON object carrying a
	// result. Anything else is a different event type and passes through.
	raw := []byte(data.String())
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return block, false, nil
	}
	if _, ok := env["result"]; !ok {
		return block, false, nil
	}
	newResult, changed, err := filterResult(env["result"], fam, keep)
	if err != nil {
		return "", false, err
	}
	if !changed {
		return block, false, nil
	}
	env["result"] = newResult
	newData, err := json.Marshal(env)
	if err != nil {
		return "", false, fmt.Errorf("mcpfilter: re-marshal sse data: %w", err)
	}

	var out bytes.Buffer
	for _, l := range other {
		out.WriteString(l)
		out.WriteByte('\n')
	}
	out.WriteString("data: ")
	out.Write(newData)
	return out.String(), true, nil
}
