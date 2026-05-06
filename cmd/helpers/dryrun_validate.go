package helpers

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/stephnangue/warden/api"
)

// schemaCache memoizes the body-schema lookup for one CLI process. Most
// commands hit only one mutating endpoint per invocation, so a per-(method,
// path) cache is enough. The cache is keyed on the templated path the
// validator passes — typed commands stamp known templated paths, the generic
// `warden write` passes the literal user path.
var (
	schemaCacheMu sync.Mutex
	schemaCache   = map[string]bodySchema{}
)

// bodySchema is the resolved view of an operation's request body — properties
// keyed by name, plus the required-list and a map of allowed values for
// fields that declare an enum.
type bodySchema struct {
	properties    map[string]propertySchema // name → property
	required      map[string]bool
	knownNames    []string // sorted list, for "did you mean" suggestions
	notDocumented bool     // schema endpoint returned no body schema for this op
}

type propertySchema struct {
	typ           string // "string" | "integer" | "number" | "boolean" | "array" | "object"
	allowedValues []any
	description   string
}

// DryRun validates `payload` locally against the server-published schema for
// `method` + `path`. It is the agent-facing replacement for sending the
// request: nothing leaves the process. Returns:
//   - nil on a clean validate, after emitting a standard "validated" envelope
//     to stdout
//   - a wrapped ErrInvalidInput on validation failure, with hints
//   - a wrapped ErrServer on schema-fetch failure (network/server-side)
//
// `method` is the HTTP verb the real call would use ("POST", "PUT", "DELETE",
// etc.). `path` should be the template form when the endpoint is templated —
// e.g. "sys/cred/sources/{name}", not the concrete "sys/cred/sources/my-aws".
// The server's schema endpoint also accepts concrete paths (it does template
// matching), but typed commands know their templated form and can skip the
// fallback.
func DryRun(c *api.Client, method, path string, payload map[string]any) error {
	bs, err := loadBodySchema(c, method, path)
	if err != nil {
		return err
	}

	if bs.notDocumented {
		// Endpoint exists but its operation has no documented body schema.
		// We still ran "warden schema" above, so authn + path resolution
		// passed. Treat this as a soft success: the agent can't have got a
		// hallucinated field wrong because there's no contract to check.
		return renderDryRunSuccess(path, "no body schema documented; only path/auth validated")
	}

	if errs := validatePayload(payload, bs); len(errs) > 0 {
		return formatValidationError(errs)
	}
	return renderDryRunSuccess(path, "")
}

// loadBodySchema fetches the OpenAPI projection for `path` from the server
// and resolves the request body schema for `method`. Cached per process.
func loadBodySchema(c *api.Client, method, path string) (bodySchema, error) {
	key := strings.ToUpper(method) + " " + path

	schemaCacheMu.Lock()
	if bs, ok := schemaCache[key]; ok {
		schemaCacheMu.Unlock()
		return bs, nil
	}
	schemaCacheMu.Unlock()

	resp, err := c.Operator().ReadRawWithData("sys/schema", map[string][]string{"path": {path}})
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return bodySchema{}, fmt.Errorf("fetch schema for %q: %w", path, err)
	}
	if resp.StatusCode == 404 {
		return bodySchema{}, fmt.Errorf("schema not found for path %q (server may not document it): %w", path, ErrNotFound)
	}
	if respErr := resp.Error(); respErr != nil {
		return bodySchema{}, respErr
	}

	resource, err := api.ParseResource(resp.Body)
	if err != nil {
		return bodySchema{}, fmt.Errorf("parse schema response: %w", err)
	}
	if resource == nil || resource.Data == nil {
		return bodySchema{}, fmt.Errorf("server returned empty schema for %q: %w", path, ErrServer)
	}
	doc, _ := resource.Data["openapi"].(map[string]any)
	if doc == nil {
		return bodySchema{}, fmt.Errorf("server response missing openapi field: %w", ErrServer)
	}

	bs := extractBodySchema(doc, method)

	schemaCacheMu.Lock()
	schemaCache[key] = bs
	schemaCacheMu.Unlock()

	return bs, nil
}

// extractBodySchema walks the OpenAPI doc to the request body for `method`,
// resolves any $ref, and returns a name → propertySchema map.
func extractBodySchema(doc map[string]any, method string) bodySchema {
	out := bodySchema{notDocumented: true}

	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		return out
	}
	// Projected docs have exactly one path; pick whichever it is.
	var item map[string]any
	for _, v := range paths {
		item, _ = v.(map[string]any)
		break
	}
	if item == nil {
		return out
	}

	op, _ := item[strings.ToLower(method)].(map[string]any)
	if op == nil {
		return out
	}
	rb, _ := op["requestBody"].(map[string]any)
	if rb == nil {
		return out
	}
	content, _ := rb["content"].(map[string]any)
	if content == nil {
		return out
	}
	app, _ := content["application/json"].(map[string]any)
	if app == nil {
		return out
	}
	schema, _ := app["schema"].(map[string]any)
	if schema == nil {
		return out
	}

	components, _ := doc["components"].(map[string]any)
	componentSchemas, _ := components["schemas"].(map[string]any)
	resolved := resolveSchemaRef(schema, componentSchemas)

	props, _ := resolved["properties"].(map[string]any)
	if len(props) == 0 {
		return out
	}

	out.notDocumented = false
	out.properties = make(map[string]propertySchema, len(props))
	out.required = map[string]bool{}
	if reqd, ok := resolved["required"].([]any); ok {
		for _, r := range reqd {
			if s, ok := r.(string); ok {
				out.required[s] = true
			}
		}
	}

	for name, raw := range props {
		pm, _ := raw.(map[string]any)
		if pm == nil {
			continue
		}
		pm = resolveSchemaRef(pm, componentSchemas)
		ps := propertySchema{}
		ps.typ, _ = pm["type"].(string)
		ps.description, _ = pm["description"].(string)
		if enum, ok := pm["enum"].([]any); ok {
			ps.allowedValues = enum
		}
		out.properties[name] = ps
		out.knownNames = append(out.knownNames, name)
	}
	sort.Strings(out.knownNames)
	return out
}

// resolveSchemaRef follows a single-level $ref into components.schemas. Used
// once at body level (where the OpenAPI generator emits refs) and once per
// property (defensive: in case a future schema introduces nested refs).
func resolveSchemaRef(s, componentSchemas map[string]any) map[string]any {
	if s == nil {
		return nil
	}
	ref, _ := s["$ref"].(string)
	if ref == "" {
		return s
	}
	const prefix = "#/components/schemas/"
	if !strings.HasPrefix(ref, prefix) {
		return s
	}
	name := strings.TrimPrefix(ref, prefix)
	if resolved, ok := componentSchemas[name].(map[string]any); ok && resolved != nil {
		return resolved
	}
	return s
}

// validatePayload walks the user's payload against bs and returns a list of
// human-readable issues (one per problem) so the agent gets all the errors at
// once instead of one-at-a-time iteration.
func validatePayload(payload map[string]any, bs bodySchema) []string {
	var problems []string

	// Missing required fields.
	missing := make([]string, 0, len(bs.required))
	for name := range bs.required {
		if _, present := payload[name]; !present {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		problems = append(problems, fmt.Sprintf("required field %q is missing", name))
	}

	// Walk every payload key against the schema.
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		ps, known := bs.properties[name]
		if !known {
			suggestion := closestName(name, bs.knownNames)
			if suggestion != "" {
				problems = append(problems, fmt.Sprintf("unknown field %q (did you mean %q?)", name, suggestion))
			} else {
				problems = append(problems, fmt.Sprintf("unknown field %q", name))
			}
			continue
		}
		if msg := checkType(name, payload[name], ps); msg != "" {
			problems = append(problems, msg)
		}
		if msg := checkAllowed(name, payload[name], ps); msg != "" {
			problems = append(problems, msg)
		}
	}
	return problems
}

func checkType(name string, value any, ps propertySchema) string {
	if ps.typ == "" {
		return ""
	}
	if value == nil {
		// Accept JSON null — server may treat it as omission.
		return ""
	}
	switch ps.typ {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Sprintf("field %q expects %s; got %T", name, ps.typ, value)
		}
	case "integer", "number":
		switch value.(type) {
		case int, int64, float64:
		default:
			return fmt.Sprintf("field %q expects %s; got %T", name, ps.typ, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Sprintf("field %q expects %s; got %T", name, ps.typ, value)
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return fmt.Sprintf("field %q expects %s; got %T", name, ps.typ, value)
		}
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return fmt.Sprintf("field %q expects %s; got %T", name, ps.typ, value)
		}
	}
	return ""
}

func checkAllowed(name string, value any, ps propertySchema) string {
	if len(ps.allowedValues) == 0 || value == nil {
		return ""
	}
	for _, allowed := range ps.allowedValues {
		if allowed == value {
			return ""
		}
	}
	allowedStrs := make([]string, 0, len(ps.allowedValues))
	for _, a := range ps.allowedValues {
		allowedStrs = append(allowedStrs, fmt.Sprintf("%v", a))
	}
	return fmt.Sprintf("field %q value %v is not one of [%s]", name, value, strings.Join(allowedStrs, ", "))
}

// closestName returns the entry in `candidates` within Levenshtein distance 2
// of `target`, biased toward shorter distances. Empty when nothing matches —
// the typo is too far off to suggest with confidence.
func closestName(target string, candidates []string) string {
	target = strings.ToLower(target)
	best := ""
	bestDist := 3 // hard ceiling: only suggest within distance 2
	for _, c := range candidates {
		d := levenshtein(target, strings.ToLower(c))
		if d < bestDist {
			best = c
			bestDist = d
		}
	}
	return best
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func formatValidationError(problems []string) error {
	return fmt.Errorf("payload validation failed:\n  - %s: %w",
		strings.Join(problems, "\n  - "), ErrInvalidInput)
}

// renderDryRunSuccess emits the standard envelope and returns nil. The
// envelope is the same shape across every mutating command so agents can
// branch on it uniformly.
func renderDryRunSuccess(path, note string) error {
	data := map[string]any{
		"path":      path,
		"validated": true,
		"dry_run":   true,
	}
	if note != "" {
		data["note"] = note
	}
	return RenderMap(data, func() {
		fmt.Fprintf(outWriter, "dry-run OK: payload validates for %s (no request sent)\n", path)
		if note != "" {
			fmt.Fprintf(outWriter, "  note: %s\n", note)
		}
	})
}

// ResetSchemaCache clears the per-process schema cache. Intended for tests.
func ResetSchemaCache() {
	schemaCacheMu.Lock()
	defer schemaCacheMu.Unlock()
	schemaCache = map[string]bodySchema{}
}

// IsValidationError reports whether err originated from local payload
// validation (vs a network/server problem). Used by tests; callers that just
// want to surface the error to the user can rely on the central renderer.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidInput)
}
