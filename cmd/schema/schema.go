// Package schema implements `warden schema`, the agent-facing introspection
// command. It hits the server endpoint at /v1/sys/schema (shipped in PR 4)
// and projects the OpenAPI doc into a shape friendly for both agents and
// humans.
package schema

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listAll bool
	raw     bool

	SchemaCmd = &cobra.Command{
		Use:           "schema [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Inspect the OpenAPI schema of the running server",
		Long: `
Usage: warden schema PATH        # describe a single path
       warden schema --list      # enumerate every path

  Hits the server's /v1/sys/schema endpoint and projects the OpenAPI
  document into a shape that's easy for both humans and agents to read.

  By default, "warden schema PATH" returns a friendly shape:
    { path, methods, description, parameters, response_schema, auth_required }

  Pass -raw to emit the underlying OpenAPI fragment instead. This is
  useful for consumers that already speak OpenAPI (Stainless, openapi-typescript,
  oapi-codegen, etc.).

  Examples:

    Describe a single path:

      $ warden schema sys/auth

    Enumerate every available path (NDJSON):

      $ warden schema --list

    Get the raw OpenAPI fragment for tooling consumption:

      $ warden schema sys/auth -raw

  The endpoint is namespace-scoped: -namespace (or WARDEN_NAMESPACE)
  controls which mounts are visible, so a tenant cannot enumerate other
  tenants' backends. Authentication is required (set WARDEN_TOKEN, an mTLS
  client cert, or pass an Authorization: Bearer JWT).
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runSchema,
	}
)

func init() {
	SchemaCmd.Flags().BoolVar(&listAll, "list", false, "List every path in the schema (NDJSON-friendly)")
	SchemaCmd.Flags().BoolVar(&raw, "raw", false, "Emit the raw OpenAPI fragment instead of the friendly projection")
}

func runSchema(cmd *cobra.Command, args []string) error {
	if listAll && len(args) > 0 {
		return fmt.Errorf("--list cannot be combined with a PATH argument: %w", helpers.ErrInvalidInput)
	}
	if !listAll && len(args) == 0 {
		return fmt.Errorf("schema requires a PATH (or --list to enumerate every path): %w", helpers.ErrInvalidInput)
	}
	if listAll {
		return runList()
	}
	return runSingle(args[0])
}

// runSingle queries /v1/sys/schema?path=<path> and renders the projection.
// Leading and trailing slashes are tolerated since OAS path keys carry a
// leading "/" — agents shouldn't have to reason about that form.
func runSingle(path string) error {
	path = strings.Trim(path, "/")
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	doc, err := fetchSchema(map[string][]string{"path": {path}})
	if err != nil {
		return err
	}

	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		return fmt.Errorf("path %q not found in schema: %w", path, helpers.ErrNotFound)
	}

	// The server projection returns at most one path. Pick whatever key it used.
	var key string
	var item map[string]any
	for k, v := range paths {
		key = k
		item, _ = v.(map[string]any)
		break
	}

	if raw {
		return helpers.RenderMap(map[string]any{
			"path":    key,
			"openapi": item,
		}, func() {
			// In table mode -raw still prints valid JSON so the output
			// stays useful for tools like Stainless / openapi-typescript
			// that consume schema fragments via shell pipes.
			b, err := json.MarshalIndent(map[string]any{key: item}, "", "  ")
			if err != nil {
				fmt.Printf("(error marshaling raw fragment: %v)\n", err)
				return
			}
			fmt.Println(string(b))
		})
	}

	components, _ := doc["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	projected := projectPath(key, item, schemas)
	return helpers.RenderMap(projected, func() {
		printFriendlyTable(projected)
	})
}

// runList enumerates every path in the doc and emits NDJSON-friendly records.
// Default output is a sorted list of {path, methods} entries.
func runList() error {
	doc, err := fetchSchema(nil)
	if err != nil {
		return err
	}

	paths, _ := doc["paths"].(map[string]any)
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	items := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		item, _ := paths[k].(map[string]any)
		items = append(items, map[string]any{
			"path":    k,
			"methods": methodsOf(item),
		})
	}

	return helpers.RenderList(items, func() {
		for _, it := range items {
			methods := it["methods"].([]string)
			fmt.Printf("  %s (%s)\n", it["path"], strings.Join(methods, ", "))
		}
	})
}

// fetchSchema calls /v1/sys/schema with the given query params and returns
// the OpenAPI document under the "openapi" key.
//
// Uses the raw API rather than ReadWithData because the standard Vault-style
// reader silently swallows 404 (path-not-found) as "no data", which would
// hide the server's "path not found in schema" error from the classifier.
func fetchSchema(params map[string][]string) (map[string]any, error) {
	c, err := helpers.Client()
	if err != nil {
		return nil, err
	}
	resp, err := c.Operator().ReadRawWithData("sys/schema", params)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// The wrapped err preserves *api.ResponseError (when present) so
		// the central classifier can map StatusCode → exit code; this
		// covers the case where the client surfaces 404/5xx as an error
		// rather than letting us inspect resp.StatusCode below.
		return nil, fmt.Errorf("failed to fetch schema: %w", err)
	}
	if resp.StatusCode == 404 {
		// Server has the canonical "path %q not found in schema" envelope.
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %w", extractFirstError(body), helpers.ErrNotFound)
	}
	if respErr := resp.Error(); respErr != nil {
		// Non-2xx (and non-404): let the central renderer classify via the
		// preserved *api.ResponseError chain.
		return nil, respErr
	}

	resource, err := api.ParseResource(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse schema response: %w", err)
	}
	if resource == nil || resource.Data == nil {
		return nil, fmt.Errorf("server returned empty schema response: %w", helpers.ErrServer)
	}
	doc, ok := resource.Data["openapi"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("server response missing \"openapi\" field: %w", helpers.ErrServer)
	}
	return doc, nil
}

// extractFirstError pulls the first message out of warden's `{"errors":[...]}`
// envelope so the surfaced not-found error preserves the server's text.
func extractFirstError(body []byte) string {
	var env struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err == nil && len(env.Errors) > 0 {
		return env.Errors[0]
	}
	return "schema endpoint returned 404"
}

// projectPath turns one OAS path-item map into the friendly shape: methods
// list, merged parameters, the success-response schema, and the warden
// vendor-extension flags.
//
// `components` is the doc's components.schemas map (may be nil) used to
// resolve `$ref` links found in request/response body schemas.
func projectPath(path string, item map[string]any, components map[string]any) map[string]any {
	out := map[string]any{
		"path":    path,
		"methods": methodsOf(item),
	}
	if v, ok := item["x-vault-sudo"].(bool); ok && v {
		out["sudo_required"] = true
	}
	if v, ok := item["x-vault-unauthenticated"].(bool); ok && v {
		out["auth_required"] = false
	} else {
		out["auth_required"] = true
	}

	if d := pathDescription(item); d != "" {
		out["description"] = d
	}

	params := mergeParameters(item, components)
	if len(params) > 0 {
		out["parameters"] = params
	}
	if rs := successResponseSchema(item, components); rs != nil {
		out["response_schema"] = rs
	}
	return out
}

// pathDescription pulls the most useful prose out of an OAS path-item: the
// path-level description (sourced server-side from HelpSynopsis), falling
// back to the first non-empty operation summary or description. Returns "" if
// nothing is set.
func pathDescription(item map[string]any) string {
	if d, ok := item["description"].(string); ok && d != "" {
		return d
	}
	for _, m := range []string{"get", "post", "put", "patch", "delete"} {
		op, ok := item[m].(map[string]any)
		if !ok {
			continue
		}
		if s, ok := op["summary"].(string); ok && s != "" {
			return s
		}
		if d, ok := op["description"].(string); ok && d != "" {
			return d
		}
	}
	return ""
}

// methodsOf returns the HTTP methods (uppercase) defined on an OAS path-item.
func methodsOf(item map[string]any) []string {
	if item == nil {
		return nil
	}
	out := []string{}
	for _, m := range []string{"get", "post", "put", "patch", "delete", "head", "options"} {
		if _, ok := item[m]; ok {
			out = append(out, strings.ToUpper(m))
		}
	}
	return out
}

// resolveRef follows a JSON-pointer-style $ref like
// "#/components/schemas/Foo" and returns the resolved schema, or the input
// unchanged if it has no $ref. `components` is the schemas map from the
// fetched OpenAPI document.
func resolveRef(schema, components map[string]any) map[string]any {
	if schema == nil {
		return nil
	}
	ref, _ := schema["$ref"].(string)
	if ref == "" {
		return schema
	}
	const prefix = "#/components/schemas/"
	if !strings.HasPrefix(ref, prefix) {
		return schema
	}
	name := strings.TrimPrefix(ref, prefix)
	if resolved, ok := components[name].(map[string]any); ok && resolved != nil {
		return resolved
	}
	return schema
}

// mergeParameters walks every operation on the path-item and returns a
// deduplicated slice of {name, in, type, required, description} entries.
// Duplicate names from different operations are collapsed (we keep the first
// seen, which is the convention OpenAPI uses for shared parameters).
//
// Body parameters are pulled from each operation's
// requestBody.content."application/json".schema.properties; if the schema is
// a $ref it's resolved via `components` (the doc's components.schemas map).
func mergeParameters(item map[string]any, components map[string]any) []map[string]any {
	seen := map[string]bool{}
	out := []map[string]any{}

	addParam := func(p map[string]any) {
		name, _ := p["name"].(string)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		entry := map[string]any{"name": name}
		if v, ok := p["in"].(string); ok {
			entry["in"] = v
		}
		if v, ok := p["required"].(bool); ok && v {
			entry["required"] = true
		}
		if v, ok := p["description"].(string); ok && v != "" {
			entry["description"] = v
		}
		if schema, ok := p["schema"].(map[string]any); ok {
			if t, ok := schema["type"].(string); ok {
				entry["type"] = t
			}
		}
		out = append(out, entry)
	}

	// Path-level parameters apply to every operation.
	if pl, ok := item["parameters"].([]any); ok {
		for _, p := range pl {
			if pm, ok := p.(map[string]any); ok {
				addParam(pm)
			}
		}
	}

	for _, m := range []string{"get", "post", "put", "patch", "delete"} {
		op, ok := item[m].(map[string]any)
		if !ok {
			continue
		}
		if pl, ok := op["parameters"].([]any); ok {
			for _, p := range pl {
				if pm, ok := p.(map[string]any); ok {
					addParam(pm)
				}
			}
		}
		// Body parameters from requestBody.content."application/json".schema.properties.
		// The schema may be inline OR a $ref into components.schemas; resolveRef
		// handles both.
		if rb, ok := op["requestBody"].(map[string]any); ok {
			if content, ok := rb["content"].(map[string]any); ok {
				if app, ok := content["application/json"].(map[string]any); ok {
					if schema, ok := app["schema"].(map[string]any); ok {
						addBodyParams(resolveRef(schema, components), &out, seen)
					}
				}
			}
		}
	}

	return out
}

// addBodyParams turns a JSON-schema object's properties into parameter entries.
func addBodyParams(schema map[string]any, out *[]map[string]any, seen map[string]bool) {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return
	}
	required := map[string]bool{}
	if rl, ok := schema["required"].([]any); ok {
		for _, r := range rl {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	}
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		entry := map[string]any{"name": name, "in": "body"}
		if required[name] {
			entry["required"] = true
		}
		if pm, ok := props[name].(map[string]any); ok {
			if t, ok := pm["type"].(string); ok {
				entry["type"] = t
			}
			if d, ok := pm["description"].(string); ok && d != "" {
				entry["description"] = d
			}
			if v, ok := pm["x-vault-displayAttrs"].(map[string]any); ok {
				if s, ok := v["sensitive"].(bool); ok && s {
					entry["sensitive"] = true
				}
			}
		}
		*out = append(*out, entry)
	}
}

// successResponseSchema returns the 2xx response schema (preferring 200) from
// any operation on the path-item, or nil if none is described. $ref schemas
// are resolved via `components` (the doc's components.schemas map).
func successResponseSchema(item map[string]any, components map[string]any) map[string]any {
	for _, m := range []string{"get", "post", "put", "patch", "delete"} {
		op, ok := item[m].(map[string]any)
		if !ok {
			continue
		}
		responses, ok := op["responses"].(map[string]any)
		if !ok {
			continue
		}
		// Try 200 then any other 2xx.
		for _, code := range []string{"200", "201", "202", "204"} {
			r, ok := responses[code].(map[string]any)
			if !ok {
				continue
			}
			if content, ok := r["content"].(map[string]any); ok {
				if app, ok := content["application/json"].(map[string]any); ok {
					if schema, ok := app["schema"].(map[string]any); ok {
						return resolveRef(schema, components)
					}
				}
			}
		}
	}
	return nil
}

func printFriendlyTable(p map[string]any) {
	fmt.Printf("Path:             %s\n", p["path"])
	if methods, ok := p["methods"].([]string); ok {
		fmt.Printf("Methods:          %s\n", strings.Join(methods, ", "))
	}
	if d, ok := p["description"].(string); ok && d != "" {
		fmt.Printf("Description:      %s\n", d)
	}
	if v, ok := p["auth_required"].(bool); ok {
		fmt.Printf("Auth required:    %v\n", v)
	}
	if v, ok := p["sudo_required"].(bool); ok && v {
		fmt.Println("Sudo required:    true")
	}
	if params, ok := p["parameters"].([]map[string]any); ok && len(params) > 0 {
		fmt.Println("Parameters:")
		for _, pm := range params {
			req := ""
			if r, _ := pm["required"].(bool); r {
				req = " (required)"
			}
			sensitive := ""
			if s, _ := pm["sensitive"].(bool); s {
				sensitive = " [sensitive]"
			}
			t, _ := pm["type"].(string)
			in, _ := pm["in"].(string)
			fmt.Printf("  - %s [%s, %s]%s%s\n", pm["name"], in, t, req, sensitive)
			if d, ok := pm["description"].(string); ok && d != "" {
				fmt.Printf("      %s\n", d)
			}
		}
	}
}
