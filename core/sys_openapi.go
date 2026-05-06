package core

import (
	"context"
	"regexp"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathOpenAPI registers the OpenAPI document endpoints. The Vault-compatible
// alias `internal/specs/openapi` is included so existing Vault/OpenBao tooling
// (codegen, SDK generators) keeps working unchanged. `schema` is the
// agent-friendly alias documented in the warden CLI.
//
// Both endpoints are namespace-scoped: the response only includes mounts
// reachable in the caller's namespace (X-Warden-Namespace), so a tenant
// cannot enumerate another tenant's backends through the schema surface.
func (b *SystemBackend) pathOpenAPI() []*framework.Path {
	pathField := map[string]*framework.FieldSchema{
		"path": {
			Type:        framework.TypeString,
			Description: "Optional. Restrict the response to a single OpenAPI path (e.g. \"aws/config\").",
			Query:       true,
		},
	}

	return []*framework.Path{
		{
			Pattern: "internal/specs/openapi",
			Fields:  pathField,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleOpenAPI,
				},
			},
			HelpSynopsis:    "Generate the OpenAPI document for the running server (caller's namespace only).",
			HelpDescription: "Returns an OpenAPI 3.0 document describing every backend mounted in the caller's namespace, plus the system backend. Pass `?path=PATH` to project to a single operation.",
		},
		{
			Pattern: "schema",
			Fields:  pathField,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleOpenAPI,
				},
			},
			HelpSynopsis:    "Agent-friendly alias for internal/specs/openapi.",
			HelpDescription: "Same content as `sys/internal/specs/openapi` — exposed as `sys/schema` for ergonomics.",
		},
	}
}

// handleOpenAPI assembles a namespace-scoped OpenAPI document. It documents:
//  1. The system backend itself (which hosts this handler and is not in the
//     mount table; without this, sys/* paths would be missing entirely).
//  2. Every framework-based mount reachable in the caller's namespace.
//
// If the caller passes ?path=<path>, the response is projected to just that
// operation — the agent-friendly path for `warden schema PATH`.
func (b *SystemBackend) handleOpenAPI(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Info.Version is left empty: warden has no clean dependency from core
	// onto cmd (where the build version is set), and agents that need version
	// comparison should look at the server build SHA via /sys/health instead.
	doc := framework.NewOASDocument("")

	// 1. Document the system backend itself. It hosts this handler and is
	//    NOT in the router's mount table, so the walker below would miss it.
	//    The system backend has no streaming paths so DocumentPathsWithMountPrefix
	//    is sufficient.
	if err := framework.DocumentPathsWithMountPrefix(b.Backend, "sys/", doc); err != nil {
		b.logger.Warn("openapi: failed to document system backend", logger.Err(err))
	}

	// 2. Walk every framework-based mount in the caller's namespace. Use
	//    DocumentMount because mounts arrive as wrappers (e.g. *awsBackend
	//    embedding *StreamingBackend) — DocumentMount extracts the inner
	//    *framework.Backend regardless of the wrapper chain. StreamingPaths
	//    (gateway proxies) are intentionally not documented; see the
	//    DocumentMount doc comment for why.
	if err := b.core.router.WalkFrameworkBackends(ctx, func(prefix string, backend logical.Backend) bool {
		if err := framework.DocumentMount(backend, prefix, doc); err != nil {
			b.logger.Warn("openapi: failed to document mount", logger.String("mount", prefix), logger.Err(err))
		}
		return true
	}); err != nil {
		return nil, err
	}

	// 3. Optional projection to a single path.
	if pathFilter, _ := d.Get("path").(string); pathFilter != "" {
		projected := projectOASToPath(doc, pathFilter)
		if projected == nil {
			// Use a CodedError so the response gets HTTP 404 (the CLI
			// classifier maps that to ExitNotFound / "not_found").
			return logical.ErrorResponse(logical.ErrNotFoundf("path %q not found in schema", pathFilter)), nil
		}
		doc = projected
	}

	return b.respondSuccess(map[string]any{"openapi": doc}), nil
}

// projectOASToPath returns a new OASDocument containing only the operation
// matching `path`. Several common spellings are tried (with/without leading or
// trailing slash) and, as a fallback, OpenAPI-style templated keys
// (`/foo/{name}`) are matched against concrete inputs (`foo/my-thing`) so
// callers don't have to know the placeholder names.
//
// Component schemas referenced by `$ref` from the path-item are also copied
// into the projected doc so consumers can resolve request/response bodies
// without needing the full document.
//
// Returns nil if no spelling matches.
func projectOASToPath(doc *framework.OASDocument, path string) *framework.OASDocument {
	if doc == nil {
		return nil
	}
	candidates := []string{
		path,
		"/" + strings.TrimPrefix(path, "/"),
		strings.TrimSuffix(path, "/"),
		"/" + strings.TrimPrefix(strings.TrimSuffix(path, "/"), "/"),
	}
	for _, c := range candidates {
		if item, ok := doc.Paths[c]; ok {
			return projectSinglePath(doc, c, item)
		}
	}

	// Fall back to template matching: a doc path of "/foo/{name}/bar" matches
	// the concrete input "foo/my-thing/bar". Without this, agents writing
	// "warden schema sys/cred/sources/my-aws" would 404 because the OAS doc
	// keys the entry under "/sys/cred/sources/{name}".
	norm := "/" + strings.TrimPrefix(strings.TrimSuffix(path, "/"), "/")
	for templ, item := range doc.Paths {
		if !strings.Contains(templ, "{") {
			continue
		}
		if templateMatches(templ, norm) {
			return projectSinglePath(doc, templ, item)
		}
	}
	return nil
}

// projectSinglePath builds a one-path projection doc, copying the referenced
// component schemas so $ref-described bodies resolve.
func projectSinglePath(doc *framework.OASDocument, key string, item *framework.OASPathItem) *framework.OASDocument {
	out := framework.NewOASDocument(doc.Info.Version)
	out.Info = doc.Info
	out.Paths[key] = item
	copyReferencedSchemas(item, doc.Components.Schemas, out.Components.Schemas)
	return out
}

// templateMatches reports whether `concrete` is matched by an OpenAPI-style
// templated path. `{name}` placeholders accept any non-slash run of characters,
// matching how warden's router treats path segments.
func templateMatches(templ, concrete string) bool {
	parts := strings.Split(templ, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			parts[i] = `[^/]+`
		} else {
			parts[i] = regexp.QuoteMeta(p)
		}
	}
	re, err := regexp.Compile("^" + strings.Join(parts, "/") + "$")
	if err != nil {
		return false
	}
	return re.MatchString(concrete)
}

// copyReferencedSchemas walks `item` recursively, finds every `$ref` of the
// form "#/components/schemas/<name>", and copies the corresponding schema
// from `from` into `to`. Already-copied schemas are not re-walked, so cycles
// terminate.
func copyReferencedSchemas(item *framework.OASPathItem, from, to map[string]*framework.OASSchema) {
	if item == nil || from == nil || to == nil {
		return
	}
	for _, op := range []*framework.OASOperation{item.Get, item.Post, item.Delete} {
		if op == nil {
			continue
		}
		copyOperationRefs(op, from, to)
	}
}

func copyOperationRefs(op *framework.OASOperation, from, to map[string]*framework.OASSchema) {
	if op == nil {
		return
	}
	if op.RequestBody != nil {
		walkContentRefs(op.RequestBody.Content, from, to)
	}
	for _, resp := range op.Responses {
		if resp == nil {
			continue
		}
		walkContentRefs(resp.Content, from, to)
	}
}

func walkContentRefs(content framework.OASContent, from, to map[string]*framework.OASSchema) {
	for _, mt := range content {
		if mt == nil || mt.Schema == nil {
			continue
		}
		walkSchemaRefs(mt.Schema, from, to)
	}
}

func walkSchemaRefs(s *framework.OASSchema, from, to map[string]*framework.OASSchema) {
	if s == nil {
		return
	}
	if s.Ref != "" {
		const prefix = "#/components/schemas/"
		if name, ok := strings.CutPrefix(s.Ref, prefix); ok {
			if _, already := to[name]; !already {
				if ref, ok := from[name]; ok && ref != nil {
					to[name] = ref
					// Recurse into the referenced schema in case it
					// itself $refs other components.
					walkSchemaRefs(ref, from, to)
					for _, prop := range ref.Properties {
						walkSchemaRefs(prop, from, to)
					}
					if ref.Items != nil {
						walkSchemaRefs(ref.Items, from, to)
					}
				}
			}
		}
	}
	for _, prop := range s.Properties {
		walkSchemaRefs(prop, from, to)
	}
	if s.Items != nil {
		walkSchemaRefs(s.Items, from, to)
	}
}

