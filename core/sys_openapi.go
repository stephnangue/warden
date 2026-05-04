package core

import (
	"context"
	"fmt"
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
	if err := framework.DocumentPathsWithMountPrefix(b.Backend, "sys/", doc); err != nil {
		b.logger.Warn("openapi: failed to document system backend", logger.Err(err))
	}

	// 2. Walk every framework-based mount in the caller's namespace.
	if err := b.core.router.WalkFrameworkBackends(ctx, func(prefix string, backend *framework.Backend) bool {
		if err := framework.DocumentPathsWithMountPrefix(backend, prefix, doc); err != nil {
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
			return logical.ErrorResponse(fmt.Errorf("path %q not found in schema", pathFilter)), nil
		}
		doc = projected
	}

	return b.respondSuccess(map[string]any{"openapi": doc}), nil
}

// projectOASToPath returns a new OASDocument containing only the operation
// matching `path`. Several common spellings are tried (with/without leading or
// trailing slash) so callers don't have to reason about path normalization.
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
			out := framework.NewOASDocument(doc.Info.Version)
			out.Info = doc.Info
			out.Paths[c] = item
			return out
		}
	}
	return nil
}

