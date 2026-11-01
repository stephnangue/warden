package core

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// SystemBackend implements logical.Backend using the framework pattern
type SystemBackend struct {
	*framework.Backend
	core   *Core
	logger *logger.GatedLogger

	// mcpHandler is the MCP discovery server (sys/mcp), built once, on first
	// use, by discoveryMCP.
	mcpOnce    sync.Once
	mcpHandler http.Handler
}

// NewSystemBackend creates a new system backend using framework.Backend
func NewSystemBackend(core *Core, log *logger.GatedLogger) *SystemBackend {
	b := &SystemBackend{
		core:   core,
		logger: log,
	}

	b.Backend = &framework.Backend{
		Help:         systemBackendHelp,
		BackendType:  "system",
		BackendClass: logical.ClassSystem,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"init",
				"health",
			},
			// Discovery: authorized on the presented credential, with no role,
			// under the built-in policies (logical.Paths.Identity).
			Identity: []string{
				"introspect/roles",
				"mcp",
				// The sponsor surface: tickets only (isSponsorPath), outside
				// identity/entity/, whose paths are root paths.
				"identity/sponsor/*",
			},
			// The discovery server reads its JSON-RPC body raw, under the MCP
			// gate, and writes its own response, a notification stream
			// included (logical.Paths.Stream). It proxies nothing and, being
			// an identity path, mints nothing.
			Stream: []string{
				"mcp",
			},
			Root: []string{
				"auth/*",
				"cred/*",
				"audit/*",
				"audit-hash/*",
				"dev/*",
				"roles",
				"roles/*",
				// The group, entity and lookup paths: identity/usage is a
				// normal ACL path.
				"identity/group",
				"identity/group/*",
				"identity/entity",
				"identity/entity/*",
				"identity/lookup",
				"step-down",
			},
		},
		Paths: b.paths(),
	}

	return b
}

// paths returns all system backend paths
func (b *SystemBackend) paths() []*framework.Path {
	paths := []*framework.Path{}

	// Provider paths
	paths = append(paths, b.pathProviders()...)

	// Auth paths
	paths = append(paths, b.pathAuth()...)

	// Role discovery from admissions and groups
	paths = append(paths, b.pathIntrospectRoles()...)

	// The MCP discovery server
	paths = append(paths, b.pathMCP()...)

	// Namespace paths
	paths = append(paths, b.pathNamespaces()...)

	// Credential paths
	paths = append(paths, b.pathCredentials()...)

	// OIDC issuer (Workload Identity Federation) — root-namespace-only
	paths = append(paths, b.pathOIDCIssuer()...)

	// RFC 9728 protected resource metadata — root-namespace-only
	paths = append(paths, b.pathProtectedResource()...)

	// Skill registry paths
	paths = append(paths, b.pathSkills()...)

	// Policy paths
	paths = append(paths, b.pathPolicies()...)

	// Namespace roles
	paths = append(paths, b.pathRoles()...)

	// Namespace groups
	paths = append(paths, b.pathIdentityGroups()...)

	// Namespace entities and their native identities
	paths = append(paths, b.pathIdentityEntities()...)

	// The sponsors' own paths on the entities they sponsor
	paths = append(paths, b.pathIdentitySponsor()...)

	// Audit paths
	paths = append(paths, b.pathAudit()...)
	paths = append(paths, b.pathAuditHash()...)

	// OpenAPI / schema endpoint (agent-facing introspection)
	paths = append(paths, b.pathOpenAPI()...)

	// Dev playground: present only on a server started with -dev-playground.
	paths = append(paths, b.pathDev()...)

	// HA leadership
	paths = append(paths, b.pathStepDown()...)

	return paths
}

// respondSuccess creates a success response with data
func (b *SystemBackend) respondSuccess(data map[string]any) *logical.Response {
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       data,
	}
}

// respondCreated creates a success response for resource creation
func (b *SystemBackend) respondCreated(data map[string]any) *logical.Response {
	return &logical.Response{
		StatusCode: http.StatusCreated,
		Data:       data,
	}
}

// ValidateMountPath performs custom validation for mount paths
func ValidateMountPath(path string) error {
	// Strip trailing slash for validation (paths typically end with /)
	path = strings.TrimSuffix(path, "/")

	// Validate path doesn't contain reserved system patterns
	reservedPaths := []string{"sys", "auth", "audit"}
	for _, reserved := range reservedPaths {
		if strings.HasPrefix(path, reserved) {
			return fmt.Errorf("path cannot start with reserved prefix: %s", reserved)
		}
	}

	// Validate path doesn't contain transparent mode reserved words
	// These paths are used for loginless/JWT-based authentication: role/{role}/gateway/...
	// We check for path segments to avoid false positives (e.g., "myrole" should be allowed)
	transparentReservedWords := []string{"role", "gateway"}
	pathSegments := strings.Split(path, "/")
	for _, segment := range pathSegments {
		for _, reserved := range transparentReservedWords {
			if segment == reserved {
				return fmt.Errorf("path cannot contain reserved transparent mode segment: %s", reserved)
			}
		}
	}

	// Ensure path doesn't start with special characters
	if strings.HasPrefix(path, "-") || strings.HasPrefix(path, "_") {
		return fmt.Errorf("path cannot start with hyphen or underscore")
	}

	return nil
}

const systemBackendHelp = `
The system backend provides endpoints for managing Warden's core functionality.

This includes:
- Provider management (enable, disable, configure)
- Auth method management (enable, disable, configure)
- Namespace management (create, list, delete)
- Credential management (sources and specs)
- Policy management (create, list, delete)
- Role management (create, read, update, delete, list)
- Group management (create, read, update, delete, list)
- System initialization and management
`
