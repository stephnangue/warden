package core

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// SystemBackend implements logical.Backend using the framework pattern
type SystemBackend struct {
	*framework.Backend
	core   *Core
	logger *logger.GatedLogger
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
			Root: []string{
				"auth/*",
				"cred/*",
			},
		},
		Paths:        b.paths(),
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

	// Namespace paths
	paths = append(paths, b.pathNamespaces()...)

	// Credential paths
	paths = append(paths, b.pathCredentials()...)

	// Policy paths
	paths = append(paths, b.pathPolicies()...)

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
- System initialization and management
`
