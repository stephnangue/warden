package core

import (
	"fmt"
	"strings"
)

// ValidateMountPath performs custom validation for mount paths
func ValidateMountPath(path string) error {
	// Strip trailing slash for validation (paths typically end with /)
	path = strings.TrimSuffix(path, "/")

	// Check for nested paths (containing slashes)
	if strings.Contains(path, "/") {
		return fmt.Errorf("nested paths are not supported - path must be a single segment")
	}

	// Validate path doesn't contain reserved patterns
	reservedPaths := []string{"sys", "auth", "audit"}
	for _, reserved := range reservedPaths {
		if strings.HasPrefix(path, reserved) {
			return fmt.Errorf("path cannot start with reserved prefix: %s", reserved)
		}
	}

	// Ensure path doesn't start with special characters
	if strings.HasPrefix(path, "-") || strings.HasPrefix(path, "_") {
		return fmt.Errorf("path cannot start with hyphen or underscore")
	}

	return nil
}
