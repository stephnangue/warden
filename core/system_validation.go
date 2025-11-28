package core

import (
	"fmt"
	"strings"
)

// ValidateMountPath performs custom validation for mount paths
func ValidateMountPath(path string) error {
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
