package helpers

import (
	"fmt"
	"os"
	"strings"
)

// ResolveFileRefs processes a config map and replaces values prefixed with "@"
// with the contents of the referenced file. This allows CLI users to pass file
// contents via --config=key=@/path/to/file (similar to curl's @ syntax).
func ResolveFileRefs(config map[string]string) (map[string]string, error) {
	for key, value := range config {
		if strings.HasPrefix(value, "@") {
			filePath := value[1:]
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("failed to read file for config key %q: %w", key, err)
			}
			config[key] = string(data)
		}
	}
	return config, nil
}
