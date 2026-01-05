package credential

import (
	"fmt"
	"strconv"
	"time"
)

// ConfigHelpers provides utility functions for parsing credential source config values
// Since all config values are stored as strings, drivers need to parse them to their expected types

// GetString returns the string value for a config key, or defaultValue if not found
func GetString(config map[string]string, key string, defaultValue string) string {
	if val, ok := config[key]; ok {
		return val
	}
	return defaultValue
}

// GetStringRequired returns the string value for a config key, or an error if not found
func GetStringRequired(config map[string]string, key string) (string, error) {
	if val, ok := config[key]; ok && val != "" {
		return val, nil
	}
	return "", fmt.Errorf("required config key '%s' not found or empty", key)
}

// GetInt returns the integer value for a config key, or defaultValue if not found or invalid
func GetInt(config map[string]string, key string, defaultValue int) int {
	if val, ok := config[key]; ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultValue
}

// GetIntRequired returns the integer value for a config key, or an error if not found or invalid
func GetIntRequired(config map[string]string, key string) (int, error) {
	val, ok := config[key]
	if !ok {
		return 0, fmt.Errorf("required config key '%s' not found", key)
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("config key '%s' must be an integer: %w", key, err)
	}
	return i, nil
}

// GetInt64 returns the int64 value for a config key, or defaultValue if not found or invalid
func GetInt64(config map[string]string, key string, defaultValue int64) int64 {
	if val, ok := config[key]; ok {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

// GetBool returns the boolean value for a config key, or defaultValue if not found or invalid
// Accepts: "true", "false", "1", "0", "yes", "no", "on", "off" (case-insensitive)
func GetBool(config map[string]string, key string, defaultValue bool) bool {
	if val, ok := config[key]; ok {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return defaultValue
}

// GetBoolRequired returns the boolean value for a config key, or an error if not found or invalid
func GetBoolRequired(config map[string]string, key string) (bool, error) {
	val, ok := config[key]
	if !ok {
		return false, fmt.Errorf("required config key '%s' not found", key)
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return false, fmt.Errorf("config key '%s' must be a boolean: %w", key, err)
	}
	return b, nil
}

// GetDuration returns the duration value for a config key, or defaultValue if not found or invalid
// Accepts duration strings like "30s", "5m", "1h", etc.
func GetDuration(config map[string]string, key string, defaultValue time.Duration) time.Duration {
	if val, ok := config[key]; ok {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultValue
}

// GetDurationRequired returns the duration value for a config key, or an error if not found or invalid
func GetDurationRequired(config map[string]string, key string) (time.Duration, error) {
	val, ok := config[key]
	if !ok {
		return 0, fmt.Errorf("required config key '%s' not found", key)
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("config key '%s' must be a valid duration: %w", key, err)
	}
	return d, nil
}

// ValidateRequired checks that all required config keys are present and non-empty
// Returns an error listing all missing keys if any are not found
func ValidateRequired(config map[string]string, requiredKeys ...string) error {
	var missing []string
	for _, key := range requiredKeys {
		if val, ok := config[key]; !ok || val == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config keys: %v", missing)
	}
	return nil
}
