package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// parseDurationFromSeconds parses a time.Duration from a JSON value representing seconds.
// The server sends duration as seconds (int64) via TypeDurationSecond.
// Handles json.Number (from UseNumber()), float64, int64, and string duration formats.
func parseDurationFromSeconds(v any) time.Duration {
	switch val := v.(type) {
	case float64:
		return time.Duration(int64(val)) * time.Second
	case json.Number:
		if n, err := val.Int64(); err == nil {
			return time.Duration(n) * time.Second
		}
	case string:
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	case int64:
		return time.Duration(val) * time.Second
	}
	return 0
}

// configValueToString converts various types from JSON to string representation.
// This ensures all config values remain as strings even if the server returns typed values.
func configValueToString(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case json.Number:
		return val.String()
	case bool:
		return strconv.FormatBool(val)
	case float64:
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", val)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprint(val)
	}
}

// parseConfigMap converts a map[string]interface{} (from JSON) to map[string]string.
// Returns nil if the input is nil or not the expected type.
func parseConfigMap(v any) map[string]string {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, val := range m {
		result[k] = configValueToString(val)
	}
	return result
}
