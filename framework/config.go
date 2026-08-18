package framework

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxBodySizeLimit is the maximum allowed value for max_body_size (100MB).
	MaxBodySizeLimit = 104857600
)

// ParseMaxBodySize extracts max_body_size from config.
// Handles int, int64, float64, json.Number, and string.
// Returns DefaultMaxBodySize if missing or invalid.
func ParseMaxBodySize(conf map[string]any) int64 {
	maxSize, ok := conf["max_body_size"]
	if !ok {
		return DefaultMaxBodySize
	}
	switch v := maxSize.(type) {
	case int:
		if v > 0 {
			return int64(v)
		}
	case int64:
		if v > 0 {
			return v
		}
	case float64:
		if v > 0 {
			return int64(v)
		}
	case json.Number:
		if parsed, err := v.Int64(); err == nil && parsed > 0 {
			return parsed
		}
	case string:
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultMaxBodySize
}

// ParseTimeout extracts timeout from config.
// Handles string (duration format) and int/float64 (seconds).
// Returns defaultTimeout if missing or invalid.
func ParseTimeout(conf map[string]any, defaultTimeout time.Duration) time.Duration {
	timeout, ok := conf["timeout"]
	if !ok {
		return defaultTimeout
	}
	switch v := timeout.(type) {
	case string:
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			return parsed
		}
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case float64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return defaultTimeout
}

// ParseTLSConfig extracts tls_skip_verify and ca_data from config.
func ParseTLSConfig(conf map[string]any) (tlsSkipVerify bool, caData string) {
	if v, ok := conf["tls_skip_verify"]; ok {
		switch b := v.(type) {
		case bool:
			tlsSkipVerify = b
		case string:
			tlsSkipVerify = b == "true" || b == "1"
		}
	}
	if v, ok := conf["ca_data"].(string); ok {
		caData = v
	}
	return
}

// GetConfigString extracts a string value from config with a default.
func GetConfigString(conf map[string]any, key, defaultValue string) string {
	if v, ok := conf[key].(string); ok && v != "" {
		return v
	}
	return defaultValue
}

// ValidateAllowedKeys checks that all keys in conf are in the allowed set.
func ValidateAllowedKeys(conf map[string]any, allowed ...string) error {
	allowedSet := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		allowedSet[k] = true
	}
	for key := range conf {
		if !allowedSet[key] {
			sort.Strings(allowed)
			return fmt.Errorf("unknown configuration key: %s (allowed: %s)", key, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// ValidateMaxBodySize validates that max_body_size is a valid integer within bounds.
func ValidateMaxBodySize(conf map[string]any) error {
	maxSize, ok := conf["max_body_size"]
	if !ok {
		return nil
	}
	var size int64
	switch v := maxSize.(type) {
	case int:
		size = int64(v)
	case int64:
		size = v
	case float64:
		size = int64(v)
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			return fmt.Errorf("max_body_size must be an integer: %w", err)
		}
		size = parsed
	case string:
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("max_body_size must be an integer: %w", err)
		}
		size = parsed
	default:
		return fmt.Errorf("max_body_size must be an integer, got %T", maxSize)
	}
	if size <= 0 {
		return fmt.Errorf("max_body_size must be greater than 0")
	}
	if size > MaxBodySizeLimit {
		return fmt.Errorf("max_body_size must not exceed %d bytes (100MB)", MaxBodySizeLimit)
	}
	return nil
}

// ValidateTimeout validates that timeout is a valid duration string or integer.
func ValidateTimeout(conf map[string]any) error {
	timeout, ok := conf["timeout"]
	if !ok {
		return nil
	}
	switch v := timeout.(type) {
	case string:
		if _, err := time.ParseDuration(v); err != nil {
			return fmt.Errorf("invalid timeout format: %w (expected format: '30s', '5m', '1h')", err)
		}
	case int:
		if v < 0 {
			return fmt.Errorf("timeout must be greater than 0 seconds")
		}
	case float64:
		if v < 0 {
			return fmt.Errorf("timeout must be greater than 0 seconds")
		}
	default:
		return fmt.Errorf("timeout must be a duration string (e.g., '30s') or integer (seconds)")
	}
	return nil
}

// ValidateTLSConfig validates tls_skip_verify and ca_data fields.
func ValidateTLSConfig(conf map[string]any) error {
	if v, ok := conf["tls_skip_verify"]; ok {
		switch v := v.(type) {
		case bool:
			// valid
		case string:
			if v != "true" && v != "false" && v != "1" && v != "0" {
				return fmt.Errorf("tls_skip_verify must be a boolean, got string: %s", v)
			}
		default:
			return fmt.Errorf("tls_skip_verify must be a boolean, got %T", v)
		}
	}
	if v, ok := conf["ca_data"]; ok {
		caStr, ok := v.(string)
		if !ok {
			return fmt.Errorf("ca_data must be a string")
		}
		if caStr != "" {
			pemBytes, err := base64.StdEncoding.DecodeString(caStr)
			if err != nil {
				return fmt.Errorf("ca_data is not valid base64: %w", err)
			}
			block, _ := pem.Decode(pemBytes)
			if block == nil {
				return fmt.Errorf("ca_data contains no valid PEM data")
			}
		}
	}
	return nil
}

// ValidateURL validates that a URL is well-formed with an https:// scheme.
// When tlsSkipVerify is true, http:// is also accepted for dev/test environments.
// urlKey is used in error messages (e.g., "scaleway_url", "openai_url").
func ValidateURL(addr string, urlKey string, tlsSkipVerify bool) error {
	if addr == "" {
		return nil
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", urlKey, err)
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme == "http" && tlsSkipVerify {
			// Allow HTTP when TLS verification is disabled (dev/test)
		} else {
			return fmt.Errorf("%s must use https:// scheme, got: %s", urlKey, parsed.Scheme)
		}
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", urlKey)
	}
	return nil
}

// ValidateStringField validates that a config field, if present, is a string.
func ValidateStringField(conf map[string]any, key string) error {
	if v, ok := conf[key]; ok {
		if _, ok := v.(string); !ok {
			return fmt.Errorf("%s must be a string", key)
		}
	}
	return nil
}

// ValidateCommonConfig validates the fields common to all providers:
// max_body_size, timeout, auto_auth_path, and default_role.
func ValidateCommonConfig(conf map[string]any) error {
	if err := ValidateMaxBodySize(conf); err != nil {
		return err
	}
	if err := ValidateTimeout(conf); err != nil {
		return err
	}
	if err := ValidateStringField(conf, "auto_auth_path"); err != nil {
		return err
	}
	return ValidateStringField(conf, "default_role")
}

// ValidateUserAuthConfig validates the secondary (user) transparent-auth config
// fields: user_auth_path and user_auth_role. It enforces their types and the
// user_auth_role → user_auth_path dependency (a role is meaningless without a
// path and would otherwise be silently discarded). The bearer-format requirement
// on the referenced mount (the user leg cannot carry an X.509 client
// certificate) is enforced at runtime, where mount visibility exists — config
// validation here has none.
//
// A persisted user_token_header from a pre-0.20 config is tolerated and ignored:
// the user credential now always rides Authorization, decided by request
// transport rather than mount config.
func ValidateUserAuthConfig(conf map[string]any) error {
	if err := ValidateStringField(conf, "user_auth_path"); err != nil {
		return err
	}
	if err := ValidateStringField(conf, "user_auth_role"); err != nil {
		return err
	}

	path, _ := conf["user_auth_path"].(string)

	if role, _ := conf["user_auth_role"].(string); role != "" && path == "" {
		return fmt.Errorf("user_auth_role requires user_auth_path")
	}

	return nil
}
