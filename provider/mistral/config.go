package mistral

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/stephnangue/warden/framework"
)

// DefaultMistralURL is the default Mistral API base URL
const DefaultMistralURL = "https://api.mistral.ai"

// DefaultMistralTimeout is the default request timeout for AI inference
const DefaultMistralTimeout = 120 * time.Second

// ProviderConfig holds parsed configuration for the Mistral provider
type ProviderConfig struct {
	MistralURL      string
	MaxBodySize     int64
	Timeout         time.Duration
	TransparentMode bool
	AutoAuthPath    string
	DefaultRole     string
}

// parseConfig parses configuration from mount config (map[string]any from JSON)
func parseConfig(conf map[string]any) ProviderConfig {
	config := ProviderConfig{
		MistralURL:  DefaultMistralURL,
		MaxBodySize: framework.DefaultMaxBodySize,
		Timeout:     DefaultMistralTimeout,
	}

	if addr, ok := conf["mistral_url"].(string); ok && addr != "" {
		config.MistralURL = addr
	}

	// Parse max_body_size — handle various JSON number types
	if maxSize, ok := conf["max_body_size"]; ok {
		switch v := maxSize.(type) {
		case int:
			if v > 0 {
				config.MaxBodySize = int64(v)
			}
		case int64:
			if v > 0 {
				config.MaxBodySize = v
			}
		case float64:
			if v > 0 {
				config.MaxBodySize = int64(v)
			}
		case json.Number:
			if parsed, err := v.Int64(); err == nil && parsed > 0 {
				config.MaxBodySize = parsed
			}
		case string:
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
				config.MaxBodySize = parsed
			}
		}
	}

	// Parse timeout — handle duration string or number
	if timeout, ok := conf["timeout"]; ok {
		switch v := timeout.(type) {
		case string:
			if parsed, err := time.ParseDuration(v); err == nil {
				config.Timeout = parsed
			}
		case int:
			if v > 0 {
				config.Timeout = time.Duration(v) * time.Second
			}
		case float64:
			if v > 0 {
				config.Timeout = time.Duration(v) * time.Second
			}
		}
	}

	// Parse transparent mode settings
	if tm, ok := conf["transparent_mode"].(bool); ok {
		config.TransparentMode = tm
	}
	if aap, ok := conf["auto_auth_path"].(string); ok {
		config.AutoAuthPath = aap
	}
	if dr, ok := conf["default_role"].(string); ok {
		config.DefaultRole = dr
	}

	return config
}

// ValidateConfig validates provider-level configuration
func ValidateConfig(conf map[string]any) error {
	// mistral_url is optional (defaults to api.mistral.ai), but if provided must be valid
	if addr, ok := conf["mistral_url"].(string); ok && addr != "" {
		if err := validateMistralAddress(addr); err != nil {
			return err
		}
	}

	// Validate max_body_size if provided
	if maxSize, ok := conf["max_body_size"]; ok {
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
				return fmt.Errorf("max_body_size must be an integer, got json.Number that can't be parsed: %w", err)
			}
			size = parsed
		case string:
			parsed, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("max_body_size must be an integer, got string that can't be parsed: %w", err)
			}
			size = parsed
		default:
			return fmt.Errorf("max_body_size must be an integer, got %T", maxSize)
		}
		if size < 0 {
			return fmt.Errorf("max_body_size must be greater than 0")
		}
		if size > 104857600 { // 100MB
			return fmt.Errorf("max_body_size must not exceed 104857600 bytes (100MB)")
		}
	}

	// Validate timeout if provided
	if timeout, ok := conf["timeout"]; ok {
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
	}

	// Validate transparent_mode
	if tm, ok := conf["transparent_mode"]; ok {
		if _, ok := tm.(bool); !ok {
			return fmt.Errorf("transparent_mode must be a boolean")
		}
	}

	// Validate auto_auth_path
	if aap, ok := conf["auto_auth_path"]; ok {
		if _, ok := aap.(string); !ok {
			return fmt.Errorf("auto_auth_path must be a string")
		}
	}

	// Validate default_role
	if dr, ok := conf["default_role"]; ok {
		if _, ok := dr.(string); !ok {
			return fmt.Errorf("default_role must be a string")
		}
	}

	return nil
}

// validateMistralAddress validates that the mistral_url is a well-formed HTTPS URL
func validateMistralAddress(addr string) error {
	if addr == "" {
		return nil // Empty means use default
	}

	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid mistral_url: %w", err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("mistral_url must use https:// scheme, got: %s", parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("mistral_url must include a host")
	}

	return nil
}
