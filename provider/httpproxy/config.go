package httpproxy

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/stephnangue/warden/framework"
)

// BaseConfig holds the standard parsed configuration fields shared by all httpproxy providers.
type BaseConfig struct {
	ProviderURL     string
	MaxBodySize     int64
	Timeout         time.Duration
	AutoAuthPath    string
	DefaultAuthRole string
	TLSSkipVerify   bool
	CAData          string // base64-encoded PEM CA certificate
}

// ParseConfig parses standard configuration fields from a mount config map.
// urlKey is the provider-specific config key for the URL (e.g., "openai_url").
func ParseConfig(conf map[string]any, urlKey string, defaultURL string, defaultTimeout time.Duration) BaseConfig {
	config := BaseConfig{
		ProviderURL: defaultURL,
		MaxBodySize: framework.DefaultMaxBodySize,
		Timeout:     defaultTimeout,
	}

	if addr, ok := conf[urlKey].(string); ok && addr != "" {
		config.ProviderURL = addr
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

	// Parse auth settings
	if aap, ok := conf["auto_auth_path"].(string); ok {
		config.AutoAuthPath = aap
	}
	if dr, ok := conf["default_role"].(string); ok {
		config.DefaultAuthRole = dr
	}

	// Parse TLS settings
	if v, ok := conf["tls_skip_verify"]; ok {
		switch b := v.(type) {
		case bool:
			config.TLSSkipVerify = b
		case string:
			config.TLSSkipVerify = b == "true" || b == "1"
		}
	}
	if v, ok := conf["ca_data"].(string); ok {
		config.CAData = v
	}

	return config
}

// ValidateConfig validates the standard configuration fields.
// urlKey is the provider-specific config key for the URL (e.g., "openai_url").
func ValidateConfig(conf map[string]any, urlKey string) error {
	// Validate URL if provided
	if addr, ok := conf[urlKey].(string); ok && addr != "" {
		if err := ValidateURL(addr, urlKey); err != nil {
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

	// Validate tls_skip_verify
	if v, ok := conf["tls_skip_verify"]; ok {
		switch v.(type) {
		case bool:
			// valid
		case string:
			s := v.(string)
			if s != "true" && s != "false" && s != "1" && s != "0" {
				return fmt.Errorf("tls_skip_verify must be a boolean, got string: %s", s)
			}
		default:
			return fmt.Errorf("tls_skip_verify must be a boolean, got %T", v)
		}
	}

	// Validate ca_data
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
func ValidateURL(addr string, urlKey string) error {
	if addr == "" {
		return nil
	}

	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", urlKey, err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use https:// scheme, got: %s", urlKey, parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", urlKey)
	}

	return nil
}
