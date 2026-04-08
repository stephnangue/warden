package azure

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/stephnangue/warden/framework"
)

// ProviderConfig holds parsed configuration for the Azure provider
type ProviderConfig struct {
	MaxBodySize     int64
	Timeout         time.Duration
	AutoAuthPath    string
	DefaultAuthRole string
	TLSSkipVerify   bool
	CAData          string
}

// parseConfig parses configuration from mount config (map[string]any from JSON)
func parseConfig(conf map[string]any) ProviderConfig {
	config := ProviderConfig{
		MaxBodySize: framework.DefaultMaxBodySize,
		Timeout:     framework.DefaultTimeout,
	}

	// Parse max_body_size - handle various JSON number types
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

	// Parse timeout - handle duration string or number
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

	// Parse auto_auth_path
	if aap, ok := conf["auto_auth_path"].(string); ok {
		config.AutoAuthPath = aap
	}

	// Parse default_role
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
