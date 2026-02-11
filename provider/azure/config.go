package azure

import (
	"encoding/json"
	"strconv"
	"time"
)

// ProviderConfig holds parsed configuration for the Azure provider
type ProviderConfig struct {
	AllowedHosts    []string
	MaxBodySize     int64
	Timeout         time.Duration
	TransparentMode bool
	AutoAuthPath    string
	DefaultRole     string
}

// Default values
const (
	DefaultMaxBodySize = int64(10485760) // 10MB
	DefaultTimeout     = 30 * time.Second
)

// DefaultAllowedHosts are the standard Azure endpoints that are allowed by default
var DefaultAllowedHosts = []string{
	"management.azure.com",
	"graph.microsoft.com",
	".vault.azure.net",
	".blob.core.windows.net",
	".queue.core.windows.net",
	".table.core.windows.net",
	".file.core.windows.net",
	".dfs.core.windows.net",
}

// parseConfig parses configuration from mount config (map[string]any from JSON)
func parseConfig(conf map[string]any) ProviderConfig {
	config := ProviderConfig{
		AllowedHosts: DefaultAllowedHosts,
		MaxBodySize:  DefaultMaxBodySize,
		Timeout:      DefaultTimeout,
	}

	// Parse allowed_hosts - handle various JSON array types
	if hosts, ok := conf["allowed_hosts"]; ok {
		switch v := hosts.(type) {
		case []string:
			if len(v) > 0 {
				config.AllowedHosts = v
			}
		case []any:
			parsed := make([]string, 0, len(v))
			for _, h := range v {
				if s, ok := h.(string); ok {
					parsed = append(parsed, s)
				}
			}
			if len(parsed) > 0 {
				config.AllowedHosts = parsed
			}
		}
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

	// Parse transparent_mode
	if tm, ok := conf["transparent_mode"]; ok {
		switch v := tm.(type) {
		case bool:
			config.TransparentMode = v
		case string:
			config.TransparentMode = v == "true"
		}
	}

	// Parse auto_auth_path
	if aap, ok := conf["auto_auth_path"].(string); ok {
		config.AutoAuthPath = aap
	}

	// Parse default_role
	if dr, ok := conf["default_role"].(string); ok {
		config.DefaultRole = dr
	}

	return config
}
