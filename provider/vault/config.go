package vault

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// ProviderConfig holds parsed configuration for the Vault provider
type ProviderConfig struct {
	VaultAddress  string
	MaxBodySize   int64
	Timeout       time.Duration
	TLSSkipVerify bool
}

// Default values
const (
	DefaultMaxBodySize = int64(10485760) // 10MB
	DefaultTimeout     = 30 * time.Second
)

// parseConfig parses configuration from mount config (map[string]any from JSON)
func parseConfig(conf map[string]any) ProviderConfig {
	config := ProviderConfig{
		MaxBodySize: DefaultMaxBodySize,
		Timeout:     DefaultTimeout,
	}

	if addr, ok := conf["vault_address"].(string); ok {
		config.VaultAddress = addr
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

	// Parse tls_skip_verify
	if tlsSkip, ok := conf["tls_skip_verify"]; ok {
		switch v := tlsSkip.(type) {
		case bool:
			config.TLSSkipVerify = v
		case string:
			config.TLSSkipVerify = v == "true"
		}
	}

	return config
}

// validateVaultAddress validates that the vault_address is a well-formed URL
func validateVaultAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("vault_address is required")
	}

	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid vault_address: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("vault_address must use http:// or https:// scheme, got: %s", parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("vault_address must include a host")
	}

	return nil
}
