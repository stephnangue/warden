package gitlab

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/stephnangue/warden/framework"
)

// ProviderConfig holds parsed configuration for the GitLab provider
type ProviderConfig struct {
	GitLabAddress string
	MaxBodySize   int64
	Timeout       time.Duration
}

// parseConfig parses configuration from mount config (map[string]any from JSON)
func parseConfig(conf map[string]any) ProviderConfig {
	config := ProviderConfig{
		MaxBodySize: framework.DefaultMaxBodySize,
		Timeout:     framework.DefaultTimeout,
	}

	if addr, ok := conf["gitlab_address"].(string); ok {
		config.GitLabAddress = addr
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

	return config
}

// ValidateConfig validates provider-level configuration
func ValidateConfig(conf map[string]any) error {
	addr, ok := conf["gitlab_address"].(string)
	if !ok || addr == "" {
		return fmt.Errorf("gitlab_address is required")
	}
	return validateGitLabAddress(addr)
}

// validateGitLabAddress validates that the gitlab_address is a well-formed URL
func validateGitLabAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("gitlab_address is required")
	}

	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid gitlab_address: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("gitlab_address must use http:// or https:// scheme, got: %s", parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("gitlab_address must include a host")
	}

	return nil
}
