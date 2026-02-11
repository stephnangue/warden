package aws

import (
	"encoding/json"
	"strconv"
	"time"
)

// Default values
const (
	DefaultMaxBodySize = int64(10485760) // 10MB
	DefaultTimeout     = 30 * time.Second
)

// ProviderConfig holds parsed configuration
type ProviderConfig struct {
	ProxyDomains []string
	MaxBodySize  int64
	Timeout      time.Duration
}

func parseConfig(conf map[string]any) ProviderConfig {
	config := ProviderConfig{
		ProxyDomains: []string{"localhost"},
	}
	// Parse proxy_domains
	if domains, ok := conf["proxy_domains"].([]string); ok {
		config.ProxyDomains = domains
	} else if domains, ok := conf["proxy_domains"].([]any); ok {
		config.ProxyDomains = make([]string, 0, len(domains))
		for _, d := range domains {
			if domain, ok := d.(string); ok {
				config.ProxyDomains = append(config.ProxyDomains, domain)
			}
		}
	}

	// Parse max_body_size
	maxBodySize := DefaultMaxBodySize
	if maxSize, ok := conf["max_body_size"].(int64); ok && maxSize > 0 {
		maxBodySize = maxSize
	} else if maxSize, ok := conf["max_body_size"].(int); ok && maxSize > 0 {
		maxBodySize = int64(maxSize)
	} else if maxSize, ok := conf["max_body_size"].(float64); ok && maxSize > 0 {
		maxBodySize = int64(maxSize)
	} else if maxSize, ok := conf["max_body_size"].(json.Number); ok {
		// Handle json.Number type (from JSON decoder with UseNumber)
		if parsed, err := maxSize.Int64(); err == nil && parsed > 0 {
			maxBodySize = parsed
		}
	} else if maxSize, ok := conf["max_body_size"].(string); ok {
		// Handle string conversion (e.g., from JSON number stored as string)
		if parsed, err := strconv.ParseInt(maxSize, 10, 64); err == nil && parsed > 0 {
			maxBodySize = parsed
		}
	}
	config.MaxBodySize = maxBodySize

	// Parse timeout
	timeOut := DefaultTimeout
	if timeout, ok := conf["timeout"].(int); ok {
		timeOut = time.Duration(timeout) * time.Second
	} else if timeout, ok := conf["timeout"].(string); ok {
		if d, err := time.ParseDuration(timeout); err == nil {
			timeOut = d
		}
	}
	if timeOut == 0 {
		timeOut = DefaultTimeout
	}
	config.Timeout = timeOut

	return config
}
