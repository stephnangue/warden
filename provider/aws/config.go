package aws

import "time"

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
	maxBodySize := int64(10485760)
	if maxSize, ok := conf["max_body_size"].(int64); (ok && maxSize > 0) {
		maxBodySize = maxSize
	} else if maxSize, ok := conf["max_body_size"].(int); (ok && maxSize > 0) {
		maxBodySize = int64(maxSize)
	}
	config.MaxBodySize = maxBodySize

	// Parse timeout
	timeOut := time.Duration(30 * time.Second)
	if timeout, ok := conf["timeout"].(int); ok {
		timeOut = time.Duration(timeout) * time.Second
	} else if timeout, ok := conf["timeout"].(string); ok {
		if d, err := time.ParseDuration(timeout); err == nil {
			timeOut = d
		}
	}
	if timeOut.String() == "0s" {
		timeOut = time.Duration(30 * time.Second)
	}
	config.Timeout = timeOut

	return config
}
