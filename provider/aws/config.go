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
	if domains, ok := conf["proxy_domains"].([]interface{}); ok {
		config.ProxyDomains = make([]string, 0, len(domains))
		for _, d := range domains {
			if domain, ok := d.(string); ok {
				config.ProxyDomains = append(config.ProxyDomains, domain)
			}
		}
	}

	// Parse max_body_size
	maxBodySize := int64(10485760)
	if maxSize, ok := conf["max_body_size"].(int64); ok {
		maxBodySize = maxSize
	} else if maxSize, ok := conf["max_body_size"].(int); ok {
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
	config.Timeout = timeOut

	return config
}
