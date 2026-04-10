package aws

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/framework"
)

// ProviderConfig holds parsed configuration
type ProviderConfig struct {
	ProxyDomains  []string
	MaxBodySize   int64
	Timeout       time.Duration
	TLSSkipVerify bool
	CAData        string
}

func parseConfig(conf map[string]any) ProviderConfig {
	config := ProviderConfig{
		ProxyDomains: []string{"localhost"},
		MaxBodySize:  framework.ParseMaxBodySize(conf),
		Timeout:      framework.ParseTimeout(conf, framework.DefaultTimeout),
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

	config.TLSSkipVerify, config.CAData = framework.ParseTLSConfig(conf)

	return config
}

// ValidateConfig validates AWS provider-specific configuration
func ValidateConfig(config map[string]any) error {
	if err := framework.ValidateAllowedKeys(config,
		"proxy_domains", "max_body_size", "timeout", "tls_skip_verify", "ca_data",
		"auto_auth_path", "default_role"); err != nil {
		return err
	}

	// Validate proxy_domains
	if domains, ok := config["proxy_domains"]; ok {
		switch v := domains.(type) {
		case []any:
			for i, d := range v {
				if _, ok := d.(string); !ok {
					return fmt.Errorf("proxy_domains[%d] must be a string", i)
				}
			}
		case []string:
		default:
			return fmt.Errorf("proxy_domains must be an array of strings")
		}
	}

	if err := framework.ValidateCommonConfig(config); err != nil {
		return err
	}

	return framework.ValidateTLSConfig(config)
}
