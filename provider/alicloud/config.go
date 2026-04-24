package alicloud

import (
	"fmt"
	"strings"
	"time"

	"github.com/stephnangue/warden/framework"
)

// DefaultTimeout is the default request timeout for Alicloud API calls.
const DefaultTimeout = 30 * time.Second

// ProviderConfig holds parsed Alicloud provider configuration.
type ProviderConfig struct {
	// ProxyDomains is the allowlist of reverse-proxy suffixes. When Warden is
	// reached via "<real-alicloud-host>.<proxy-domain>", the suffix is stripped
	// to recover the real Alicloud target before re-signing and forwarding.
	// Hosts that are directly "*.aliyuncs.com" are always accepted regardless
	// of this list; anything else is rejected.
	ProxyDomains []string

	MaxBodySize     int64
	Timeout         time.Duration
	TLSSkipVerify   bool
	CAData          string
	AutoAuthPath    string
	DefaultAuthRole string
}

// parseConfig parses the raw config map into a ProviderConfig.
func parseConfig(conf map[string]any) ProviderConfig {
	tlsSkipVerify, caData := framework.ParseTLSConfig(conf)
	c := ProviderConfig{
		MaxBodySize:     framework.ParseMaxBodySize(conf),
		Timeout:         framework.ParseTimeout(conf, DefaultTimeout),
		TLSSkipVerify:   tlsSkipVerify,
		CAData:          caData,
		AutoAuthPath:    framework.GetConfigString(conf, "auto_auth_path", ""),
		DefaultAuthRole: framework.GetConfigString(conf, "default_role", ""),
	}

	// Parse proxy_domains. Accept both []string (internal callers) and []any
	// (typical JSON decode) forms.
	switch v := conf["proxy_domains"].(type) {
	case []string:
		c.ProxyDomains = v
	case []any:
		c.ProxyDomains = make([]string, 0, len(v))
		for _, d := range v {
			if s, ok := d.(string); ok {
				c.ProxyDomains = append(c.ProxyDomains, s)
			}
		}
	}

	return c
}

// ValidateConfig validates Alicloud provider-specific configuration.
func ValidateConfig(config map[string]any) error {
	if err := framework.ValidateAllowedKeys(config,
		"proxy_domains", "max_body_size", "timeout", "auto_auth_path", "default_role",
		"tls_skip_verify", "ca_data"); err != nil {
		return err
	}

	if domains, ok := config["proxy_domains"]; ok {
		switch v := domains.(type) {
		case []any:
			for i, d := range v {
				s, ok := d.(string)
				if !ok {
					return fmt.Errorf("proxy_domains[%d] must be a string", i)
				}
				if err := validateProxyDomain(s); err != nil {
					return fmt.Errorf("proxy_domains[%d]: %w", i, err)
				}
			}
		case []string:
			for i, s := range v {
				if err := validateProxyDomain(s); err != nil {
					return fmt.Errorf("proxy_domains[%d]: %w", i, err)
				}
			}
		default:
			return fmt.Errorf("proxy_domains must be an array of strings")
		}
	}

	if err := framework.ValidateCommonConfig(config); err != nil {
		return err
	}
	return framework.ValidateTLSConfig(config)
}

// validateProxyDomain ensures a proxy_domain entry is well-formed and doesn't
// create ambiguity with real Alicloud hostnames.
func validateProxyDomain(s string) error {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return fmt.Errorf("entry must not be empty")
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return fmt.Errorf("entry %q must not start or end with '.'", s)
	}
	if strings.Contains(s, "/") || strings.Contains(s, " ") {
		return fmt.Errorf("entry %q must be a bare DNS name", s)
	}
	// A proxy_domain that ends in .aliyuncs.com would make host resolution
	// ambiguous (real Alicloud host vs. subdomain-form host under a proxy).
	if s == "aliyuncs.com" || strings.HasSuffix(s, ".aliyuncs.com") {
		return fmt.Errorf("entry %q must not be or end with aliyuncs.com", s)
	}
	return nil
}
