package dualgateway

import (
	"time"

	"github.com/stephnangue/warden/framework"
)

// providerConfig holds parsed configuration for a dual-gateway provider.
type providerConfig struct {
	ProviderURL   string
	MaxBodySize   int64
	Timeout       time.Duration
	TLSSkipVerify bool
	CAData        string
}

func parseConfig(spec *ProviderSpec, conf map[string]any) providerConfig {
	tlsSkipVerify, caData := framework.ParseTLSConfig(conf)
	return providerConfig{
		ProviderURL:   framework.GetConfigString(conf, spec.URLConfigKey, spec.DefaultURL),
		MaxBodySize:   framework.ParseMaxBodySize(conf),
		Timeout:       framework.ParseTimeout(conf, spec.DefaultTimeout),
		TLSSkipVerify: tlsSkipVerify,
		CAData:        caData,
	}
}

// validateConfig validates provider configuration using the spec's URL key.
func validateConfig(spec *ProviderSpec, config map[string]any) error {
	allowedKeys := []string{
		spec.URLConfigKey, "max_body_size", "timeout", "auto_auth_path", "default_role",
		"tls_skip_verify", "ca_data",
	}
	allowedKeys = append(allowedKeys, spec.ExtraConfigKeys...)
	if err := framework.ValidateAllowedKeys(config, allowedKeys...); err != nil {
		return err
	}

	skipVerify, _ := framework.ParseTLSConfig(config)
	if addr, ok := config[spec.URLConfigKey].(string); ok && addr != "" {
		if err := framework.ValidateURL(addr, spec.URLConfigKey, skipVerify); err != nil {
			return err
		}
	}

	if err := framework.ValidateCommonConfig(config); err != nil {
		return err
	}
	return framework.ValidateTLSConfig(config)
}
