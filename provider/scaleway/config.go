package scaleway

import (
	"time"

	"github.com/stephnangue/warden/framework"
)

// DefaultScalewayURL is the default Scaleway API base URL (global endpoint)
const DefaultScalewayURL = "https://api.scaleway.com"

// DefaultScalewayTimeout is the default request timeout for Scaleway API calls
const DefaultScalewayTimeout = 30 * time.Second

// ProviderConfig holds parsed configuration
type ProviderConfig struct {
	ScalewayURL   string
	MaxBodySize   int64
	Timeout       time.Duration
	TLSSkipVerify bool
	CAData        string
}

func parseConfig(conf map[string]any) ProviderConfig {
	tlsSkipVerify, caData := framework.ParseTLSConfig(conf)
	return ProviderConfig{
		ScalewayURL:   framework.GetConfigString(conf, "scaleway_url", DefaultScalewayURL),
		MaxBodySize:   framework.ParseMaxBodySize(conf),
		Timeout:       framework.ParseTimeout(conf, DefaultScalewayTimeout),
		TLSSkipVerify: tlsSkipVerify,
		CAData:        caData,
	}
}

// ValidateConfig validates Scaleway provider-specific configuration
func ValidateConfig(config map[string]any) error {
	if err := framework.ValidateAllowedKeys(config,
		"scaleway_url", "max_body_size", "timeout", "auto_auth_path", "default_role",
		"tls_skip_verify", "ca_data"); err != nil {
		return err
	}

	skipVerify, _ := framework.ParseTLSConfig(config)
	if addr, ok := config["scaleway_url"].(string); ok && addr != "" {
		if err := framework.ValidateURL(addr, "scaleway_url", skipVerify); err != nil {
			return err
		}
	}

	if err := framework.ValidateCommonConfig(config); err != nil {
		return err
	}
	return framework.ValidateTLSConfig(config)
}
