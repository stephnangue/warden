package httpproxy

import (
	"time"

	"github.com/stephnangue/warden/framework"
)

// BaseConfig holds the standard parsed configuration fields shared by all httpproxy providers.
type BaseConfig struct {
	ProviderURL     string
	MaxBodySize     int64
	Timeout         time.Duration
	AutoAuthPath    string
	DefaultAuthRole string
	TLSSkipVerify   bool
	CAData          string // base64-encoded PEM CA certificate
}

// ParseConfig parses standard configuration fields from a mount config map.
// urlKey is the provider-specific config key for the URL (e.g., "openai_url").
func ParseConfig(conf map[string]any, urlKey string, defaultURL string, defaultTimeout time.Duration) BaseConfig {
	tlsSkipVerify, caData := framework.ParseTLSConfig(conf)
	return BaseConfig{
		ProviderURL:     framework.GetConfigString(conf, urlKey, defaultURL),
		MaxBodySize:     framework.ParseMaxBodySize(conf),
		Timeout:         framework.ParseTimeout(conf, defaultTimeout),
		AutoAuthPath:    framework.GetConfigString(conf, "auto_auth_path", ""),
		DefaultAuthRole: framework.GetConfigString(conf, "default_role", ""),
		TLSSkipVerify:   tlsSkipVerify,
		CAData:          caData,
	}
}

// ValidateConfig validates the standard configuration fields.
// urlKey is the provider-specific config key for the URL (e.g., "openai_url").
func ValidateConfig(conf map[string]any, urlKey string) error {
	skipVerify, _ := framework.ParseTLSConfig(conf)

	if addr, ok := conf[urlKey].(string); ok && addr != "" {
		if err := framework.ValidateURL(addr, urlKey, skipVerify); err != nil {
			return err
		}
	}

	if err := framework.ValidateCommonConfig(conf); err != nil {
		return err
	}

	return framework.ValidateTLSConfig(conf)
}
