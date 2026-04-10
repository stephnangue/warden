package azure

import (
	"time"

	"github.com/stephnangue/warden/framework"
)

// ProviderConfig holds parsed configuration for the Azure provider
type ProviderConfig struct {
	MaxBodySize     int64
	Timeout         time.Duration
	AutoAuthPath    string
	DefaultAuthRole string
	TLSSkipVerify   bool
	CAData          string
}

// parseConfig parses configuration from mount config (map[string]any from JSON)
func parseConfig(conf map[string]any) ProviderConfig {
	tlsSkipVerify, caData := framework.ParseTLSConfig(conf)
	return ProviderConfig{
		MaxBodySize:     framework.ParseMaxBodySize(conf),
		Timeout:         framework.ParseTimeout(conf, framework.DefaultTimeout),
		AutoAuthPath:    framework.GetConfigString(conf, "auto_auth_path", ""),
		DefaultAuthRole: framework.GetConfigString(conf, "default_role", ""),
		TLSSkipVerify:   tlsSkipVerify,
		CAData:          caData,
	}
}
