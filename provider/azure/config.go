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
	UserAuthPath    string
	DefaultAuthRole string
	// UserAuthRoleStored: the mount config still names the removed
	// user_auth_role (framework.HasUserAuthRole).
	UserAuthRoleStored bool
	TLSSkipVerify      bool
	CAData             string
	// AllowedHosts is the target host allowlist; empty means the default.
	AllowedHosts []string
}

// parseConfig parses configuration from mount config (map[string]any from JSON).
// conf must have passed ValidateConfig.
func parseConfig(conf map[string]any) ProviderConfig {
	tlsSkipVerify, caData := framework.ParseTLSConfig(conf)
	allowedHosts, _ := framework.ParseHostAllowlist(conf[framework.HostAllowlistKey])
	return ProviderConfig{
		MaxBodySize:     framework.ParseMaxBodySize(conf),
		Timeout:         framework.ParseTimeout(conf, framework.DefaultTimeout),
		AutoAuthPath:    framework.GetConfigString(conf, "auto_auth_path", ""),
		UserAuthPath:    framework.GetConfigString(conf, "user_auth_path", ""),
		DefaultAuthRole: framework.GetConfigString(conf, "default_role", ""),

		UserAuthRoleStored: framework.HasUserAuthRole(conf),
		TLSSkipVerify:      tlsSkipVerify,
		CAData:             caData,
		AllowedHosts:       allowedHosts,
	}
}
