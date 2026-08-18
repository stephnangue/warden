package vault

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/framework"
)

// ProviderConfig holds parsed configuration for the Vault provider
type ProviderConfig struct {
	VaultAddress    string
	MaxBodySize     int64
	Timeout         time.Duration
	AutoAuthPath    string
	DefaultAuthRole string
	UserAuthPath    string
	UserAuthRole    string
	TLSSkipVerify   bool
	CAData          string
}

// parseConfig parses configuration from mount config (map[string]any from JSON)
func parseConfig(conf map[string]any) ProviderConfig {
	tlsSkipVerify, caData := framework.ParseTLSConfig(conf)
	return ProviderConfig{
		VaultAddress:    framework.GetConfigString(conf, "vault_address", ""),
		MaxBodySize:     framework.ParseMaxBodySize(conf),
		Timeout:         framework.ParseTimeout(conf, framework.DefaultTimeout),
		AutoAuthPath:    framework.GetConfigString(conf, "auto_auth_path", ""),
		DefaultAuthRole: framework.GetConfigString(conf, "default_role", ""),
		UserAuthPath:    framework.GetConfigString(conf, "user_auth_path", ""),
		UserAuthRole:    framework.GetConfigString(conf, "user_auth_role", ""),
		TLSSkipVerify:   tlsSkipVerify,
		CAData:          caData,
	}
}

// validateVaultAddress validates that the vault_address is a well-formed URL.
// Vault accepts both http:// and https:// (http is common in dev mode).
func validateVaultAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("vault_address is required")
	}
	return framework.ValidateURL(addr, "vault_address", true) // true: allow http
}
