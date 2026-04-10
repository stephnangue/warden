package vault

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/framework"
)

// ProviderConfig holds parsed configuration for the Vault provider
type ProviderConfig struct {
	VaultAddress  string
	MaxBodySize   int64
	Timeout       time.Duration
	TLSSkipVerify bool
	CAData        string
}

// parseConfig parses configuration from mount config (map[string]any from JSON)
func parseConfig(conf map[string]any) ProviderConfig {
	tlsSkipVerify, caData := framework.ParseTLSConfig(conf)
	return ProviderConfig{
		VaultAddress:  framework.GetConfigString(conf, "vault_address", ""),
		MaxBodySize:   framework.ParseMaxBodySize(conf),
		Timeout:       framework.ParseTimeout(conf, framework.DefaultTimeout),
		TLSSkipVerify: tlsSkipVerify,
		CAData:        caData,
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
