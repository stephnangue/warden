package core

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newConfiguredCore builds a core from raw, the server config.
func newConfiguredCore(t *testing.T, raw *config.Config) *Core {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	phys, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err)
	c, err := NewCore(&CoreConfig{
		RawConfig:    raw,
		Physical:     phys,
		Logger:       log,
		AuditDevices: map[string]audit.Factory{"file": &mockAuditFactory{}},
	})
	require.NoError(t, err)
	t.Cleanup(c.closeStores)
	return c
}

// The token cache budget of the server config reaches the token store, and the
// credential cache budget is read for setupCredentialManager, which hands it
// to the manager (credential.WithCacheMaxBytes, tested in its package); unset,
// the built-in defaults hold.
func TestNewCore_CacheBudgetsFromConfig(t *testing.T) {
	c := newConfiguredCore(t, &config.Config{TokenCacheMegabytes: 2, CredentialCacheMegabytes: 3})
	assert.Equal(t, int64(2<<20), c.tokenStore.byID.MaxCost())
	assert.Equal(t, int64(3<<20), c.credentialCacheMaxBytes())

	c = newConfiguredCore(t, &config.Config{})
	assert.Equal(t, DefaultTokenStoreConfig().CacheMaxCost, c.tokenStore.byID.MaxCost(), "the default")
	assert.Zero(t, c.credentialCacheMaxBytes(), "0 keeps the credential manager's default")
}
