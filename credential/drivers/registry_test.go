package drivers

import (
	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRegisterBuiltinDrivers(t *testing.T) {
	registry := credential.NewDriverRegistry(testDriverLogger())
	err := RegisterBuiltinDrivers(registry)
	require.NoError(t, err)

	// Every builtin driver, not a subset — an under-enumerated list reads as
	// "all registered" while silently skipping whatever was added last.
	expectedTypes := []string{
		credential.SourceTypeLocal,
		credential.SourceTypeVault,
		credential.SourceTypeAWS,
		credential.SourceTypeAzure,
		credential.SourceTypeGCP,
		credential.SourceTypeGitLab,
		credential.SourceTypeGitHub,
		credential.SourceTypeAPIKey,
		credential.SourceTypeOAuth2,
		credential.SourceTypeAlicloud,
		credential.SourceTypeElastic,
		credential.SourceTypeGrafana,
		credential.SourceTypeIBM,
		credential.SourceTypeKubernetes,
		credential.SourceTypeOVH,
		credential.SourceTypeScaleway,
		credential.SourceTypeTokenExchange,
	}
	for _, typeName := range expectedTypes {
		factory, err := registry.GetFactory(typeName)
		assert.NoError(t, err, "type=%s should be registered", typeName)
		assert.NotNil(t, factory, "type=%s factory should not be nil", typeName)
	}
}

// =============================================================================
// readLimitedBody Tests
// =============================================================================
