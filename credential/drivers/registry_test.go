package drivers

import (
	"testing"
	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterBuiltinDrivers(t *testing.T) {
	registry := credential.NewDriverRegistry(testDriverLogger())
	err := RegisterBuiltinDrivers(registry)
	require.NoError(t, err)

	// Verify all expected drivers are registered
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

