package jwt

import (
	"context"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper/factstest"
	"github.com/stephnangue/warden/logical"
)

// Every operation under role/ answers 410, and the roles an older version
// stored there are neither read nor changed.
func TestRoles_Gone(t *testing.T) {
	ctx := context.Background()
	storage := &factstest.RecordingStorage{Storage: newInmemStorage()}
	stored, err := sdklogical.StorageEntryJSON("role/legacy", map[string]any{"token_policies": []string{"admin"}})
	require.NoError(t, err)
	require.NoError(t, storage.Storage.Put(ctx, stored))

	backend, err := Factory(ctx, &logical.BackendConfig{Logger: testLoggerLogin(), StorageView: storage})
	require.NoError(t, err)
	factstest.AssertRolesGone(t, backend)

	assert.Zero(t, storage.RoleOps(), "the old role storage must not be touched")
	got, err := storage.Storage.Get(ctx, "role/legacy")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, stored.Value, got.Value)
}
