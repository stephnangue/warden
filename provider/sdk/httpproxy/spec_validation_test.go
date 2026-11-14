package httpproxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Spec validation tests ---

func TestValidateSpec(t *testing.T) {
	t.Run("nil spec", func(t *testing.T) {
		assert.Error(t, ValidateSpec(nil))
	})

	t.Run("missing Name", func(t *testing.T) {
		s := *testSpec()
		s.Name = ""
		assert.Contains(t, ValidateSpec(&s).Error(), "Name")
	})

	t.Run("missing URLConfigKey", func(t *testing.T) {
		s := *testSpec()
		s.URLConfigKey = ""
		assert.Contains(t, ValidateSpec(&s).Error(), "URLConfigKey")
	})

	t.Run("missing ExtractCredentials", func(t *testing.T) {
		s := *testSpec()
		s.ExtractCredentials = nil
		assert.Contains(t, ValidateSpec(&s).Error(), "ExtractCredentials")
	})

	// An empty DefaultURL is how a provider says its upstream is per-deployment.
	// Nine of the shipped specs are in that shape, so requiring it here would
	// refuse to mount every instance-specific product we carry.
	t.Run("empty DefaultURL is valid", func(t *testing.T) {
		s := *testSpec()
		s.DefaultURL = ""
		assert.NoError(t, ValidateSpec(&s))
	})

	t.Run("valid spec", func(t *testing.T) {
		assert.NoError(t, ValidateSpec(testSpec()))
	})

	// A spec counting on the hook to refuse what it cannot rewrite must have one.
	t.Run("RewriteWithoutPrefix without the hooks", func(t *testing.T) {
		s := *testSpec()
		s.RewriteWithoutPrefix = true
		assert.Contains(t, ValidateSpec(&s).Error(), "RewriteWithoutPrefix")

		s.RewriteResponse = func(*http.Request, map[string]any) bool { return true }
		s.ModifyResponse = func(*http.Response, RewriteContext) error { return nil }
		assert.NoError(t, ValidateSpec(&s))
	})
}

func TestNewFactory_InvalidSpec(t *testing.T) {
	factory := NewFactory(&ProviderSpec{}) // empty spec
	_, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Name")
}

// A spec that mounts but has no extractor panics on the first authenticated
// request rather than failing at mount, which is the failure this guards.
func TestNewFactory_MissingExtractorFailsAtMount(t *testing.T) {
	spec := testSpec()
	spec.ExtractCredentials = nil
	factory := NewFactory(spec)
	_, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ExtractCredentials")
}
