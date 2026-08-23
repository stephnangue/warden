package dualgateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathConfig_ReadDefaults(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	path := b.pathConfig()

	resp, err := b.handleConfigRead(context.Background(), &logical.Request{}, makeFieldData(path, nil))
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https://api.test.com", resp.Data["test_url"])
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
}

func TestPathConfig_Write(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	path := b.pathConfig()

	raw := map[string]interface{}{
		"test_url":       "https://custom.test.com",
		"timeout":        30,
		"auto_auth_path": "auth/jwt/",
		"default_role":   "reader",
	}

	resp, err := b.handleConfigWrite(context.Background(), &logical.Request{}, makeFieldData(path, raw))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https://custom.test.com", b.providerURL)
}

// A mount serving only the non-transparent leg — X-Warden-Token against
// gateway/... — never sets auto_auth_path. Rejecting its writes would leave it
// unable to change its own URL or timeout for the life of the mount.
func TestPathConfig_Write_WithoutAutoAuthPath_OnNonTransparentMount(t *testing.T) {
	b := createBackend(t, headerAuthSpec)

	writeConfig(t, b, map[string]any{"test_url": "https://api.test.com"})

	assert.Equal(t, "https://api.test.com", readConfig(t, b)["test_url"])
}

// The rejection that does still apply: taking transparent auth away from a
// mount serving it. An empty string is a value the caller sent, not an absence.
func TestPathConfig_Write_CannotClearAutoAuthPath(t *testing.T) {
	b := createBackendWithConfig(t, headerAuthSpec, map[string]any{
		"auto_auth_path": "auth/cert/",
	})

	resp, err := b.handleConfigWrite(context.Background(), &logical.Request{},
		makeFieldData(b.pathConfig(), map[string]any{"auto_auth_path": ""}))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	assert.Equal(t, "auth/cert/", readConfig(t, b)["auto_auth_path"],
		"a rejected write must not have applied anything")
}

// B4: a write names one key; every key it does not name must survive it.
// Measured against the exact sequence that repointed a working scaleway mount
// at the vendor's public endpoint while reporting success.
func TestPathConfig_Write_PreservesUnnamedKeys(t *testing.T) {
	b := createBackendWithConfig(t, headerAuthSpec, map[string]any{
		"test_url":        "http://127.0.0.1:9999",
		"tls_skip_verify": true,
		"timeout":         "2m",
	})

	writeConfig(t, b, map[string]any{"auto_auth_path": "auth/cert/"})

	got := readConfig(t, b)
	assert.Equal(t, "http://127.0.0.1:9999", got["test_url"])
	assert.Equal(t, "2m0s", got["timeout"])
	assert.Equal(t, "auth/cert/", got["auto_auth_path"])
}

// The same property in the other direction: the transparent settings a mount
// depends on survive a write that touches only an unrelated key.
func TestPathConfig_Write_PreservesTransparentConfig(t *testing.T) {
	b := createBackendWithConfig(t, headerAuthSpec, map[string]any{
		"auto_auth_path": "auth/cert/",
		"default_role":   "reader",
	})

	writeConfig(t, b, map[string]any{"timeout": "45s"})

	got := readConfig(t, b)
	assert.Equal(t, "auth/cert/", got["auto_auth_path"])
	assert.Equal(t, "reader", got["default_role"])
	assert.Equal(t, "45s", got["timeout"])
}

// Extra keys are provider-specific and merge on the same terms as the rest.
// account_id is what R2 needs to build an S3 endpoint at all; losing it to an
// unrelated write would break every object-storage request through the mount.
func TestPathConfig_Write_PreservesExtraKeys(t *testing.T) {
	b := createBackendWithConfig(t, extraKeySpec, map[string]any{
		"account_id": "abc123",
	})

	writeConfig(t, b, map[string]any{"timeout": "45s"})

	got := readConfig(t, b)
	assert.Equal(t, "abc123", got["account_id"])

	b.mu.RLock()
	state := b.extraState["account_id"]
	b.mu.RUnlock()
	assert.Equal(t, "abc123", state, "the resolved state the gateway reads must move with it")
}

func TestPathConfig_UsesSpecURLConfigKey(t *testing.T) {
	b := createBackend(t, bearerAuthSpec)
	path := b.pathConfig()

	resp, err := b.handleConfigRead(context.Background(), &logical.Request{}, makeFieldData(path, nil))
	require.NoError(t, err)
	assert.Equal(t, "https://api.bearer.com/1.0", resp.Data["bearer_url"])
	_, hasWrongKey := resp.Data["test_url"]
	assert.False(t, hasWrongKey)
}

func TestPathConfig_Write_Persists(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	path := b.pathConfig()

	raw := map[string]interface{}{
		"test_url":       "https://persisted.test.com",
		"timeout":        60,
		"auto_auth_path": "auth/cert/",
	}

	resp, err := b.handleConfigWrite(context.Background(), &logical.Request{}, makeFieldData(path, raw))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read back and verify
	resp, err = b.handleConfigRead(context.Background(), &logical.Request{}, makeFieldData(path, nil))
	require.NoError(t, err)
	assert.Equal(t, "https://persisted.test.com", resp.Data["test_url"])
}
