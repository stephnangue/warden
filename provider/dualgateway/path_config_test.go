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

func TestPathConfig_Write_MissingAutoAuthPath(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	path := b.pathConfig()

	raw := map[string]interface{}{
		"test_url": "https://api.test.com",
	}

	resp, err := b.handleConfigWrite(context.Background(), &logical.Request{}, makeFieldData(path, raw))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
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
