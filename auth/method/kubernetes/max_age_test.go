package kubernetes

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// =============================================================================
// Config: max_age
// =============================================================================

// tableConfig is a mount table config that builds, plus extra keys.
func tableConfig(extra map[string]any) map[string]any {
	conf := map[string]any{"kubernetes_host": "https://10.0.0.1:6443", "tls_skip_verify": true}
	for k, v := range extra {
		conf[k] = v
	}
	return conf
}

func TestConfig_MaxAge(t *testing.T) {
	b := reviewingBackend(t, nil)
	ctx := context.Background()
	read := func() map[string]any {
		resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
		require.NoError(t, err)
		return resp.Data
	}
	assert.Equal(t, "0s", read()["max_age"], "unset")

	// A duration string, through the framework as a request carries it.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data:      map[string]any{"max_age": "10m"},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "write: %v", resp.Err)
	assert.Equal(t, 10*time.Minute, b.config.MaxAge)
	assert.Equal(t, "10m0s", read()["max_age"])

	// A write that leaves it out keeps it.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"issuer": "https://kube"}).StatusCode)
	assert.Equal(t, 10*time.Minute, b.config.MaxAge)

	// Storage holds the duration string, and a reload reads it back.
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, entry.DecodeJSON(&stored))
	assert.Equal(t, "10m0s", stored["max_age"])
	reloaded, _ := newTestBackend(t)
	reloaded.storageView = b.storageView
	require.NoError(t, reloaded.Initialize(ctx))
	assert.Equal(t, 10*time.Minute, reloaded.config.MaxAge)
	assert.Equal(t, "https://kube", reloaded.config.Issuer)

	// Seconds are accepted; zero unsets it.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"max_age": 90}).StatusCode)
	assert.Equal(t, 90*time.Second, b.config.MaxAge)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"max_age": "0"}).StatusCode)
	assert.Zero(t, b.config.MaxAge)
	assert.Equal(t, "0s", read()["max_age"])

	// A mount table config gives it as a string or a number of seconds.
	for raw, want := range map[any]time.Duration{"15m": 15 * time.Minute, float64(300): 5 * time.Minute, "": 0} {
		fromTable, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: tableConfig(map[string]any{"max_age": raw})})
		require.NoError(t, err, "%v", raw)
		assert.Equal(t, want, fromTable.(*kubernetesAuthBackend).config.MaxAge, "%v", raw)
	}
}

func TestConfig_MaxAgeRefused(t *testing.T) {
	cases := []struct {
		name string
		raw  any
	}{
		{"negative duration", "-10m"},
		{"negative seconds", -60},
		{"not a duration", "soon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := reviewingBackend(t, map[string]any{"max_age": "5m"})
			ctx := context.Background()
			before := b.config
			beforeEntry, err := b.storageView.Get(ctx, "config")
			require.NoError(t, err)

			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config",
				Data:      map[string]any{"max_age": tc.raw},
			})
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			require.Error(t, resp.Err)
			assert.Contains(t, resp.Err.Error(), "max_age")

			assert.Same(t, before, b.config, "a refused write is not installed")
			afterEntry, err := b.storageView.Get(ctx, "config")
			require.NoError(t, err)
			assert.Equal(t, beforeEntry.Value, afterEntry.Value, "a refused write is not stored")

			// A mount table config is refused alike.
			_, err = Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: tableConfig(map[string]any{"max_age": tc.raw})})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "max_age")
		})
	}
}

// max_age is stored but not used by role logins: a token issued long before
// max_age, and one without an iat, are both admitted.
func TestConfig_MaxAgeNotUsedByLogins(t *testing.T) {
	b := reviewingBackend(t, map[string]any{"max_age": "1m"})
	issued := time.Now().Add(-time.Hour)

	resp := login(t, b, saToken("default", "myapp", []string{apiServerAudience}, map[string]any{"iat": issued.Unix()}), "reader")
	require.Equal(t, http.StatusOK, resp.StatusCode, "old iat: %v", resp.Err)
	assert.Equal(t, issued.Unix(), resp.Auth.Admission.IssuedAt.Unix())

	resp = login(t, b, saToken("default", "myapp", []string{apiServerAudience}, nil), "reader")
	require.Equal(t, http.StatusOK, resp.StatusCode, "no iat: %v", resp.Err)
	assert.True(t, resp.Auth.Admission.IssuedAt.IsZero())
}
