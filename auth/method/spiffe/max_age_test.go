package spiffe

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

func TestConfig_MaxAge(t *testing.T) {
	b, ctx := createTestBackend(t)
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
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"default_role": "api"}).StatusCode)
	assert.Equal(t, 10*time.Minute, b.config.MaxAge)

	// Storage holds the duration string, and a reload reads it back.
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, entry.DecodeJSON(&stored))
	assert.Equal(t, "10m0s", stored["max_age"])
	backend, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), StorageView: b.storageView})
	require.NoError(t, err)
	reloaded := backend.(*spiffeAuthBackend)
	require.NoError(t, reloaded.Initialize(ctx))
	t.Cleanup(reloaded.spiffe.Stop)
	assert.Equal(t, 10*time.Minute, reloaded.config.MaxAge)
	assert.Equal(t, "api", reloaded.config.DefaultRole)

	// Seconds are accepted; zero unsets it.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"max_age": 90}).StatusCode)
	assert.Equal(t, 90*time.Second, b.config.MaxAge)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"max_age": "0"}).StatusCode)
	assert.Zero(t, b.config.MaxAge)
	assert.Equal(t, "0s", read()["max_age"])

	// A mount table config gives it as a string or a number of seconds.
	for raw, want := range map[any]time.Duration{"15m": 15 * time.Minute, float64(300): 5 * time.Minute, "": 0} {
		fromTable, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: map[string]any{"max_age": raw}})
		require.NoError(t, err, "%v", raw)
		assert.Equal(t, want, fromTable.(*spiffeAuthBackend).config.MaxAge, "%v", raw)
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
			b, ctx := createTestBackend(t)
			require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"max_age": "5m"}).StatusCode)
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
			_, err = Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: map[string]any{"max_age": tc.raw}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "max_age")
		})
	}
}

// max_age is stored but not used by role logins: an X.509-SVID, which has no
// issue time, and a JWT-SVID issued long before max_age are both admitted.
func TestConfig_MaxAgeNotUsedByLogins(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"max_age": "1m"})
	ctx := context.Background()
	const id = "spiffe://" + testTD + "/ns/a/sa/b"

	resp := x509Login(t, f.b, ctx, "api", f.svid(t, id))
	require.Equal(t, http.StatusOK, resp.StatusCode, "x509: %v", resp.Err)
	assert.True(t, resp.Auth.Admission.IssuedAt.IsZero())

	issued := time.Now().Add(-time.Hour)
	resp = jwtLogin(t, f.b, ctx, "api", f.jwt.sign(t, id, []string{"warden"}, time.Now().Add(time.Hour),
		map[string]any{"iat": issued.Unix()}))
	require.Equal(t, http.StatusOK, resp.StatusCode, "jwt: %v", resp.Err)
	assert.Equal(t, issued.Unix(), resp.Auth.Admission.IssuedAt.Unix())
}
