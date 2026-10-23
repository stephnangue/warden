package jwt

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
func tableConfig(t *testing.T, extra map[string]any) map[string]any {
	t.Helper()
	_, pemStr := genTestPubKeyPEM(t, "ECDSA")
	conf := map[string]any{"jwt_validation_pubkeys": []string{pemStr}, "bound_issuer": factsTestIssuer}
	for k, v := range extra {
		conf[k] = v
	}
	return conf
}

func TestConfig_MaxAge(t *testing.T) {
	b, _ := factsBackend(t, nil)
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
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"user_claim": "email"}).StatusCode)
	assert.Equal(t, 10*time.Minute, b.config.MaxAge)

	// Storage holds the duration string, and a reload reads it back.
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, entry.DecodeJSON(&stored))
	assert.Equal(t, "10m0s", stored["max_age"])
	reloaded, _ := createTestBackendWithStorage(t)
	reloaded.storageView = b.storageView
	require.NoError(t, reloaded.Initialize(ctx))
	assert.Equal(t, 10*time.Minute, reloaded.config.MaxAge)
	assert.Equal(t, "email", reloaded.config.UserClaim)

	// Seconds are accepted; zero unsets it.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"max_age": 90}).StatusCode)
	assert.Equal(t, 90*time.Second, b.config.MaxAge)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"max_age": "0"}).StatusCode)
	assert.Zero(t, b.config.MaxAge)
	assert.Equal(t, "0s", read()["max_age"])

	// A mount table config gives it as a string or a number of seconds.
	for raw, want := range map[any]time.Duration{"15m": 15 * time.Minute, float64(300): 5 * time.Minute, "": 0} {
		fromTable, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: tableConfig(t, map[string]any{"max_age": raw})})
		require.NoError(t, err, "%v", raw)
		assert.Equal(t, want, fromTable.(*jwtAuthBackend).config.MaxAge, "%v", raw)
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
			b, _ := factsBackend(t, map[string]any{"max_age": "5m"})
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
			_, err = Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: tableConfig(t, map[string]any{"max_age": tc.raw})})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "max_age")
		})
	}
}

// The mount's max_age is enforced at login, as at introspect/admit: a JWT
// issued longer ago than max_age, or without an iat, is not admitted; a fresh
// one is.
func TestLogin_EnforcesMountMaxAge(t *testing.T) {
	b, key := factsBackend(t, map[string]any{"max_age": "30m"})

	issued := time.Now().Add(-time.Hour)
	resp := login(t, b, signES256(t, key, baseClaims(map[string]any{"iat": issued.Unix()})))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "an hour-old JWT is older than max_age")
	assert.Nil(t, resp.Auth)

	noIat := baseClaims(nil)
	delete(noIat, "iat")
	resp = login(t, b, signES256(t, key, noIat))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a JWT without iat is not admitted under max_age")

	fresh := time.Now().Add(-time.Minute)
	resp = login(t, b, signES256(t, key, baseClaims(map[string]any{"iat": fresh.Unix()})))
	require.Equal(t, http.StatusOK, resp.StatusCode, "fresh iat: %v", resp.Err)
	assert.Equal(t, fresh.Unix(), resp.Auth.Admission.IssuedAt.Unix())
}
