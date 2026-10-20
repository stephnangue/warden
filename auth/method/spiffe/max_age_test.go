package spiffe

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
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

// max_age applies to JWT-SVIDs only: an X.509-SVID carries no issue time and
// is not checked, while a JWT-SVID is held to helper.CheckMaxAge, which refuses
// one without an iat.
func TestCheckSVIDMaxAge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	id := spiffeid.RequireFromString("spiffe://example.org/ns/a/sa/b")
	x509 := newAdmission(id, svidX509, nil, time.Time{}, nil)
	jwtAt := func(iat time.Time) *logical.Admission { return newAdmission(id, svidJWT, []string{"warden"}, iat, nil) }
	cfg := &SPIFFEAuthConfig{MaxAge: 10 * time.Minute}

	cases := []struct {
		name    string
		cfg     *SPIFFEAuthConfig
		adm     *logical.Admission
		wantErr string
	}{
		{"x509 is not checked", cfg, x509, ""},
		{"x509 with a stale issue time is not checked", cfg, newAdmission(id, svidX509, nil, now.Add(-time.Hour), nil), ""},
		{"jwt fresh", cfg, jwtAt(now.Add(-time.Minute)), ""},
		{"jwt exactly max_age", cfg, jwtAt(now.Add(-10 * time.Minute)), ""},
		{"jwt over max_age", cfg, jwtAt(now.Add(-10*time.Minute - time.Second)), "credential is 10m1s old, more than max_age 10m0s"},
		{"jwt without iat", cfg, jwtAt(time.Time{}), "credential has no issue time"},
		{"unset max_age", &SPIFFEAuthConfig{}, jwtAt(time.Time{}), ""},
		{"unconfigured mount", nil, jwtAt(time.Time{}), ""},
		{"an unknown kind is held to max_age", cfg, newAdmission(id, "other", nil, time.Time{}, nil), "credential has no issue time"},
		{"no admission is held to max_age", cfg, nil, "credential has no issue time"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.CheckSVIDMaxAge(tc.adm, now)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
		})
	}
	assert.ErrorIs(t, cfg.CheckSVIDMaxAge(jwtAt(time.Time{}), now), helper.ErrNoIssueTime)
}

// The admissions real logins produce: an X.509-SVID passes whatever max_age
// is, a JWT-SVID issued before max_age does not.
func TestCheckSVIDMaxAge_LoginAdmissions(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"max_age": "1m"})
	ctx := context.Background()
	const id = "spiffe://" + testTD + "/ns/a/sa/b"

	resp := x509Login(t, f.b, ctx, "api", f.svid(t, id))
	require.Equal(t, http.StatusOK, resp.StatusCode, "x509: %v", resp.Err)
	assert.NoError(t, f.b.config.CheckSVIDMaxAge(resp.Auth.Admission, time.Now()))

	resp = jwtLogin(t, f.b, ctx, "api", f.jwt.sign(t, id, []string{"warden"}, time.Now().Add(time.Hour), nil))
	require.Equal(t, http.StatusOK, resp.StatusCode, "fresh jwt: %v", resp.Err)
	assert.NoError(t, f.b.config.CheckSVIDMaxAge(resp.Auth.Admission, time.Now()))

	resp = jwtLogin(t, f.b, ctx, "api", f.jwt.sign(t, id, []string{"warden"}, time.Now().Add(time.Hour),
		map[string]any{"iat": time.Now().Add(-time.Hour).Unix()}))
	require.Equal(t, http.StatusOK, resp.StatusCode, "stale jwt: %v", resp.Err)
	assert.ErrorContains(t, f.b.config.CheckSVIDMaxAge(resp.Auth.Admission, time.Now()), "more than max_age 1m0s")
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
