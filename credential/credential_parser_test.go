package credential

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lifetimeSpec(maxTTL time.Duration) *CredSpec {
	spec := carriageSpec()
	spec.MaxTTL = maxTTL
	return spec
}

func parseWithLease(t *testing.T, spec *CredSpec, leaseTTL time.Duration) (*Credential, error) {
	t.Helper()
	return strictCarriageParser(t).ParseAndValidate(t.Context(), spec,
		map[string]interface{}{"token": "the-secret"}, nil, leaseTTL, "", carriageDriver(SourceTypeVault))
}

// A negative lease is an expiry already past, or an overflow. Served, it would
// read as expired at once and every request would mint again.
func TestParseAndValidate_RefusesALifetimeAlreadyPast(t *testing.T) {
	_, err := parseWithLease(t, lifetimeSpec(0), -time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already past")
}

// max_ttl bounds how long every credential is served, whatever its type. A dynamic
// lease past it is capped; a static credential stays static (LeaseTTL 0, so a
// chained consumer or the AWS gateway still reads it as one) and carries the bound
// in MaxServe for its cache entry.
func TestParseAndValidate_MaxTTLBoundsTheServedLifetime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		maxTTL    time.Duration
		lease     time.Duration
		wantLease time.Duration
	}{
		{"an upstream lease past max_ttl is capped", 10 * time.Minute, time.Hour, 10 * time.Minute},
		{"a lease within max_ttl is kept", time.Hour, 10 * time.Minute, 10 * time.Minute},
		{"a static credential stays static", 10 * time.Minute, 0, 0},
		{"no max_ttl leaves the lease as reported", 0, time.Hour, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := parseWithLease(t, lifetimeSpec(tc.maxTTL), tc.lease)
			require.NoError(t, err)
			assert.Equal(t, tc.wantLease, cred.LeaseTTL)
			assert.Equal(t, tc.maxTTL, cred.MaxServe)
		})
	}
}

func TestSmallestPositive(t *testing.T) {
	assert.Equal(t, time.Duration(0), smallestPositive())
	assert.Equal(t, time.Duration(0), smallestPositive(0, -time.Second))
	assert.Equal(t, time.Minute, smallestPositive(0, time.Hour, time.Minute))
	assert.Equal(t, time.Hour, smallestPositive(time.Hour, 0))
}
