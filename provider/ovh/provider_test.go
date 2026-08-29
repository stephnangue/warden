package ovh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The S3 leg forces https and addresses a host, so an override is reduced to
// one. Operators write the API-side key as a URL, so this accepts either rather
// than making the two keys behave differently.
func TestS3Host(t *testing.T) {
	for name, tc := range map[string]struct{ configured, want string }{
		"unset":           {"", ""},
		"bare host":       {"s3.egress.internal", "s3.egress.internal"},
		"host and port":   {"127.0.0.1:8443", "127.0.0.1:8443"},
		"https URL":       {"https://s3.egress.internal", "s3.egress.internal"},
		"URL with a path": {"https://s3.egress.internal/v1/", "s3.egress.internal"},
		"http URL":        {"http://127.0.0.1:8443", "127.0.0.1:8443"},
		"trailing slash":  {"s3.egress.internal/", "s3.egress.internal"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, s3Host(tc.configured))
		})
	}
}

// Nothing else checks this key, so a value that cannot be a host has to be
// refused here or it is stored and only fails per request, much later.
func TestValidateExtraConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		configured string
		wantErr    bool
	}{
		"unset":               {"", false},
		"bare host":           {"s3.egress.internal", false},
		"host and port":       {"127.0.0.1:8443", false},
		"full URL":            {"https://s3.egress.internal", false},
		"scheme with no host": {"https://", true},
		"host with a path":    {"s3.egress.internal/v1", true},
		"query string":        {"s3.egress.internal?x=1", true},
	} {
		t.Run(name, func(t *testing.T) {
			err := Spec.ValidateExtraConfig(map[string]any{"s3_url": tc.configured})
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// A config read echoes the state map back, so the key has to be one the write
// path would accept — otherwise a mount's configuration cannot round-trip.
func TestOnConfigParsedRoundTrips(t *testing.T) {
	state := Spec.OnConfigParsed(map[string]any{"s3_url": "https://s3.egress.internal/"})
	host, ok := state["s3_url"].(string)
	require.True(t, ok, "config read must report s3_url, the key an operator writes")
	assert.Equal(t, "s3.egress.internal", host)
	assert.NoError(t, Spec.ValidateExtraConfig(map[string]any{"s3_url": host}),
		"what a read reports must be writable again")
}

func TestS3Endpoint(t *testing.T) {
	t.Run("the region names the public host", func(t *testing.T) {
		assert.Equal(t, "s3.gra.io.cloud.ovh.net", Spec.S3Endpoint(map[string]any{}, "gra"))
	})

	// An operator whose traffic leaves through a private gateway names it, and
	// the region stops deciding where the request goes.
	t.Run("an override wins over the region", func(t *testing.T) {
		state := Spec.OnConfigParsed(map[string]any{"s3_url": "https://s3.egress.internal"})
		assert.Equal(t, "s3.egress.internal", Spec.S3Endpoint(state, "gra"))
	})

	t.Run("no override leaves the region deciding", func(t *testing.T) {
		state := Spec.OnConfigParsed(map[string]any{})
		assert.Equal(t, "s3.gra.io.cloud.ovh.net", Spec.S3Endpoint(state, "gra"))
	})
}
