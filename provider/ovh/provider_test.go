package ovh

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
