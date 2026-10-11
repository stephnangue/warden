package framework

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTargetHost(t *testing.T) {
	for _, host := range []string{"storage.googleapis.com", "us-central1-aiplatform.googleapis.com", "my-vault.vault.azure.net"} {
		assert.NoError(t, ValidateTargetHost(host), host)
	}
	for _, host := range []string{
		"", "localhost", "127.0.0.1", "[::1]", "169.254.169.254",
		"storage.googleapis.com:443", "x@storage.googleapis.com", "attacker.example#.googleapis.com",
		"Storage.googleapis.com", "storage.googleapis.com.", "-x.googleapis.com", "x..googleapis.com",
	} {
		assert.Error(t, ValidateTargetHost(host), host)
	}
}

func TestHostAllowed(t *testing.T) {
	allowlist := []string{".googleapis.com", ".management.azure.com"}
	for host, want := range map[string]bool{
		"storage.googleapis.com":           true,
		"googleapis.com":                   true,
		"management.azure.com":             true,
		"eastus.management.azure.com":      true,
		"notgoogleapis.com":                false,
		"googleapis.com.attacker.example":  false,
		"attacker.example":                 false,
		"x.eastus.cloudapp.azure.com":      false,
		"management.azure.com.attacker.io": false,
	} {
		assert.Equal(t, want, HostAllowed(host, allowlist), host)
	}
	assert.False(t, HostAllowed("storage.googleapis.com", nil))
}

func TestParseHostAllowlist(t *testing.T) {
	got, err := ParseHostAllowlist([]any{".googleapis.com", " .Example.COM ", ""})
	require.NoError(t, err)
	assert.Equal(t, []string{".googleapis.com", ".example.com"}, got)

	got, err = ParseHostAllowlist(".a.example.com,.b.example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{".a.example.com", ".b.example.com"}, got)

	got, err = ParseHostAllowlist(nil)
	require.NoError(t, err)
	assert.Nil(t, got)

	for _, raw := range []any{
		[]any{"googleapis.com"}, // no leading dot
		[]any{"*"},
		[]any{".com/x"},
		[]any{"."},
		[]any{1},
		42,
	} {
		_, err := ParseHostAllowlist(raw)
		assert.Error(t, err, "%v", raw)
	}
}
