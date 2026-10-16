package configutil

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/config"
)

func TestConfigureWrapper_PKCS11Unsupported(t *testing.T) {
	wrapper, err := ConfigureWrapper(&config.KMS{Type: "pkcs11"}, nil, nil, nil)
	require.Error(t, err)
	assert.Nil(t, wrapper)
	assert.Contains(t, err.Error(), `seal type "pkcs11" is not supported`)
	assert.Contains(t, err.Error(), `seal "transit"`)
}

// loadSeal loads a server config carrying the given seal stanza through the
// real HCL decode path and returns the seal.
func loadSeal(t *testing.T, seal string) *config.KMS {
	t.Helper()
	p := filepath.Join(t.TempDir(), "warden.hcl")
	require.NoError(t, os.WriteFile(p, []byte(`
storage "inmem" {}
listener "tcp" {
  address     = "127.0.0.1:8400"
  tls_disable = true
}
`+seal), 0o600))
	cfg, err := config.LoadConfig(p)
	require.NoError(t, err)
	require.Len(t, cfg.Seals, 1)
	return &cfg.Seals[0]
}

// clearTransitEnv unsets the env vars the transit wrapper reads ahead of its
// config map, so the test sees only what the HCL stanza supplies.
func clearTransitEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"ADDR", "TOKEN", "KEY_NAME", "MOUNT_PATH", "DISABLE_RENEWAL", "NAMESPACE"} {
		t.Setenv("TRANSIT_WRAPPER_"+k, "")
		t.Setenv("VAULT_TRANSIT_SEAL_"+k, "")
	}
	t.Setenv("VAULT_NAMESPACE", "")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
}

// TestGetTransitKMS_KeyNameFromHCL pins that a transit seal configured
// purely in HCL reaches the wrapper with its key_name. SetConfig probes the
// key with one encrypt call, which the stub answers and records.
func TestGetTransitKMS_KeyNameFromHCL(t *testing.T) {
	clearTransitEnv(t)

	var gotPath, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotToken = r.URL.Path, r.Header.Get("X-Vault-Token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v1:Y2lwaGVy"}}`))
	}))
	t.Cleanup(srv.Close)

	kms := loadSeal(t, fmt.Sprintf(`
seal "transit" {
  address         = %q
  token           = "s.test"
  key_name        = "warden-unseal"
  mount_path      = "transit/"
  disable_renewal = "true"
}
`, srv.URL))
	wrapper, info, err := GetTransitKMSFunc(kms)
	require.NoError(t, err)
	require.NotNil(t, wrapper)
	assert.Equal(t, "/v1/transit/encrypt/warden-unseal", gotPath)
	assert.Equal(t, "s.test", gotToken)
	assert.Equal(t, "warden-unseal", info["Transit Key Name"])
	assert.Equal(t, "transit/", info["Transit Mount Path"])
}

func TestGetTransitKMS_MissingKeyName(t *testing.T) {
	clearTransitEnv(t)

	kms := loadSeal(t, `
seal "transit" {
  address         = "http://127.0.0.1:1"
  token           = "s.test"
  mount_path      = "transit/"
  disable_renewal = "true"
}
`)
	_, _, err := GetTransitKMSFunc(kms)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key_name is required")
}

func TestConfigureWrapper_UnknownType(t *testing.T) {
	_, err := ConfigureWrapper(&config.KMS{Type: "bogus"}, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown KMS type "bogus"`)
}
