package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_SignerBlock(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	dir := t.TempDir()
	p := writeFile(t, dir, "signer.hcl", `
signer "transit" {
  address         = "https://bao.example.com:8200"
  token           = "s.abc123"
  mount_path      = "transit"
  key_name_prefix = "warden-oidc"
  namespace       = "ns1"
  request_timeout = "10s"
  tls_ca_cert     = "/etc/warden/ca.pem"
  disable_renewal = "false"
}
`)
	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	require.NotNil(t, cfg.Signer)
	s := cfg.Signer
	assert.Equal(t, "transit", s.Type)
	assert.Equal(t, "https://bao.example.com:8200", s.Address)
	assert.Equal(t, "s.abc123", s.Token)
	assert.Equal(t, "transit", s.MountPath)
	assert.Equal(t, "warden-oidc", s.KeyNamePrefix)
	assert.Equal(t, "ns1", s.Namespace)
	assert.Equal(t, "10s", s.RequestTimeout)
	assert.Equal(t, "/etc/warden/ca.pem", s.TlsCaCert)
}

func TestLoadConfig_SignerBlock_EnvInterpolation(t *testing.T) {
	t.Setenv("WARDEN_TEST_SIGNER_TOKEN", "s.from-env")
	t.Setenv("VAULT_ADDR", "")
	dir := t.TempDir()
	p := writeFile(t, dir, "signer.hcl", `
signer "transit" {
  address    = "https://bao:8200"
  mount_path = "transit"
  token      = "{{ env "WARDEN_TEST_SIGNER_TOKEN" }}"
}
`)
	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	require.NotNil(t, cfg.Signer)
	assert.Equal(t, "s.from-env", cfg.Signer.Token)
}

func TestLoadConfig_SignerBlock_PrunesUnknownKeys(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	dir := t.TempDir()
	p := writeFile(t, dir, "signer.hcl", `
signer "transit" {
  address        = "https://bao:8200"
  mount_path     = "transit"
  not_a_real_key = "ignored"
}
`)
	cfg, err := LoadConfig(p)
	require.NoError(t, err, "an unknown attribute must be pruned with a warning, not fail the load")
	require.NotNil(t, cfg.Signer)
	assert.Equal(t, "transit", cfg.Signer.Type)
}

func TestValidateConfig_SignerBlock(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		signer  *SignerBlock
		wantErr string
	}{
		{
			name:   "valid",
			signer: &SignerBlock{Type: "transit", Address: "https://bao:8200", MountPath: "transit"},
		},
		{
			name:    "unsupported type",
			signer:  &SignerBlock{Type: "awskms", Address: "https://bao:8200", MountPath: "transit"},
			wantErr: "only \"transit\" is supported",
		},
		{
			name:    "missing mount_path",
			signer:  &SignerBlock{Type: "transit", Address: "https://bao:8200"},
			wantErr: "mount_path is required",
		},
		{
			name:    "missing address without VAULT_ADDR",
			signer:  &SignerBlock{Type: "transit", MountPath: "transit"},
			wantErr: "address is required",
		},
		{
			name:   "missing address but VAULT_ADDR set",
			env:    map[string]string{"VAULT_ADDR": "https://bao:8200"},
			signer: &SignerBlock{Type: "transit", MountPath: "transit"},
		},
		{
			name:    "key_name_prefix with slash",
			signer:  &SignerBlock{Type: "transit", Address: "https://bao:8200", MountPath: "transit", KeyNamePrefix: "a/b"},
			wantErr: "must not contain '/'",
		},
		{
			name:    "bad request_timeout",
			signer:  &SignerBlock{Type: "transit", Address: "https://bao:8200", MountPath: "transit", RequestTimeout: "soon"},
			wantErr: "invalid request_timeout",
		},
		{
			name:    "non-positive request_timeout",
			signer:  &SignerBlock{Type: "transit", Address: "https://bao:8200", MountPath: "transit", RequestTimeout: "0s"},
			wantErr: "must be positive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Default VAULT_ADDR empty unless the case sets it, so the address check is deterministic.
			if _, ok := tc.env["VAULT_ADDR"]; !ok {
				t.Setenv("VAULT_ADDR", "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			err := validateConfig(&Config{Signer: tc.signer})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
