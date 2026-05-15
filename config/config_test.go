package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestInterpolateEnv(t *testing.T) {
	t.Setenv("WARDEN_TEST_HOST", "warden-0.warden-headless.warden.svc")
	t.Setenv("WARDEN_TEST_EMPTY", "")

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "simple substitution",
			in:   `api_addr = "https://{{ env "WARDEN_TEST_HOST" }}:8400"`,
			want: `api_addr = "https://warden-0.warden-headless.warden.svc:8400"`,
		},
		{
			name: "missing var expands to empty",
			in:   `x = "{{ env "WARDEN_TEST_NOT_SET" }}"`,
			want: `x = ""`,
		},
		{
			name: "empty var expands to empty",
			in:   `x = "{{ env "WARDEN_TEST_EMPTY" }}"`,
			want: `x = ""`,
		},
		{
			name: "HCL-native ${...} is left untouched",
			in:   `path = "${some_hcl_ref}"`,
			want: `path = "${some_hcl_ref}"`,
		},
		{
			name: "no interpolation needed",
			in:   `log_level = "trace"`,
			want: `log_level = "trace"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InterpolateEnv([]byte(tt.in))
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestLoadConfig_EnvInterpolation(t *testing.T) {
	t.Setenv("WARDEN_TEST_API_ADDR", "https://node1.warden.svc:8400")
	t.Setenv("WARDEN_TEST_CLUSTER_ADDR", "https://node1.warden.svc:8401")

	dir := t.TempDir()
	hcl := `
api_addr     = "{{ env "WARDEN_TEST_API_ADDR" }}"
cluster_addr = "{{ env "WARDEN_TEST_CLUSTER_ADDR" }}"

storage "postgres" {
  connection_url = "postgres://x:y@host:5432/db"
}

listener "tcp" {
  address = ":8400"
}
`
	p := writeFile(t, dir, "warden.hcl", hcl)

	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	assert.Equal(t, "https://node1.warden.svc:8400", cfg.APIAddr)
	assert.Equal(t, "https://node1.warden.svc:8401", cfg.ClusterAddr)
}

func TestLoadConfigDir_LexicalMergeOrder(t *testing.T) {
	dir := t.TempDir()

	// Base file: full HCL with placeholder values that the overlay will replace.
	writeFile(t, dir, "00-base.hcl", `
log_level    = "info"
log_format   = "json"
api_addr     = "https://placeholder:8400"
cluster_addr = "https://placeholder:8401"

storage "postgres" {
  connection_url = "postgres://placeholder/db"
}

listener "tcp" {
  address = ":8400"
}
`)

	// Overlay file: only overrides log_level, api_addr, and the storage block
	// (mirrors the ConfigMap+Secret split where the Secret owns the storage block).
	writeFile(t, dir, "10-overlay.hcl", `
log_level = "debug"
api_addr  = "https://final:8400"

storage "postgres" {
  connection_url = "postgres://real-user:real-password@db:5432/warden"
}
`)

	cfg, err := LoadConfigDir(dir)
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.LogLevel, "overlay should override log_level")
	assert.Equal(t, "json", cfg.LogFormat, "log_format should be preserved from base")
	assert.Equal(t, "https://final:8400", cfg.APIAddr, "overlay should override api_addr")
	assert.Equal(t, "https://placeholder:8401", cfg.ClusterAddr, "cluster_addr should be preserved from base")
	require.NotNil(t, cfg.Storage)
	assert.Equal(t, "postgres://real-user:real-password@db:5432/warden", cfg.Storage.ConnectionUrl, "overlay should replace storage block")
	require.Len(t, cfg.Listeners, 1)
	assert.Equal(t, ":8400", cfg.Listeners[0].Address, "listener should be preserved from base")
}

func TestLoadConfigDir_EnvInterpolation(t *testing.T) {
	t.Setenv("WARDEN_TEST_DB_URL", "postgres://prod-user:prod-pw@db:5432/warden")
	t.Setenv("WARDEN_TEST_API_HOST", "node1.warden.svc")

	dir := t.TempDir()
	writeFile(t, dir, "00-base.hcl", `
api_addr = "https://{{ env "WARDEN_TEST_API_HOST" }}:8400"

listener "tcp" {
  address = ":8400"
}
`)
	writeFile(t, dir, "10-secrets.hcl", `
storage "postgres" {
  connection_url = "{{ env "WARDEN_TEST_DB_URL" }}"
}
`)

	cfg, err := LoadConfigDir(dir)
	require.NoError(t, err)
	assert.Equal(t, "https://node1.warden.svc:8400", cfg.APIAddr)
	require.NotNil(t, cfg.Storage)
	assert.Equal(t, "postgres://prod-user:prod-pw@db:5432/warden", cfg.Storage.ConnectionUrl)
}

func TestLoadConfigDir_IgnoresNonHCLFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "00-base.hcl", `
log_level = "info"

storage "postgres" {
  connection_url = "postgres://x/db"
}

listener "tcp" {
  address = ":8400"
}
`)
	writeFile(t, dir, "README.md", "not a config file")
	writeFile(t, dir, "warden.hcl.bak", "log_level = \"this should be ignored\"")

	cfg, err := LoadConfigDir(dir)
	require.NoError(t, err)
	assert.Equal(t, "info", cfg.LogLevel)
}

func TestLoadConfigDir_EmptyDirIsAnError(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadConfigDir(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no .hcl files")
}

func TestLoadConfigDir_MissingDirIsAnError(t *testing.T) {
	_, err := LoadConfigDir(filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
}

func TestLoadConfigDir_PropagatesParseErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "broken.hcl", `this is not valid hcl {{{`)
	_, err := LoadConfigDir(dir)
	require.Error(t, err)
}

func TestLoadConfigDir_ValidatesMergedResult(t *testing.T) {
	dir := t.TempDir()
	// Base has an invalid ip_binding_policy that the overlay corrects.
	// Validation must run on the merged result, not per file, otherwise
	// the base would be rejected even though the final config is fine.
	writeFile(t, dir, "00-base.hcl", `
ip_binding_policy = "bogus"

storage "postgres" {
  connection_url = "postgres://x/db"
}

listener "tcp" {
  address = ":8400"
}
`)
	writeFile(t, dir, "10-overlay.hcl", `
ip_binding_policy = "optional"
`)
	cfg, err := LoadConfigDir(dir)
	require.NoError(t, err)
	assert.Equal(t, "optional", cfg.IPBindingPolicy)
}

func TestLoadConfigDir_RejectsInvalidMergedResult(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "00-base.hcl", `
ip_binding_policy = "bogus"

storage "postgres" {
  connection_url = "postgres://x/db"
}

listener "tcp" {
  address = ":8400"
}
`)
	_, err := LoadConfigDir(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ip_binding_policy")
}
