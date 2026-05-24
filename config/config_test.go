package config

import (
	"os"
	"path/filepath"
	"strings"
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
  address     = ":8400"
  tls_disable = true
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
  address     = ":8400"
  tls_disable = true
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
  address     = ":8400"
  tls_disable = true
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
  address     = ":8400"
  tls_disable = true
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
  address     = ":8400"
  tls_disable = true
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
  address     = ":8400"
  tls_disable = true
}
`)
	_, err := LoadConfigDir(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ip_binding_policy")
}

// TestLoadConfig_AuditBlock exercises the two-label audit block syntax:
// `audit "TYPE" "PATH" { options = { ... } }`. The block flows through
// HCL decode → validateConfig → Config.Audits, and the Options map is
// preserved verbatim for the audit factory to consume.
func TestLoadConfig_AuditBlock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "00-base.hcl", `
ip_binding_policy = "optional"

storage "postgres" {
  connection_url = "postgres://x/db"
}

listener "tcp" {
  address     = ":8400"
  tls_disable = true
}

audit "file" "default" {
  description = "primary file audit"
  options = {
    file_path = "/var/log/warden/audit.log"
  }
}

audit "file" "stdout" {
  options = {
    file_path = "/dev/stdout"
  }
}
`)
	cfg, err := LoadConfigDir(dir)
	require.NoError(t, err)
	require.Len(t, cfg.Audits, 2)

	assert.Equal(t, "file", cfg.Audits[0].Type)
	assert.Equal(t, "default", cfg.Audits[0].Path)
	assert.Equal(t, "primary file audit", cfg.Audits[0].Description)
	assert.Equal(t, "/var/log/warden/audit.log", cfg.Audits[0].Options["file_path"])

	assert.Equal(t, "stdout", cfg.Audits[1].Path)
	assert.Equal(t, "/dev/stdout", cfg.Audits[1].Options["file_path"])

	// .Config() returns the options as map[string]any (the shape Core consumes)
	cfgMap := cfg.Audits[0].Config()
	assert.Equal(t, "/var/log/warden/audit.log", cfgMap["file_path"])
}

func TestValidateConfig_AuditBlock(t *testing.T) {
	base := `
ip_binding_policy = "optional"
storage "postgres" { connection_url = "postgres://x/db" }
listener "tcp" {
  address     = ":8400"
  tls_disable = true
}
`

	t.Run("duplicate type+path rejected", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "00.hcl", base+`
audit "file" "default" { options = { file_path = "/a" } }
audit "file" "default" { options = { file_path = "/b" } }
`)
		_, err := LoadConfigDir(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate")
	})

	t.Run("path containing slash rejected", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "00.hcl", base+`
audit "file" "nested/path" { options = { file_path = "/a" } }
`)
		_, err := LoadConfigDir(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not contain slashes")
	})
}

// TestMergeConfig_Audits verifies the same "last-file-wins, block
// replaced wholesale" semantics already used for Seals/Listeners.
func TestMergeConfig_Audits(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "00-base.hcl", `
storage "postgres" { connection_url = "postgres://x/db" }
listener "tcp" {
  address     = ":8400"
  tls_disable = true
}

audit "file" "from-base" { options = { file_path = "/base" } }
`)
	writeFile(t, dir, "10-override.hcl", `
audit "file" "from-override" { options = { file_path = "/override" } }
`)
	cfg, err := LoadConfigDir(dir)
	require.NoError(t, err)
	require.Len(t, cfg.Audits, 1, "override file should replace audit block wholesale")
	assert.Equal(t, "from-override", cfg.Audits[0].Path)
}

// Dev mode deliberately ships zero audit declarations. The broker
// fail-opens at zero, so `warden server -dev` runs unaudited (audit
// noise isn't useful for local hacking) and the operator can still
// `warden audit enable file ...` to opt in.
func TestDevConfig_HasNoAudit(t *testing.T) {
	cfg := DevConfig()
	assert.Empty(t, cfg.Audits)
}

// collectingWarner captures warnings for assertion. Implements Warner.
type collectingWarner struct{ msgs []string }

func (c *collectingWarner) Warn(msg string) { c.msgs = append(c.msgs, msg) }

// TestLoadConfig_IgnoresUnknownStanzas verifies that warden parses a
// foreign-style HCL config — unknown top-level attributes and blocks
// (e.g. `ui`, `cluster_name`, `service_registration`), and unknown attrs
// inside a known block — without erroring. Each removal is reported
// through the Warner so operators can diagnose stale or typo'd keys.
func TestLoadConfig_IgnoresUnknownStanzas(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "warden.hcl", `
ui            = true
cluster_name  = "some-cluster"
log_level     = "info"

storage "postgres" {
  connection_url = "postgres://u:p@db:5432/warden"
  unknown_attr   = "ignored"
}

listener "tcp" {
  address          = ":8400"
  tls_disable      = true
  tls_min_version  = "tls13"
}

seal "static" {
  current_key_id  = "k1"
  current_key     = "file:///k"
  bogus_seal_attr = "x"
}

service_registration "consul" {
  address = "127.0.0.1:8500"
}
`)
	w := &collectingWarner{}
	cfg, err := LoadConfigWithLogger(p, w)
	require.NoError(t, err)
	assert.Equal(t, "info", cfg.LogLevel)
	require.NotNil(t, cfg.Storage)
	assert.Equal(t, "postgres://u:p@db:5432/warden", cfg.Storage.ConnectionUrl)
	require.Len(t, cfg.Listeners, 1)
	assert.True(t, cfg.Listeners[0].TLSDisable)

	require.Len(t, cfg.Seals, 1)
	assert.Equal(t, "static", cfg.Seals[0].Type)
	assert.Equal(t, "k1", cfg.Seals[0].CurrentKeyID)

	joined := strings.Join(w.msgs, "\n")
	for _, want := range []string{
		`unknown attribute "ui"`,
		`unknown attribute "cluster_name"`,
		`unknown attribute "unknown_attr"`,
		`unknown attribute "tls_min_version"`,
		`unknown attribute "bogus_seal_attr"`,
		`unknown block "service_registration"`,
	} {
		assert.Contains(t, joined, want, "expected warning for %s", want)
	}
}
