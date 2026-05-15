package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalConfigHCL is a valid HCL config used as the base for tests that
// then write one additional offending field. Lets each test focus on the
// invariant being checked instead of restating boilerplate.
const minimalConfigHCL = `
storage "postgres" {
  connection_url = "postgres://u:p@db:5432/warden"
}

listener "tcp" {
  address = ":8400"
}
`

func loadFromHCL(t *testing.T, body string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "warden.hcl")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return LoadConfig(p)
}

// TestLoadConfig_BaselineParses establishes that minimalConfigHCL on its
// own loads cleanly; otherwise every other validation test would be
// suspect.
func TestLoadConfig_BaselineParses(t *testing.T) {
	cfg, err := loadFromHCL(t, minimalConfigHCL)
	require.NoError(t, err)
	require.NotNil(t, cfg.Storage)
	require.Len(t, cfg.Listeners, 1)
}

func TestLoadConfig_IPBindingPolicy(t *testing.T) {
	tests := []struct {
		policy  string
		wantErr bool
	}{
		{"", false},          // unset is fine; downstream picks default
		{"disabled", false},
		{"optional", false},
		{"required", false},
		{"bogus", true},
		{"OPTIONAL", true}, // case-sensitive
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			body := minimalConfigHCL
			if tt.policy != "" {
				body += "\nip_binding_policy = \"" + tt.policy + "\"\n"
			}
			_, err := loadFromHCL(t, body)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "ip_binding_policy")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoadConfig_RotationPeriodBounds(t *testing.T) {
	tests := []struct {
		name    string
		minStr  string
		maxStr  string
		wantErr string // empty → no error expected
	}{
		{"both unset", "", "", ""},
		{"min only valid", "5m", "", ""},
		{"max only valid", "", "10m", ""},
		{"valid range", "5m", "1h", ""},
		{"min equals max", "10m", "10m", ""},
		{"min greater than max", "1h", "5m", "must be <="},
		{"unparseable min", "not-a-duration", "", "invalid min_cred_source_rotation_period"},
		{"unparseable max", "", "still-not-a-duration", "invalid max_cred_source_rotation_period"},
		{"negative min", "-5m", "", "must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := minimalConfigHCL
			if tt.minStr != "" {
				body += "\nmin_cred_source_rotation_period = \"" + tt.minStr + "\"\n"
			}
			if tt.maxStr != "" {
				body += "\nmax_cred_source_rotation_period = \"" + tt.maxStr + "\"\n"
			}
			_, err := loadFromHCL(t, body)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadConfig_SpecRotationPeriodBounds(t *testing.T) {
	// Same shape as source bounds — keep one focused case to confirm the
	// spec variant is wired up too.
	body := minimalConfigHCL + `
min_cred_spec_rotation_period = "1h"
max_cred_spec_rotation_period = "5m"
`
	_, err := loadFromHCL(t, body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min_cred_spec_rotation_period")
	assert.Contains(t, err.Error(), "must be <=")
}

func TestLoadConfig_ListenerTLSRequiresCertAndKey(t *testing.T) {
	tests := []struct {
		name    string
		extra   string
		wantErr bool
	}{
		{
			name: "tls disabled, no cert/key — ok",
			extra: `
listener "tcp" {
  address = ":8410"
  tls_enabled = false
}
`,
			wantErr: false,
		},
		{
			name: "tls enabled with both cert and key — ok",
			extra: `
listener "tcp" {
  address     = ":8420"
  tls_enabled = true
  tls_cert_file = "/c.pem"
  tls_key_file  = "/k.pem"
}
`,
			wantErr: false,
		},
		{
			name: "tls enabled, missing cert — error",
			extra: `
listener "tcp" {
  address     = ":8430"
  tls_enabled = true
  tls_key_file = "/k.pem"
}
`,
			wantErr: true,
		},
		{
			name: "tls enabled, missing key — error",
			extra: `
listener "tcp" {
  address     = ":8440"
  tls_enabled = true
  tls_cert_file = "/c.pem"
}
`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadFromHCL(t, minimalConfigHCL+tt.extra)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "tls_enabled")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoadConfig_ClusterAddrValidation(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr string
	}{
		{"unset", "", ""},
		{"valid https", "https://node1.warden.svc:8401", ""},
		{"http scheme rejected", "http://node1.warden.svc:8401", "https://"},
		{"no scheme rejected", "node1.warden.svc:8401", "https://"},
		{"no host rejected", "https://", "must include a host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := minimalConfigHCL
			if tt.addr != "" {
				body += "\ncluster_addr = \"" + tt.addr + "\"\n"
			}
			_, err := loadFromHCL(t, body)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadConfig_ClusterDurationFields(t *testing.T) {
	tests := []struct {
		field   string
		value   string
		wantErr bool
	}{
		{"goroutine_shutdown_timeout", "30s", false},
		{"goroutine_shutdown_timeout", "1h", false},
		{"goroutine_shutdown_timeout", "0", false}, // zero is allowed (means "use default" semantically)
		{"goroutine_shutdown_timeout", "not-a-duration", true},
		{"goroutine_shutdown_timeout", "-30s", true},
		{"lock_acquisition_timeout", "5m", false},
		{"leader_lookup_timeout", "10s", false},
		{"forwarding_timeout", "1m", false},
	}
	for _, tt := range tests {
		t.Run(tt.field+"="+tt.value, func(t *testing.T) {
			body := minimalConfigHCL + "\n" + tt.field + " = \"" + tt.value + "\"\n"
			_, err := loadFromHCL(t, body)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.field)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDevConfig_Defaults(t *testing.T) {
	cfg := DevConfig()
	assert.Equal(t, "trace", cfg.LogLevel)
	require.NotNil(t, cfg.Storage)
	assert.Equal(t, "inmem", cfg.Storage.Type)
	require.Len(t, cfg.Listeners, 1)
	assert.Equal(t, "tcp", cfg.Listeners[0].Type)
	assert.Equal(t, "127.0.0.1:8400", cfg.Listeners[0].Address)
	assert.False(t, cfg.Listeners[0].TLSEnabled)
	assert.Equal(t, "disabled", cfg.IPBindingPolicy)
}

func TestGetListenerByType(t *testing.T) {
	cfg := &Config{
		Listeners: []ListenerBlock{
			{Type: "tcp", Address: ":8400"},
			{Type: "unix", Address: "/var/run/warden.sock"},
		},
	}
	tcp, err := cfg.GetTCPListener()
	require.NoError(t, err)
	assert.Equal(t, ":8400", tcp.Address)

	unix, err := cfg.GetUnixListener()
	require.NoError(t, err)
	assert.Equal(t, "/var/run/warden.sock", unix.Address)

	_, err = cfg.GetListenerByType("missing")
	require.Error(t, err)
}

func TestStorageBlock_Config(t *testing.T) {
	t.Run("postgres with all fields", func(t *testing.T) {
		s := &StorageBlock{
			Type:               "postgres",
			ConnectionUrl:      "postgres://u:p@db:5432/warden",
			Table:              "kv_store",
			MaxIdleConnections: 5,
			MaxParallel:        "128",
			HAEnabled:          "true",
			HATable:            "ha_locks",
			SkipCreateTable:    "false",
			MaxConnectRetries:  "10",
		}
		got := s.Config()
		assert.Equal(t, "postgres", got["type"])
		assert.Equal(t, "postgres://u:p@db:5432/warden", got["connection_url"])
		assert.Equal(t, "kv_store", got["table"])
		assert.Equal(t, "5", got["max_idle_connections"])
		assert.Equal(t, "128", got["max_parallel"])
		assert.Equal(t, "true", got["ha_enabled"])
		assert.Equal(t, "ha_locks", got["ha_table"])
		assert.Equal(t, "false", got["skip_create_table"])
		assert.Equal(t, "10", got["max_connect_retries"])
	})

	t.Run("inmem with no extra fields", func(t *testing.T) {
		s := &StorageBlock{Type: "inmem"}
		got := s.Config()
		assert.Equal(t, "inmem", got["type"])
		_, hasURL := got["connection_url"]
		assert.False(t, hasURL, "empty fields should not appear in the map")
		_, hasTable := got["table"]
		assert.False(t, hasTable)
	})

	t.Run("file backend uses path", func(t *testing.T) {
		s := &StorageBlock{Type: "file", Path: "/var/lib/warden/data"}
		got := s.Config()
		assert.Equal(t, "file", got["type"])
		assert.Equal(t, "/var/lib/warden/data", got["path"])
	})

	t.Run("zero MaxIdleConnections omitted", func(t *testing.T) {
		s := &StorageBlock{Type: "postgres", ConnectionUrl: "postgres://x"}
		got := s.Config()
		_, has := got["max_idle_connections"]
		assert.False(t, has, "zero int should be omitted, not serialized as \"0\"")
	})
}

func TestKMS_Config(t *testing.T) {
	t.Run("static seal", func(t *testing.T) {
		k := &KMS{
			Type:         "static",
			CurrentKeyID: "2026-05-15",
			CurrentKey:   "file:///seal/key",
		}
		got := k.Config()
		assert.Equal(t, "static", got["type"])
		assert.Equal(t, "2026-05-15", got["current_key_id"])
		assert.Equal(t, "file:///seal/key", got["current_key"])
	})

	t.Run("transit seal", func(t *testing.T) {
		k := &KMS{
			Type:      "transit",
			Address:   "https://vault.example.com:8200",
			Token:     "s.abc123",
			KeyName:   "warden-unseal",
			MountPath: "transit/",
			Namespace: "ops",
		}
		got := k.Config()
		assert.Equal(t, "transit", got["type"])
		assert.Equal(t, "https://vault.example.com:8200", got["address"])
		assert.Equal(t, "s.abc123", got["token"])
		assert.Equal(t, "warden-unseal", got["key_name"])
		assert.Equal(t, "transit/", got["mount_path"])
		assert.Equal(t, "ops", got["namespace"])
	})

	t.Run("aws kms seal", func(t *testing.T) {
		k := &KMS{
			Type:      "awskms",
			AwsRegion: "us-east-1",
			AccessKey: "AKIA...",
			SecretKey: "secret",
			KmsKeyID:  "arn:aws:kms:us-east-1:111:key/abc",
		}
		got := k.Config()
		assert.Equal(t, "awskms", got["type"])
		assert.Equal(t, "us-east-1", got["aws_region"])
		assert.Equal(t, "AKIA...", got["access_key"])
		assert.Equal(t, "arn:aws:kms:us-east-1:111:key/abc", got["kms_key_id"])
	})

	t.Run("purpose list expanded", func(t *testing.T) {
		k := &KMS{Type: "static", Purpose: []string{"keyring", "recovery"}}
		got := k.Config()
		assert.Equal(t, "keyring", got["purpose_0"])
		assert.Equal(t, "recovery", got["purpose_1"])
	})

	t.Run("empty optional fields omitted", func(t *testing.T) {
		k := &KMS{Type: "static"}
		got := k.Config()
		assert.Equal(t, "static", got["type"])
		_, has := got["current_key_id"]
		assert.False(t, has)
		_, has = got["address"]
		assert.False(t, has)
	})
}

func TestKMS_IsDisabled(t *testing.T) {
	// Pins the current — counterintuitive — semantics of KMS.IsDisabled():
	// returns true iff Disabled is non-empty AND not literally "true". This
	// matches the underlying Vault/OpenBao convention where the Disabled
	// field carries a seal-type-name sentinel during seal migration, and an
	// empty value or the literal string "true" both mean "not migrating".
	tests := []struct {
		disabled string
		want     bool
	}{
		{"", false},
		{"true", false},
		{"false", true},
		{"yes", true},
		{"awskms", true},
	}
	for _, tt := range tests {
		t.Run(tt.disabled, func(t *testing.T) {
			k := &KMS{Disabled: tt.disabled}
			assert.Equal(t, tt.want, k.IsDisabled())
		})
	}
}

func TestMergeConfig(t *testing.T) {
	t.Run("scalar fields take overlay non-zero values", func(t *testing.T) {
		base := &Config{LogLevel: "info", APIAddr: "https://base:8400"}
		overlay := &Config{LogLevel: "debug"}
		mergeConfig(base, overlay)
		assert.Equal(t, "debug", base.LogLevel, "overlay overrides")
		assert.Equal(t, "https://base:8400", base.APIAddr, "unset overlay field leaves base intact")
	})

	t.Run("storage pointer replaces wholesale", func(t *testing.T) {
		base := &Config{Storage: &StorageBlock{Type: "postgres", ConnectionUrl: "postgres://base"}}
		overlay := &Config{Storage: &StorageBlock{Type: "postgres", ConnectionUrl: "postgres://overlay"}}
		mergeConfig(base, overlay)
		require.NotNil(t, base.Storage)
		assert.Equal(t, "postgres://overlay", base.Storage.ConnectionUrl)
	})

	t.Run("nil storage in overlay preserves base", func(t *testing.T) {
		base := &Config{Storage: &StorageBlock{Type: "postgres", ConnectionUrl: "postgres://base"}}
		overlay := &Config{}
		mergeConfig(base, overlay)
		require.NotNil(t, base.Storage)
		assert.Equal(t, "postgres://base", base.Storage.ConnectionUrl)
	})

	t.Run("listeners slice replaces wholesale", func(t *testing.T) {
		base := &Config{Listeners: []ListenerBlock{{Type: "tcp", Address: ":8400"}}}
		overlay := &Config{Listeners: []ListenerBlock{{Type: "tcp", Address: ":9999"}, {Type: "unix", Address: "/sock"}}}
		mergeConfig(base, overlay)
		require.Len(t, base.Listeners, 2)
		assert.Equal(t, ":9999", base.Listeners[0].Address)
	})

	t.Run("empty listeners in overlay preserves base", func(t *testing.T) {
		base := &Config{Listeners: []ListenerBlock{{Type: "tcp", Address: ":8400"}}}
		overlay := &Config{}
		mergeConfig(base, overlay)
		require.Len(t, base.Listeners, 1)
		assert.Equal(t, ":8400", base.Listeners[0].Address)
	})

	t.Run("seals slice replaces wholesale", func(t *testing.T) {
		base := &Config{Seals: []KMS{{Type: "static"}}}
		overlay := &Config{Seals: []KMS{{Type: "transit"}, {Type: "static"}}}
		mergeConfig(base, overlay)
		require.Len(t, base.Seals, 2)
		assert.Equal(t, "transit", base.Seals[0].Type)
	})

	t.Run("bool fields can be set true but not turned off", func(t *testing.T) {
		base := &Config{DisableClustering: true}
		overlay := &Config{DisableClustering: false}
		mergeConfig(base, overlay)
		assert.True(t, base.DisableClustering, "overlay false does not turn off — documented limitation")

		base2 := &Config{}
		overlay2 := &Config{DisableClustering: true}
		mergeConfig(base2, overlay2)
		assert.True(t, base2.DisableClustering)
	})

	t.Run("int fields take overlay non-zero", func(t *testing.T) {
		base := &Config{LogRotateMegabytes: 100}
		overlay := &Config{LogRotateMegabytes: 500}
		mergeConfig(base, overlay)
		assert.Equal(t, 500, base.LogRotateMegabytes)
	})
}
