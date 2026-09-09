package credential

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyKeyMap(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		keyMap   string
		expected map[string]interface{}
	}{
		{
			name: "basic remapping",
			data: map[string]interface{}{
				"accessKeyId": "AKIA123",
				"secretKey":   "secret123",
			},
			keyMap: "accessKeyId=access_key_id,secretKey=secret_access_key",
			expected: map[string]interface{}{
				"access_key_id":     "AKIA123",
				"secret_access_key": "secret123",
			},
		},
		{
			name: "missing source key",
			data: map[string]interface{}{
				"accessKeyId": "AKIA123",
			},
			keyMap: "accessKeyId=access_key_id,missing=other",
			expected: map[string]interface{}{
				"access_key_id": "AKIA123",
			},
		},
		{
			name: "whitespace handling",
			data: map[string]interface{}{
				"key1": "val1",
			},
			keyMap: " key1 = mapped_key1 ",
			expected: map[string]interface{}{
				"mapped_key1": "val1",
			},
		},
		{
			// The selection is a disclosure boundary: what it does not name, it
			// does not vend.
			name: "unnamed keys are dropped",
			data: map[string]interface{}{
				"api_key":     "sk-abc",
				"admin_token": "root-secret",
				"note":        "internal",
			},
			keyMap:   "api_key=api_key",
			expected: map[string]interface{}{"api_key": "sk-abc"},
		},
		{
			name: "no selection passes the payload through untouched",
			data: map[string]interface{}{
				"api_key": "sk-abc",
				"note":    "internal",
			},
			keyMap: "",
			expected: map[string]interface{}{
				"api_key": "sk-abc",
				"note":    "internal",
			},
		},
		{
			name:     "no pair matches yields an empty payload",
			data:     map[string]interface{}{"api_key": "sk-abc"},
			keyMap:   "typo=api_key",
			expected: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ApplyKeyMap(tt.data, tt.keyMap))
		})
	}
}

func TestValidateSecretSelection(t *testing.T) {
	tests := []struct {
		name       string
		config     Config
		sourceType string
		wantErr    string
	}{
		{
			name:       "json_key_map on a KV read",
			config:     NewConfig(map[string]string{"mint_method": "kv2_read", "json_key_map": "token=api_key"}),
			sourceType: SourceTypeVault,
		},
		{
			name:       "json_key_map on a Secrets Manager read",
			config:     NewConfig(map[string]string{"mint_method": "secrets_manager", "json_key_map": "token=api_key"}),
			sourceType: SourceTypeAWS,
		},
		{
			name:       "secret_version on a KV read",
			config:     NewConfig(map[string]string{"mint_method": "static_aws", "secret_version": "3"}),
			sourceType: SourceTypeVault,
		},
		{
			// secret_version predates this check on the Key Vault fetch, where it
			// is an opaque identifier rather than a number. Rejecting it there
			// would break every pinned Key Vault spec already written.
			name:       "secret_version on a Key Vault read",
			config:     NewConfig(map[string]string{"mint_method": "key_vault_secret", "secret_version": "abc123def456"}),
			sourceType: SourceTypeAzure,
		},
		{
			// The Key Vault fetch returns one secret, not a document to pick from.
			name:       "json_key_map on a Key Vault read",
			config:     NewConfig(map[string]string{"mint_method": "key_vault_secret", "json_key_map": "a=b"}),
			sourceType: SourceTypeAzure,
			wantErr:    "'json_key_map' selects fields of a stored secret",
		},
		{
			name:       "neither key set is always fine",
			config:     NewConfig(map[string]string{"mint_method": "dynamic_gcp"}),
			sourceType: SourceTypeVault,
		},
		{
			name:       "json_key_map on a mint method that builds its own payload",
			config:     NewConfig(map[string]string{"mint_method": "dynamic_aws", "json_key_map": "a=b"}),
			sourceType: SourceTypeVault,
			wantErr:    "'json_key_map' selects fields of a stored secret",
		},
		{
			name:       "json_key_map on an STS mint",
			config:     NewConfig(map[string]string{"mint_method": "sts_assume_role", "json_key_map": "a=b"}),
			sourceType: SourceTypeAWS,
			wantErr:    "'json_key_map' selects fields of a stored secret",
		},
		{
			// Secrets Manager addresses revisions as version_id / version_stage,
			// so a numbered version there would silently do nothing.
			name:       "secret_version on a Secrets Manager read",
			config:     NewConfig(map[string]string{"mint_method": "secrets_manager", "secret_version": "3"}),
			sourceType: SourceTypeAWS,
			wantErr:    "'secret_version' pins a revision",
		},
		{
			// secret_read reads the same store, so the same projection applies...
			name:       "json_key_map on a stored-secret read",
			config:     NewConfig(map[string]string{"mint_method": "secret_read", "json_key_map": "k=api_key"}),
			sourceType: SourceTypeAWS,
		},
		{
			// ...and the same revision addressing, which is not a number.
			name:       "secret_version on a stored-secret read",
			config:     NewConfig(map[string]string{"mint_method": "secret_read", "secret_version": "3"}),
			sourceType: SourceTypeAWS,
			wantErr:    "'secret_version' pins a revision",
		},
		{
			name:       "secret_version on a dynamic mint",
			config:     NewConfig(map[string]string{"mint_method": "dynamic_ibm", "secret_version": "3"}),
			sourceType: SourceTypeVault,
			wantErr:    "'secret_version' pins a revision",
		},
		{
			// ApplyKeyMap skips a pair it cannot split, so without this check the
			// spec would write, mint, and quietly omit organization_id.
			name:       "key map entry missing its separator",
			config:     NewConfig(map[string]string{"mint_method": "kv2_read", "json_key_map": "token=api_key,org_id:organization_id"}),
			sourceType: SourceTypeVault,
			wantErr:    "must read 'srcKey=destKey'",
		},
		{
			name:       "key map entry with an empty destination",
			config:     NewConfig(map[string]string{"mint_method": "kv2_read", "json_key_map": "token="}),
			sourceType: SourceTypeVault,
			wantErr:    "must read 'srcKey=destKey'",
		},
		{
			name:       "key map entry with an empty source",
			config:     NewConfig(map[string]string{"mint_method": "kv2_read", "json_key_map": "=api_key"}),
			sourceType: SourceTypeVault,
			wantErr:    "must read 'srcKey=destKey'",
		},
		{
			name:       "key map with a trailing comma",
			config:     NewConfig(map[string]string{"mint_method": "kv2_read", "json_key_map": "token=api_key,"}),
			sourceType: SourceTypeVault,
			wantErr:    "empty entry",
		},
		{
			name:       "key map with a duplicated destination",
			config:     NewConfig(map[string]string{"mint_method": "kv2_read", "json_key_map": "token=api_key,pat=api_key"}),
			sourceType: SourceTypeVault,
			wantErr:    "more than one field to 'api_key'",
		},
		{
			name:       "well-formed multi-pair key map with padding",
			config:     NewConfig(map[string]string{"mint_method": "kv2_read", "json_key_map": " token = api_key , org_id = organization_id "}),
			sourceType: SourceTypeVault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretSelection(tt.config, tt.sourceType)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestGetString(t *testing.T) {
	cfg := map[string]string{"key": "value"}
	assert.Equal(t, "value", GetString(NewConfig(cfg), "key", "default"))
	assert.Equal(t, "default", GetString(NewConfig(cfg), "missing", "default"))
}

func TestGetStringRequired(t *testing.T) {
	cfg := map[string]string{"key": "value", "empty": ""}

	v, err := GetStringRequired(NewConfig(cfg), "key")
	require.NoError(t, err)
	assert.Equal(t, "value", v)

	_, err = GetStringRequired(NewConfig(cfg), "missing")
	assert.Error(t, err)

	_, err = GetStringRequired(NewConfig(cfg), "empty")
	assert.Error(t, err)
}

func TestGetInt(t *testing.T) {
	cfg := map[string]string{"num": "42", "bad": "abc"}
	assert.Equal(t, 42, GetInt(NewConfig(cfg), "num", 0))
	assert.Equal(t, 0, GetInt(NewConfig(cfg), "bad", 0))
	assert.Equal(t, 99, GetInt(NewConfig(cfg), "missing", 99))
}

func TestGetIntRequired(t *testing.T) {
	cfg := map[string]string{"num": "42", "bad": "abc"}

	v, err := GetIntRequired(NewConfig(cfg), "num")
	require.NoError(t, err)
	assert.Equal(t, 42, v)

	_, err = GetIntRequired(NewConfig(cfg), "bad")
	assert.Error(t, err)

	_, err = GetIntRequired(NewConfig(cfg), "missing")
	assert.Error(t, err)
}

func TestGetInt64(t *testing.T) {
	cfg := map[string]string{"num": "1234567890", "bad": "abc"}
	assert.Equal(t, int64(1234567890), GetInt64(NewConfig(cfg), "num", 0))
	assert.Equal(t, int64(0), GetInt64(NewConfig(cfg), "bad", 0))
	assert.Equal(t, int64(99), GetInt64(NewConfig(cfg), "missing", 99))
}

func TestGetBool(t *testing.T) {
	cfg := map[string]string{"yes": "true", "no": "false", "one": "1", "bad": "abc"}
	assert.True(t, GetBool(NewConfig(cfg), "yes", false))
	assert.False(t, GetBool(NewConfig(cfg), "no", true))
	assert.True(t, GetBool(NewConfig(cfg), "one", false))
	assert.False(t, GetBool(NewConfig(cfg), "bad", false))
	assert.True(t, GetBool(NewConfig(cfg), "missing", true))
}

func TestGetBoolRequired(t *testing.T) {
	cfg := map[string]string{"yes": "true", "bad": "abc"}

	v, err := GetBoolRequired(NewConfig(cfg), "yes")
	require.NoError(t, err)
	assert.True(t, v)

	_, err = GetBoolRequired(NewConfig(cfg), "bad")
	assert.Error(t, err)

	_, err = GetBoolRequired(NewConfig(cfg), "missing")
	assert.Error(t, err)
}

func TestGetDuration(t *testing.T) {
	cfg := map[string]string{"ttl": "30s", "bad": "abc"}
	assert.Equal(t, 30*time.Second, GetDuration(NewConfig(cfg), "ttl", time.Minute))
	assert.Equal(t, time.Minute, GetDuration(NewConfig(cfg), "bad", time.Minute))
	assert.Equal(t, time.Hour, GetDuration(NewConfig(cfg), "missing", time.Hour))
}

func TestGetDurationRequired(t *testing.T) {
	cfg := map[string]string{"ttl": "5m", "bad": "abc"}

	v, err := GetDurationRequired(NewConfig(cfg), "ttl")
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, v)

	_, err = GetDurationRequired(NewConfig(cfg), "bad")
	assert.Error(t, err)

	_, err = GetDurationRequired(NewConfig(cfg), "missing")
	assert.Error(t, err)
}

func TestGetPrefixed(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		prefix string
		want   map[string]string
	}{
		{
			name:   "empty config",
			config: NewConfig(map[string]string{}),
			prefix: "token_param.",
			want:   map[string]string{},
		},
		{
			name:   "no matching prefix",
			config: NewConfig(map[string]string{"client_id": "test", "scope": "read"}),
			prefix: "token_param.",
			want:   map[string]string{},
		},
		{
			name:   "single match",
			config: NewConfig(map[string]string{"token_param.resource": "urn:dtaccount:123", "client_id": "test"}),
			prefix: "token_param.",
			want:   map[string]string{"resource": "urn:dtaccount:123"},
		},
		{
			name: "multiple matches",
			config: NewConfig(map[string]string{
				"token_param.resource": "urn:dtaccount:123",
				"token_param.audience": "https://api.example.com",
				"client_id":            "test",
			}),
			prefix: "token_param.",
			want:   map[string]string{"resource": "urn:dtaccount:123", "audience": "https://api.example.com"},
		},
		{
			name:   "key equal to prefix is skipped",
			config: NewConfig(map[string]string{"token_param.": "value"}),
			prefix: "token_param.",
			want:   map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPrefixed(tt.config, tt.prefix)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateRequired(t *testing.T) {
	cfg := map[string]string{"a": "1", "b": "2", "empty": ""}

	assert.NoError(t, ValidateRequired(NewConfig(cfg), "a", "b"))
	assert.Error(t, ValidateRequired(NewConfig(cfg), "a", "missing"))
	assert.Error(t, ValidateRequired(NewConfig(cfg), "empty"))
	assert.NoError(t, ValidateRequired(NewConfig(cfg)))
}
