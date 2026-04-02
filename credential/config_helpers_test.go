package credential

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetString(t *testing.T) {
	cfg := map[string]string{"key": "value"}
	assert.Equal(t, "value", GetString(cfg, "key", "default"))
	assert.Equal(t, "default", GetString(cfg, "missing", "default"))
}

func TestGetStringRequired(t *testing.T) {
	cfg := map[string]string{"key": "value", "empty": ""}

	v, err := GetStringRequired(cfg, "key")
	require.NoError(t, err)
	assert.Equal(t, "value", v)

	_, err = GetStringRequired(cfg, "missing")
	assert.Error(t, err)

	_, err = GetStringRequired(cfg, "empty")
	assert.Error(t, err)
}

func TestGetInt(t *testing.T) {
	cfg := map[string]string{"num": "42", "bad": "abc"}
	assert.Equal(t, 42, GetInt(cfg, "num", 0))
	assert.Equal(t, 0, GetInt(cfg, "bad", 0))
	assert.Equal(t, 99, GetInt(cfg, "missing", 99))
}

func TestGetIntRequired(t *testing.T) {
	cfg := map[string]string{"num": "42", "bad": "abc"}

	v, err := GetIntRequired(cfg, "num")
	require.NoError(t, err)
	assert.Equal(t, 42, v)

	_, err = GetIntRequired(cfg, "bad")
	assert.Error(t, err)

	_, err = GetIntRequired(cfg, "missing")
	assert.Error(t, err)
}

func TestGetInt64(t *testing.T) {
	cfg := map[string]string{"num": "1234567890", "bad": "abc"}
	assert.Equal(t, int64(1234567890), GetInt64(cfg, "num", 0))
	assert.Equal(t, int64(0), GetInt64(cfg, "bad", 0))
	assert.Equal(t, int64(99), GetInt64(cfg, "missing", 99))
}

func TestGetBool(t *testing.T) {
	cfg := map[string]string{"yes": "true", "no": "false", "one": "1", "bad": "abc"}
	assert.True(t, GetBool(cfg, "yes", false))
	assert.False(t, GetBool(cfg, "no", true))
	assert.True(t, GetBool(cfg, "one", false))
	assert.False(t, GetBool(cfg, "bad", false))
	assert.True(t, GetBool(cfg, "missing", true))
}

func TestGetBoolRequired(t *testing.T) {
	cfg := map[string]string{"yes": "true", "bad": "abc"}

	v, err := GetBoolRequired(cfg, "yes")
	require.NoError(t, err)
	assert.True(t, v)

	_, err = GetBoolRequired(cfg, "bad")
	assert.Error(t, err)

	_, err = GetBoolRequired(cfg, "missing")
	assert.Error(t, err)
}

func TestGetDuration(t *testing.T) {
	cfg := map[string]string{"ttl": "30s", "bad": "abc"}
	assert.Equal(t, 30*time.Second, GetDuration(cfg, "ttl", time.Minute))
	assert.Equal(t, time.Minute, GetDuration(cfg, "bad", time.Minute))
	assert.Equal(t, time.Hour, GetDuration(cfg, "missing", time.Hour))
}

func TestGetDurationRequired(t *testing.T) {
	cfg := map[string]string{"ttl": "5m", "bad": "abc"}

	v, err := GetDurationRequired(cfg, "ttl")
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, v)

	_, err = GetDurationRequired(cfg, "bad")
	assert.Error(t, err)

	_, err = GetDurationRequired(cfg, "missing")
	assert.Error(t, err)
}

func TestValidateRequired(t *testing.T) {
	cfg := map[string]string{"a": "1", "b": "2", "empty": ""}

	assert.NoError(t, ValidateRequired(cfg, "a", "b"))
	assert.Error(t, ValidateRequired(cfg, "a", "missing"))
	assert.Error(t, ValidateRequired(cfg, "empty"))
	assert.NoError(t, ValidateRequired(cfg))
}
