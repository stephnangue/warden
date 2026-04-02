package gcp

import (
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stretchr/testify/assert"
)

func TestParseConfig_Extended(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		config := parseConfig(map[string]any{})
		assert.Equal(t, framework.DefaultMaxBodySize, config.MaxBodySize)
		assert.Equal(t, framework.DefaultTimeout, config.Timeout)
	})

	t.Run("custom timeout string", func(t *testing.T) {
		config := parseConfig(map[string]any{"timeout": "60s"})
		assert.Equal(t, 60.0, config.Timeout.Seconds())
	})

	t.Run("integer timeout", func(t *testing.T) {
		config := parseConfig(map[string]any{"timeout": 45})
		assert.Equal(t, 45.0, config.Timeout.Seconds())
	})

	t.Run("float timeout", func(t *testing.T) {
		config := parseConfig(map[string]any{"timeout": 30.0})
		assert.Equal(t, 30.0, config.Timeout.Seconds())
	})

	t.Run("int64 max_body_size", func(t *testing.T) {
		config := parseConfig(map[string]any{"max_body_size": int64(5242880)})
		assert.Equal(t, int64(5242880), config.MaxBodySize)
	})

	t.Run("float max_body_size", func(t *testing.T) {
		config := parseConfig(map[string]any{"max_body_size": 5242880.0})
		assert.Equal(t, int64(5242880), config.MaxBodySize)
	})

	t.Run("string max_body_size", func(t *testing.T) {
		config := parseConfig(map[string]any{"max_body_size": "5242880"})
		assert.Equal(t, int64(5242880), config.MaxBodySize)
	})

	t.Run("auth settings", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		})
		assert.Equal(t, "auth/jwt/", config.AutoAuthPath)
		assert.Equal(t, "reader", config.DefaultAuthRole)
	})
}

func TestValidateConfig_Extended(t *testing.T) {
	t.Run("empty config valid", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{}))
	})

	t.Run("valid config", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{
			"max_body_size":  1024,
			"timeout":        "30s",
			"auto_auth_path": "auth/jwt/",
		}))
	})

	t.Run("invalid timeout", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"timeout": "bad"}))
	})

	t.Run("negative max_body_size", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": -1}))
	})

	t.Run("oversized max_body_size", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": 200000000}))
	})

	t.Run("unknown key rejected", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"unknown_key": "val"}))
	})

	t.Run("invalid timeout type", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"timeout": []string{"bad"}}))
	})

	t.Run("negative timeout", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"timeout": -1}))
	})

	t.Run("negative timeout float", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"timeout": -1.0}))
	})

	t.Run("invalid max_body_size type", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": true}))
	})

	t.Run("string max_body_size valid", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{"max_body_size": "1024"}))
	})

	t.Run("string max_body_size invalid", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": "not-a-number"}))
	})

	t.Run("non-string auto_auth_path", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"auto_auth_path": 123}))
	})

	t.Run("non-string default_role", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"default_role": 123}))
	})
}
