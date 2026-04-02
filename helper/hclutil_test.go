package helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig_HCL(t *testing.T) {
	data := []byte(`listener "tcp" { address = "0.0.0.0:8200" }`)
	file, err := ParseConfig(data)
	require.NoError(t, err)
	assert.NotNil(t, file)
}

func TestParseConfig_JSON(t *testing.T) {
	data := []byte(`{"listener": {"tcp": {"address": "0.0.0.0:8200"}}}`)
	file, err := ParseConfig(data)
	require.NoError(t, err)
	assert.NotNil(t, file)
}

func TestParseConfig_InvalidHCL(t *testing.T) {
	data := []byte(`{{{invalid}}}`)
	_, err := ParseConfig(data)
	assert.Error(t, err)
}

func TestIsJson(t *testing.T) {
	assert.True(t, isJson([]byte(`{"key": "value"}`)))
	assert.True(t, isJson([]byte(`  { "key": "value" }`)))
	assert.False(t, isJson([]byte(`listener "tcp" {}`)))
	assert.False(t, isJson([]byte(``)))
}

func TestCheckHCLKeys(t *testing.T) {
	data := []byte(`key1 = "val1"
key2 = "val2"
key3 = "val3"`)

	file, err := ParseConfig(data)
	require.NoError(t, err)

	t.Run("all valid", func(t *testing.T) {
		err := CheckHCLKeys(file.Node, []string{"key1", "key2", "key3"})
		assert.NoError(t, err)
	})

	t.Run("invalid key", func(t *testing.T) {
		err := CheckHCLKeys(file.Node, []string{"key1"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key2")
	})
}
