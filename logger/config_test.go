package logger

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProductionConfig(t *testing.T) {
	config := ProductionConfig("myapp")

	assert.Equal(t, InfoLevel, config.Level)
	assert.Equal(t, JSONFormat, config.Format)
	assert.Equal(t, "production", config.Environment)
	assert.True(t, config.EnableCaller)
	assert.True(t, config.EnableSampling)
	require.NotNil(t, config.FileConfig)
	assert.Equal(t, "logs/myapp.log", config.FileConfig.Filename)
	assert.Equal(t, 100, config.FileConfig.MaxSize)
	assert.Equal(t, 30, config.FileConfig.MaxAge)
	assert.Equal(t, 10, config.FileConfig.MaxBackups)
	assert.True(t, config.FileConfig.Compress)
}

// =============================================================================
// DefaultFileConfig Tests
// =============================================================================

func TestDefaultFileConfig(t *testing.T) {
	fc := DefaultFileConfig("test.log")

	assert.Equal(t, "test.log", fc.Filename)
	assert.Equal(t, 100, fc.MaxSize)
	assert.Equal(t, 30, fc.MaxAge)
	assert.Equal(t, 10, fc.MaxBackups)
	assert.True(t, fc.Compress)
}

// =============================================================================
// GatedWriter FlushGate and BufferedSize
// =============================================================================
