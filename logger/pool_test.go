package logger

import (
	"io"
	"testing"
	"github.com/stretchr/testify/require"
)

func TestLoggerPool(t *testing.T) {
	config := DefaultConfig()
	config.Format = JSONFormat
	config.Environment = "production"
	config.Outputs = []io.Writer{io.Discard}

	pool := NewLoggerPool(config)
	require.NotNil(t, pool)

	// Get a logger
	l := pool.Get()
	require.NotNil(t, l)

	// Use it (should not panic)
	l.Info("pool test")

	// Return it
	pool.Put(l)

	// Get again (may be recycled)
	l2 := pool.Get()
	require.NotNil(t, l2)
}

// =============================================================================
// GatedLogger with nil config
// =============================================================================

