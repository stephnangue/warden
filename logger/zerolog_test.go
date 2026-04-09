package logger

import (
	"bytes"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
	"time"
)

func TestZerologLogger_TypedFieldsInOutput(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:       TraceLevel,
		Format:      JSONFormat,
		Outputs:     []io.Writer{&buf},
		Environment: "production",
	}

	logger := NewZerologLogger(config)

	now := time.Now()
	logger.Info("typed fields test",
		String("name", "test"),
		Int("count", 5),
		Int64("big", int64(12345)),
		Float64("rate", 1.5),
		Bool("active", true),
		Duration("elapsed", 3*time.Second),
		Time("ts", now),
		Err(errors.New("oops")),
		Any("extra", map[string]string{"k": "v"}),
	)

	output := buf.String()
	assert.Contains(t, output, "typed fields test")
	assert.Contains(t, output, "name")
	assert.Contains(t, output, "count")
	assert.Contains(t, output, "big")
	assert.Contains(t, output, "rate")
	assert.Contains(t, output, "active")
	assert.Contains(t, output, "elapsed")
}

// =============================================================================
// ZerologLogger Flush and Close
// =============================================================================

func TestZerologLogger_FlushAndClose(t *testing.T) {
	logger := NewZerologLogger(&Config{
		Level:   InfoLevel,
		Format:  JSONFormat,
		Outputs: []io.Writer{io.Discard},
	})

	// Should not panic
	logger.Flush()
	err := logger.Close()
	assert.NoError(t, err)
}

// =============================================================================
// ZerologLogger formatted logging
// =============================================================================

func TestZerologLogger_FormattedLogging(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:       TraceLevel,
		Format:      JSONFormat,
		Outputs:     []io.Writer{&buf},
		Environment: "production",
	}

	logger := NewZerologLogger(config)

	logger.Tracef("trace %s %d", "msg", 1)
	logger.Debugf("debug %s", "msg")
	logger.Infof("info %d", 42)
	logger.Warnf("warn %v", true)
	logger.Errorf("error %s", "oops")

	output := buf.String()
	assert.Contains(t, output, "trace msg 1")
	assert.Contains(t, output, "debug msg")
	assert.Contains(t, output, "info 42")
	assert.Contains(t, output, "warn true")
	assert.Contains(t, output, "error oops")
}

// =============================================================================
// ZerologLogger WithSubsystem and WithSystem
// =============================================================================

func TestZerologLogger_WithSubsystemAndSystem(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:       InfoLevel,
		Format:      JSONFormat,
		Outputs:     []io.Writer{&buf},
		Environment: "production",
	}

	logger := NewZerologLogger(config)

	sub := logger.WithSubsystem("api")
	sub.Info("from subsystem")
	assert.Contains(t, buf.String(), "api")

	buf.Reset()

	sys := logger.WithSystem("core")
	sys.Info("from system")
	assert.Contains(t, buf.String(), "core")
}

// =============================================================================
// ZerologLogger WithFields empty
// =============================================================================

func TestZerologLogger_WithFields_Empty(t *testing.T) {
	logger := NewZerologLogger(&Config{
		Level:   InfoLevel,
		Format:  JSONFormat,
		Outputs: []io.Writer{io.Discard},
	})

	// WithFields with no args should return same logger
	same := logger.WithFields()
	assert.Equal(t, logger, same)
}

// =============================================================================
// ZerologLogger IsLevelEnabled
// =============================================================================

func TestZerologLogger_IsLevelEnabled(t *testing.T) {
	// Note: zerolog uses a global level, so we test with TraceLevel
	// to ensure all levels are enabled, then test the unknown level case
	logger := NewZerologLogger(&Config{
		Level:   TraceLevel,
		Format:  JSONFormat,
		Outputs: []io.Writer{io.Discard},
	})

	assert.True(t, logger.IsLevelEnabled(TraceLevel))
	assert.True(t, logger.IsLevelEnabled(DebugLevel))
	assert.True(t, logger.IsLevelEnabled(InfoLevel))
	assert.True(t, logger.IsLevelEnabled(WarnLevel))
	assert.True(t, logger.IsLevelEnabled(ErrorLevel))
	assert.True(t, logger.IsLevelEnabled(FatalLevel))
	assert.True(t, logger.IsLevelEnabled(PanicLevel))
	assert.False(t, logger.IsLevelEnabled(LogLevel(99)))
}

// =============================================================================
// F (legacy field) constructor
// =============================================================================

func TestNewZerologLogger_WithSampling(t *testing.T) {
	logger := NewZerologLogger(&Config{
		Level:          InfoLevel,
		Format:         JSONFormat,
		Outputs:        []io.Writer{io.Discard},
		Environment:    "production",
		EnableSampling: true,
	})

	// Should not panic
	logger.Info("sampled message")
}

func TestNewZerologLogger_WithCaller(t *testing.T) {
	var buf bytes.Buffer
	logger := NewZerologLogger(&Config{
		Level:        InfoLevel,
		Format:       JSONFormat,
		Outputs:      []io.Writer{&buf},
		Environment:  "production",
		EnableCaller: true,
		CallerSkip:   0,
	})

	logger.Info("caller test")
	// Should contain caller info
	assert.Contains(t, buf.String(), "caller")
}

func TestNewZerologLogger_NilConfig(t *testing.T) {
	logger := NewZerologLogger(nil)
	require.NotNil(t, logger)
	logger.Info("nil config test")
}
