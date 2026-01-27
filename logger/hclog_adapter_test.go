package logger

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestLogger creates a GatedLogger that writes to a buffer for testing
func createTestLogger(t *testing.T) (*GatedLogger, *bytes.Buffer) {
	buf := &bytes.Buffer{}

	config := &Config{
		Level:   TraceLevel,
		Format:  JSONFormat,
		Outputs: []io.Writer{buf},
	}

	gateConfig := GatedWriterConfig{
		Underlying:   buf,
		InitialState: GateOpen,
	}

	logger, _ := NewGatedLogger(config, gateConfig)
	return logger, buf
}

func TestHCLogAdapter_ImplementsInterface(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Verify it implements hclog.Logger
	var _ hclog.Logger = adapter
}

func TestHCLogAdapter_LogLevels(t *testing.T) {
	tests := []struct {
		name     string
		logFunc  func(adapter hclog.Logger)
		expected string
	}{
		{
			name: "Trace",
			logFunc: func(a hclog.Logger) {
				a.Trace("trace message")
			},
			expected: "trace message",
		},
		{
			name: "Debug",
			logFunc: func(a hclog.Logger) {
				a.Debug("debug message")
			},
			expected: "debug message",
		},
		{
			name: "Info",
			logFunc: func(a hclog.Logger) {
				a.Info("info message")
			},
			expected: "info message",
		},
		{
			name: "Warn",
			logFunc: func(a hclog.Logger) {
				a.Warn("warn message")
			},
			expected: "warn message",
		},
		{
			name: "Error",
			logFunc: func(a hclog.Logger) {
				a.Error("error message")
			},
			expected: "error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, buf := createTestLogger(t)
			adapter := NewHCLogAdapter(logger)

			tt.logFunc(adapter)

			output := buf.String()
			assert.Contains(t, output, tt.expected)
		})
	}
}

func TestHCLogAdapter_LogWithArgs(t *testing.T) {
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	adapter.Info("test message", "key1", "value1", "key2", 42)

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "key1")
	assert.Contains(t, output, "value1")
	assert.Contains(t, output, "key2")
	assert.Contains(t, output, "42")
}

func TestHCLogAdapter_Log(t *testing.T) {
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	adapter.Log(hclog.Info, "log method message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "log method message")
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")
}

func TestHCLogAdapter_Named(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Create named logger
	named := adapter.Named("subsystem1")
	assert.Equal(t, "subsystem1", named.Name())

	// Create nested named logger
	nested := named.Named("subsystem2")
	assert.Equal(t, "subsystem1.subsystem2", nested.Name())
}

func TestHCLogAdapter_With(t *testing.T) {
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Create logger with implied args
	withLogger := adapter.With("implied_key", "implied_value")

	// Verify implied args are returned
	args := withLogger.ImpliedArgs()
	assert.Len(t, args, 2)
	assert.Equal(t, "implied_key", args[0])
	assert.Equal(t, "implied_value", args[1])

	// Log a message - implied args should be included
	withLogger.Info("test message", "extra_key", "extra_value")

	output := buf.String()
	assert.Contains(t, output, "implied_key")
	assert.Contains(t, output, "implied_value")
	assert.Contains(t, output, "extra_key")
	assert.Contains(t, output, "extra_value")
}

func TestHCLogAdapter_WithChained(t *testing.T) {
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Chain multiple With calls
	chained := adapter.With("key1", "value1").With("key2", "value2")

	chained.Info("chained message")

	output := buf.String()
	assert.Contains(t, output, "key1")
	assert.Contains(t, output, "value1")
	assert.Contains(t, output, "key2")
	assert.Contains(t, output, "value2")
}

func TestHCLogAdapter_Name(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Initial name should be empty
	assert.Equal(t, "", adapter.Name())

	// After Named, name should be set
	named := adapter.Named("mylogger")
	assert.Equal(t, "mylogger", named.Name())
}

func TestHCLogAdapter_IsLevelEnabled(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// With TraceLevel config, all levels should be enabled
	assert.True(t, adapter.IsTrace())
	assert.True(t, adapter.IsDebug())
	assert.True(t, adapter.IsInfo())
	assert.True(t, adapter.IsWarn())
	assert.True(t, adapter.IsError())
}

func TestHCLogAdapter_GetLevel(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// With TraceLevel config, GetLevel should return Trace
	level := adapter.GetLevel()
	assert.Equal(t, hclog.Trace, level)
}

func TestHCLogAdapter_SetLevel(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// SetLevel is a no-op but should not panic
	adapter.SetLevel(hclog.Error)
	// Level is controlled by GatedLogger's config, not the adapter
}

func TestHCLogAdapter_StandardLogger(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Should return nil (not supported)
	assert.Nil(t, adapter.StandardLogger(nil))
}

func TestHCLogAdapter_StandardWriter(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Should return nil (not supported)
	assert.Nil(t, adapter.StandardWriter(nil))
}

func TestHCLogAdapter_ArgsToFields_OddArgs(t *testing.T) {
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Odd number of args - last arg should be ignored
	adapter.Info("test", "key1", "value1", "key2")

	output := buf.String()
	assert.Contains(t, output, "key1")
	assert.Contains(t, output, "value1")
	// key2 should not appear as a key because it has no value
}

func TestHCLogAdapter_ArgsToFields_NonStringKey(t *testing.T) {
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Non-string key should be skipped
	adapter.Info("test", 123, "value1", "valid_key", "valid_value")

	output := buf.String()
	assert.Contains(t, output, "valid_key")
	assert.Contains(t, output, "valid_value")
	// 123 and value1 should be skipped
}

func TestHCLogAdapter_NamedPreservesGate(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	named := adapter.Named("child")

	// Both should work without panic
	adapter.Info("parent message")
	named.Info("child message")
}

func TestHCLogAdapter_WithPreservesNamed(t *testing.T) {
	logger, _ := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Named then With
	namedWithArgs := adapter.Named("mylogger").With("key", "value")

	assert.Equal(t, "mylogger", namedWithArgs.Name())
	assert.Len(t, namedWithArgs.ImpliedArgs(), 2)
}

func TestHCLogAdapter_UsedWithFairshare(t *testing.T) {
	// This test verifies the adapter can be used in the way fairshare.JobManager uses it
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Simulate fairshare usage pattern
	jobManagerLogger := adapter.Named("job-manager")
	workerLogger := jobManagerLogger.With("worker_id", 1)

	workerLogger.Debug("processing job", "job_id", "abc123")

	output := buf.String()
	assert.Contains(t, output, "processing job")
	assert.Contains(t, output, "worker_id")
	assert.Contains(t, output, "job_id")
	assert.Contains(t, output, "abc123")
}

func TestHCLogAdapter_EmptyMessage(t *testing.T) {
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	adapter.Info("")

	// Should not panic, output should have something
	require.NotEmpty(t, buf.String())
}

func TestHCLogAdapter_LargeNumberOfArgs(t *testing.T) {
	logger, buf := createTestLogger(t)
	adapter := NewHCLogAdapter(logger)

	// Many key-value pairs
	adapter.Info("many args",
		"key1", "value1",
		"key2", "value2",
		"key3", "value3",
		"key4", "value4",
		"key5", "value5",
	)

	output := buf.String()
	for i := 1; i <= 5; i++ {
		assert.Contains(t, output, strings.ReplaceAll("keyN", "N", string(rune('0'+i))))
		assert.Contains(t, output, strings.ReplaceAll("valueN", "N", string(rune('0'+i))))
	}
}
