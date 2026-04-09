package logger

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestFieldConstructors(t *testing.T) {
	t.Run("Int", func(t *testing.T) {
		f := Int("count", 42)
		intF, ok := f.(IntField)
		require.True(t, ok)
		assert.Equal(t, "count", intF.Key)
		assert.Equal(t, 42, intF.Value)
	})

	t.Run("Int64", func(t *testing.T) {
		f := Int64("big", int64(9999999999))
		i64F, ok := f.(Int64Field)
		require.True(t, ok)
		assert.Equal(t, "big", i64F.Key)
		assert.Equal(t, int64(9999999999), i64F.Value)
	})

	t.Run("Float64", func(t *testing.T) {
		f := Float64("rate", 3.14)
		fF, ok := f.(Float64Field)
		require.True(t, ok)
		assert.Equal(t, "rate", fF.Key)
		assert.InDelta(t, 3.14, fF.Value, 0.001)
	})

	t.Run("Bool", func(t *testing.T) {
		f := Bool("enabled", true)
		bF, ok := f.(BoolField)
		require.True(t, ok)
		assert.Equal(t, "enabled", bF.Key)
		assert.True(t, bF.Value)
	})

	t.Run("Duration", func(t *testing.T) {
		f := Duration("elapsed", 5*time.Second)
		dF, ok := f.(DurationField)
		require.True(t, ok)
		assert.Equal(t, "elapsed", dF.Key)
		assert.Equal(t, 5*time.Second, dF.Value)
	})

	t.Run("Time", func(t *testing.T) {
		now := time.Now()
		f := Time("created_at", now)
		tF, ok := f.(TimeField)
		require.True(t, ok)
		assert.Equal(t, "created_at", tF.Key)
		assert.Equal(t, now, tF.Value)
	})

	t.Run("Err", func(t *testing.T) {
		e := errors.New("test error")
		f := Err(e)
		eF, ok := f.(ErrorField)
		require.True(t, ok)
		assert.Equal(t, "error", eF.Key)
		assert.Equal(t, e, eF.Value)
	})
}

// =============================================================================
// ProductionConfig Tests
// =============================================================================

func TestLogLevel_String_AllLevels(t *testing.T) {
	tests := []struct {
		level LogLevel
		str   string
	}{
		{TraceLevel, "trace"},
		{DebugLevel, "debug"},
		{InfoLevel, "info"},
		{WarnLevel, "warn"},
		{ErrorLevel, "error"},
		{FatalLevel, "fatal"},
		{PanicLevel, "panic"},
		{LogLevel(99), "info"}, // default
	}
	for _, tc := range tests {
		assert.Equal(t, tc.str, tc.level.String())
	}
}

func TestParseLogLevel_AllStrings(t *testing.T) {
	tests := []struct {
		str   string
		level LogLevel
	}{
		{"trace", TraceLevel},
		{"debug", DebugLevel},
		{"info", InfoLevel},
		{"warn", WarnLevel},
		{"warning", WarnLevel},
		{"error", ErrorLevel},
		{"err", ErrorLevel},
		{"fatal", FatalLevel},
		{"panic", PanicLevel},
		{"TRACE", TraceLevel},
		{"INFO", InfoLevel},
		{"unknown", InfoLevel},
		{"", InfoLevel},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.level, ParseLogLevel(tc.str))
	}
}

func TestOutputFormat_String(t *testing.T) {
	assert.Equal(t, "json", JSONFormat.String())
	assert.Equal(t, "default", DefaultFormat.String())
	assert.Equal(t, "default", OutputFormat(99).String())
}

func TestParseOutPutFormat(t *testing.T) {
	assert.Equal(t, JSONFormat, ParseOutPutFormat("json"))
	assert.Equal(t, JSONFormat, ParseOutPutFormat("JSON"))
	assert.Equal(t, DefaultFormat, ParseOutPutFormat("default"))
	assert.Equal(t, DefaultFormat, ParseOutPutFormat("DEFAULT"))
	assert.Equal(t, DefaultFormat, ParseOutPutFormat("unknown"))
}

// =============================================================================
// LoggerPool Tests
// =============================================================================

func TestF_LegacyConstructor(t *testing.T) {
	f := F("key", "value")
	af, ok := f.(AnyField)
	require.True(t, ok)
	assert.Equal(t, "key", af.Key)
	assert.Equal(t, "value", af.Value)
}

// =============================================================================
// NewZerologLogger with sampling config
// =============================================================================
