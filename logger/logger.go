package logger

import (
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// LogLevel represents the logging level
type LogLevel int

const (
	TraceLevel LogLevel = iota
	DebugLevel
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
	PanicLevel
)

// String returns the string representation of LogLevel
func (l LogLevel) String() string {
	switch l {
	case TraceLevel:
		return "trace"
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warn"
	case ErrorLevel:
		return "error"
	case FatalLevel:
		return "fatal"
	case PanicLevel:
		return "panic"
	default:
		return "info"
	}
}

// ParseLogLevel parses a string to LogLevel
func ParseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "trace":
		return TraceLevel
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn", "warning":
		return WarnLevel
	case "error", "err":
		return ErrorLevel
	case "fatal":
		return FatalLevel
	case "panic":
		return PanicLevel
	default:
		return InfoLevel
	}
}

// OutputFormat represents the output format
type OutputFormat int

const (
	JSONFormat OutputFormat = iota
	DefaultFormat
)

// String returns the string representation of OutputFormat
func (o OutputFormat) String() string {
	switch o {
	case JSONFormat:
		return "json"
	case DefaultFormat:
		return "default"
	default:
		return "default"
	}
}

// ParseOutPutFormat parses a string to OutputFormat
func ParseOutPutFormat(format string) OutputFormat {
	switch strings.ToUpper(format) {
	case "JSON":
		return JSONFormat
	case "DEFAULT":
		return DefaultFormat
	default:
		return DefaultFormat
	}
}

// TypedField represents a type-safe field for structured logging
type TypedField interface {
	apply(event *zerolog.Event) *zerolog.Event
}

// Performance-optimized field types
type (
	StringField struct {
		Key   string
		Value string
	}
	IntField struct {
		Key   string
		Value int
	}
	Int64Field struct {
		Key   string
		Value int64
	}
	Float64Field struct {
		Key   string
		Value float64
	}
	BoolField struct {
		Key   string
		Value bool
	}
	DurationField struct {
		Key   string
		Value time.Duration
	}
	TimeField struct {
		Key   string
		Value time.Time
	}
	ErrorField struct {
		Key   string
		Value error
	}
	AnyField struct {
		Key   string
		Value interface{}
	}
)

// Type-safe field constructors
func String(key, value string) TypedField {
	return StringField{Key: key, Value: value}
}

func Int(key string, value int) TypedField {
	return IntField{Key: key, Value: value}
}

func Int64(key string, value int64) TypedField {
	return Int64Field{Key: key, Value: value}
}

func Float64(key string, value float64) TypedField {
	return Float64Field{Key: key, Value: value}
}

func Bool(key string, value bool) TypedField {
	return BoolField{Key: key, Value: value}
}

func Duration(key string, value time.Duration) TypedField {
	return DurationField{Key: key, Value: value}
}

func Time(key string, value time.Time) TypedField {
	return TimeField{Key: key, Value: value}
}

func Err(value error) TypedField {
	return ErrorField{Key: "error", Value: value}
}

func Any(key string, value interface{}) TypedField {
	return AnyField{Key: key, Value: value}
}

// Logger defines the public interface for logging
type Logger interface {
	// Basic logging methods with type-safe fields
	Trace(msg string, fields ...TypedField)
	Debug(msg string, fields ...TypedField)
	Info(msg string, fields ...TypedField)
	Warn(msg string, fields ...TypedField)
	Error(msg string, fields ...TypedField)
	Fatal(msg string, fields ...TypedField)
	Panic(msg string, fields ...TypedField)

	// Formatted logging methods
	Tracef(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Panicf(format string, args ...interface{})

	// Subsystem support
	WithSubsystem(name string) Logger

	// System support
	WithSystem(name string) Logger
	
	// Context support
	WithFields(fields ...TypedField) Logger
	
	// Level checking
	IsLevelEnabled(level LogLevel) bool
	
	// Performance methods
	Flush() // Flush any buffered logs
	Close() error // Close and cleanup resources
}

// Field represents a legacy field for backward compatibility
type Field struct {
	Key   string
	Value interface{}
}

// F is a convenience function to create a Field (legacy support)
func F(key string, value interface{}) TypedField {
	return Any(key, value)
}

// Performance utilities

// LoggerPool provides object pooling for high-performance scenarios
type LoggerPool struct {
	pool   sync.Pool
	config *Config
}


// NewLoggerPool creates a new logger pool for high-throughput scenarios
func NewLoggerPool(config *Config) *LoggerPool {
	pool := &LoggerPool{config: config}
	pool.pool.New = func() interface{} {
		return NewZerologLogger(config)
	}
	return pool
}

// Get retrieves a logger from the pool
func (lp *LoggerPool) Get() Logger {
	return lp.pool.Get().(Logger)
}

// Put returns a logger to the pool
func (lp *LoggerPool) Put(logger Logger) {
	lp.pool.Put(logger)
}