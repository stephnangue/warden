package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Zerolog field implementations
func (f StringField) apply(event *zerolog.Event) *zerolog.Event {
	return event.Str(f.Key, f.Value)
}

func (f IntField) apply(event *zerolog.Event) *zerolog.Event {
	return event.Int(f.Key, f.Value)
}

func (f Int64Field) apply(event *zerolog.Event) *zerolog.Event {
	return event.Int64(f.Key, f.Value)
}

func (f Float64Field) apply(event *zerolog.Event) *zerolog.Event {
	return event.Float64(f.Key, f.Value)
}

func (f BoolField) apply(event *zerolog.Event) *zerolog.Event {
	return event.Bool(f.Key, f.Value)
}

func (f DurationField) apply(event *zerolog.Event) *zerolog.Event {
	return event.Dur(f.Key, f.Value)
}

func (f TimeField) apply(event *zerolog.Event) *zerolog.Event {
	return event.Time(f.Key, f.Value)
}

func (f ErrorField) apply(event *zerolog.Event) *zerolog.Event {
	return event.Err(f.Value)
}

func (f AnyField) apply(event *zerolog.Event) *zerolog.Event {
	return event.Interface(f.Key, f.Value)
}

// ZerologLogger implements Logger using zerolog with performance optimizations
type ZerologLogger struct {
	logger     zerolog.Logger
	config     *Config
	subsystem  string
	fileWriter *lumberjack.Logger
}

// NewZerologLogger creates a new high-performance ZerologLogger
func NewZerologLogger(config *Config) Logger {
	if config == nil {
		config = DefaultConfig()
	}

	// Configure zerolog level
	var zerologLevel zerolog.Level
	switch config.Level {
	case TraceLevel:
		zerologLevel = zerolog.TraceLevel
	case DebugLevel:
		zerologLevel = zerolog.DebugLevel
	case InfoLevel:
		zerologLevel = zerolog.InfoLevel
	case WarnLevel:
		zerologLevel = zerolog.WarnLevel
	case ErrorLevel:
		zerologLevel = zerolog.ErrorLevel
	case FatalLevel:
		zerologLevel = zerolog.FatalLevel
	case PanicLevel:
		zerologLevel = zerolog.PanicLevel
	default:
		zerologLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(zerologLevel)
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack // Better error stack traces

	var writers []io.Writer
	var fileWriter *lumberjack.Logger

	// Add file writer for production
	if config.FileConfig != nil {
		// Ensure log directory exists
		if err := os.MkdirAll(filepath.Dir(config.FileConfig.Filename), 0755); err != nil {
			fmt.Printf("Failed to create log directory: %v\n", err)
		} else {
			fileWriter = &lumberjack.Logger{
				Filename:   config.FileConfig.Filename,
				MaxSize:    config.FileConfig.MaxSize,
				MaxAge:     config.FileConfig.MaxAge,
				MaxBackups: config.FileConfig.MaxBackups,
				Compress:   config.FileConfig.Compress,
				LocalTime:  true,
			}
			writers = append(writers, fileWriter)
		}
	}

	// Add configured outputs
	for _, output := range config.Outputs {
		if config.Format == DefaultFormat || config.Environment == "development" {
			consoleWriter := zerolog.ConsoleWriter{
				Out:        output,
				TimeFormat: "15:04:05",
				NoColor:    false,
				PartsOrder: []string{
					zerolog.TimestampFieldName,
					zerolog.LevelFieldName,
					zerolog.CallerFieldName,
					"module",
					zerolog.MessageFieldName,
				},
			}
			writers = append(writers, consoleWriter)
		} else {
			writers = append(writers, output)
		}
	}

	var writer io.Writer
	if len(writers) == 1 {
		writer = writers[0]
	} else {
		writer = zerolog.MultiLevelWriter(writers...)
	}

	// Create logger with sampling for high throughput
	var logger zerolog.Logger
	if config.EnableSampling && config.Environment == "production" {
		// Sample debug logs to reduce volume in production
		logger = zerolog.New(writer).Sample(&zerolog.BurstSampler{
			Burst:       10,
			Period:      1 * time.Second,
			NextSampler: &zerolog.BasicSampler{N: 100},
		})
	} else {
		logger = zerolog.New(writer)
	}

	// Add timestamp
	logger = logger.With().Timestamp().Logger()

	// Add caller info if enabled
	if config.EnableCaller {
		logger = logger.With().CallerWithSkipFrameCount(3 + config.CallerSkip).Logger()
	}

	// Add subsystem if provided
	if config.Subsystem != "" {
		logger = logger.With().Str("module", config.Subsystem).Logger()
	}

	return &ZerologLogger{
		logger:     logger,
		config:     config,
		subsystem:  config.Subsystem,
		fileWriter: fileWriter,
	}
}

// Performance-optimized logging methods
func (zl *ZerologLogger) logWithFields(level zerolog.Level, msg string, fields []TypedField) {
	if zl.logger.GetLevel() > level {
		return
	}

	var event *zerolog.Event
	switch level {
	case zerolog.TraceLevel:
		event = zl.logger.Trace()
	case zerolog.DebugLevel:
		event = zl.logger.Debug()
	case zerolog.InfoLevel:
		event = zl.logger.Info()
	case zerolog.WarnLevel:
		event = zl.logger.Warn()
	case zerolog.ErrorLevel:
		event = zl.logger.Error()
	case zerolog.FatalLevel:
		event = zl.logger.Fatal()
	case zerolog.PanicLevel:
		event = zl.logger.Panic()
	default:
		return
	}

	// Apply all fields at once if there are any
	if len(fields) > 0 {
		event.Fields(fieldsToMap(fields))
	}

	event.Msg(msg)
}

// Trace logs a message at trace level
func (zl *ZerologLogger) Trace(msg string, fields ...TypedField) {
	zl.logWithFields(zerolog.TraceLevel, msg, fields)
}

// Debug logs a message at debug level
func (zl *ZerologLogger) Debug(msg string, fields ...TypedField) {
	zl.logWithFields(zerolog.DebugLevel, msg, fields)
}

// Info logs a message at info level
func (zl *ZerologLogger) Info(msg string, fields ...TypedField) {
	zl.logWithFields(zerolog.InfoLevel, msg, fields)
}

// Warn logs a message at warn level
func (zl *ZerologLogger) Warn(msg string, fields ...TypedField) {
	zl.logWithFields(zerolog.WarnLevel, msg, fields)
}

// Error logs a message at error level
func (zl *ZerologLogger) Error(msg string, fields ...TypedField) {
	zl.logWithFields(zerolog.ErrorLevel, msg, fields)
}

// Fatal logs a message at fatal level and exits
func (zl *ZerologLogger) Fatal(msg string, fields ...TypedField) {
	zl.logWithFields(zerolog.FatalLevel, msg, fields)
}

// Panic logs a message at panic level and panics
func (zl *ZerologLogger) Panic(msg string, fields ...TypedField) {
	zl.logWithFields(zerolog.PanicLevel, msg, fields)
}

// Formatted logging methods
func (zl *ZerologLogger) Tracef(format string, args ...interface{}) {
	zl.logger.Trace().Msgf(format, args...)
}

func (zl *ZerologLogger) Debugf(format string, args ...interface{}) {
	zl.logger.Debug().Msgf(format, args...)
}

func (zl *ZerologLogger) Infof(format string, args ...interface{}) {
	zl.logger.Info().Msgf(format, args...)
}

func (zl *ZerologLogger) Warnf(format string, args ...interface{}) {
	zl.logger.Warn().Msgf(format, args...)
}

func (zl *ZerologLogger) Errorf(format string, args ...interface{}) {
	zl.logger.Error().Msgf(format, args...)
}

func (zl *ZerologLogger) Fatalf(format string, args ...interface{}) {
	zl.logger.Fatal().Msgf(format, args...)
}

func (zl *ZerologLogger) Panicf(format string, args ...interface{}) {
	zl.logger.Panic().Msgf(format, args...)
}

// WithSubsystem creates a new logger with a subsystem
func (zl *ZerologLogger) WithSubsystem(name string) Logger {
	newConfig := *zl.config
	if zl.subsystem != "" {
		newConfig.Subsystem = zl.subsystem + "." + name
	} else {
		newConfig.Subsystem = name
	}
	return NewZerologLogger(&newConfig)
}

// WithSystem creates a new logger with a system
func (zl *ZerologLogger) WithSystem(name string) Logger {
	newConfig := *zl.config
	newConfig.Subsystem = name
	return NewZerologLogger(&newConfig)
}

// fieldsToMap converts typed fields to a map[string]interface{}
func fieldsToMap(fields []TypedField) map[string]interface{} {
	result := make(map[string]interface{}, len(fields))
	for _, field := range fields {
		switch f := field.(type) {
		case StringField:
			result[f.Key] = f.Value
		case IntField:
			result[f.Key] = f.Value
		case Int64Field:
			result[f.Key] = f.Value
		case Float64Field:
			result[f.Key] = f.Value
		case BoolField:
			result[f.Key] = f.Value
		case DurationField:
			result[f.Key] = f.Value
		case TimeField:
			result[f.Key] = f.Value
		case ErrorField:
			result[f.Key] = f.Value
		case AnyField:
			result[f.Key] = f.Value
		}
	}
	return result
}

// WithFields creates a new logger with additional fields
func (zl *ZerologLogger) WithFields(fields ...TypedField) Logger {
	if len(fields) == 0 {
		return zl // Return original logger if no fields
	}

	// Convert typed fields to a map
	fieldMap := fieldsToMap(fields)

	// Apply all fields to the context at once
	ctx := zl.logger.With().Fields(fieldMap)

	return &ZerologLogger{
		logger:     ctx.Logger(),
		config:     zl.config,
		subsystem:  zl.subsystem,
		fileWriter: zl.fileWriter,
	}
}

// IsLevelEnabled checks if a log level is enabled
func (zl *ZerologLogger) IsLevelEnabled(level LogLevel) bool {
	switch level {
	case TraceLevel:
		return zl.logger.GetLevel() <= zerolog.TraceLevel
	case DebugLevel:
		return zl.logger.GetLevel() <= zerolog.DebugLevel
	case InfoLevel:
		return zl.logger.GetLevel() <= zerolog.InfoLevel
	case WarnLevel:
		return zl.logger.GetLevel() <= zerolog.WarnLevel
	case ErrorLevel:
		return zl.logger.GetLevel() <= zerolog.ErrorLevel
	case FatalLevel:
		return zl.logger.GetLevel() <= zerolog.FatalLevel
	case PanicLevel:
		return zl.logger.GetLevel() <= zerolog.PanicLevel
	default:
		return false
	}
}

// Flush ensures all logs are written
func (zl *ZerologLogger) Flush() {
	// zerolog doesn't have explicit flush, but we can flush the file writer
	if zl.fileWriter != nil {
		// lumberjack doesn't have flush either, but we can close and reopen
		zl.fileWriter.Rotate()
	}
}

// Close closes the logger and cleans up resources
func (zl *ZerologLogger) Close() error {
	if zl.fileWriter != nil {
		return zl.fileWriter.Close()
	}
	return nil
}
