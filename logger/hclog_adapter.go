package logger

import (
	"io"
	"log"

	"github.com/hashicorp/go-hclog"
)

// HCLogAdapter adapts Warden's GatedLogger to implement hclog.Logger interface.
// This allows Warden's logger to be used with libraries that require hclog.Logger,
// such as OpenBao's fairshare.JobManager.
type HCLogAdapter struct {
	logger *GatedLogger
	name   string
	args   []interface{} // Implied args from With()
}

// Compile-time assertion that HCLogAdapter implements hclog.Logger
var _ hclog.Logger = (*HCLogAdapter)(nil)

// NewHCLogAdapter creates a new adapter for the given GatedLogger
func NewHCLogAdapter(logger *GatedLogger) hclog.Logger {
	return &HCLogAdapter{
		logger: logger,
		name:   "",
		args:   nil,
	}
}

// Log emits a message at the given level
func (a *HCLogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	fields := a.argsToFields(args)
	switch level {
	case hclog.Trace:
		a.logger.Trace(msg, fields...)
	case hclog.Debug:
		a.logger.Debug(msg, fields...)
	case hclog.Info:
		a.logger.Info(msg, fields...)
	case hclog.Warn:
		a.logger.Warn(msg, fields...)
	case hclog.Error:
		a.logger.Error(msg, fields...)
	default:
		a.logger.Info(msg, fields...)
	}
}

// Trace emits a message at Trace level
func (a *HCLogAdapter) Trace(msg string, args ...interface{}) {
	a.logger.Trace(msg, a.argsToFields(args)...)
}

// Debug emits a message at Debug level
func (a *HCLogAdapter) Debug(msg string, args ...interface{}) {
	a.logger.Debug(msg, a.argsToFields(args)...)
}

// Info emits a message at Info level
func (a *HCLogAdapter) Info(msg string, args ...interface{}) {
	a.logger.Info(msg, a.argsToFields(args)...)
}

// Warn emits a message at Warn level
func (a *HCLogAdapter) Warn(msg string, args ...interface{}) {
	a.logger.Warn(msg, a.argsToFields(args)...)
}

// Error emits a message at Error level
func (a *HCLogAdapter) Error(msg string, args ...interface{}) {
	a.logger.Error(msg, a.argsToFields(args)...)
}

// argsToFields converts hclog key/value pairs to Warden's TypedField slice.
// hclog uses alternating key/value pairs: ("key1", value1, "key2", value2, ...)
func (a *HCLogAdapter) argsToFields(args []interface{}) []TypedField {
	// Prepend implied args from With()
	allArgs := append(a.args, args...)

	fields := make([]TypedField, 0, len(allArgs)/2)
	for i := 0; i < len(allArgs)-1; i += 2 {
		key, ok := allArgs[i].(string)
		if !ok {
			continue
		}
		fields = append(fields, Any(key, allArgs[i+1]))
	}
	return fields
}

// Named returns a logger with the specified name appended.
// Names are joined with "." when nested.
func (a *HCLogAdapter) Named(name string) hclog.Logger {
	newName := name
	if a.name != "" {
		newName = a.name + "." + name
	}
	// Use GatedLogger's WithSubsystem to create a named child logger
	return &HCLogAdapter{
		logger: a.logger.WithSubsystem(name),
		name:   newName,
		args:   a.args,
	}
}

// With returns a logger with the given key/value pairs as implied args.
// These args are prepended to all subsequent log calls.
func (a *HCLogAdapter) With(args ...interface{}) hclog.Logger {
	newArgs := make([]interface{}, len(a.args)+len(args))
	copy(newArgs, a.args)
	copy(newArgs[len(a.args):], args)
	return &HCLogAdapter{
		logger: a.logger,
		name:   a.name,
		args:   newArgs,
	}
}

// Name returns the current logger's name
func (a *HCLogAdapter) Name() string {
	return a.name
}

// ResetNamed returns a logger with the name set to the given name directly,
// rather than appending to the current name.
func (a *HCLogAdapter) ResetNamed(name string) hclog.Logger {
	return &HCLogAdapter{
		logger: a.logger.WithSubsystem(name),
		name:   name,
		args:   a.args,
	}
}

// IsTrace returns true if Trace level is enabled
func (a *HCLogAdapter) IsTrace() bool {
	return a.logger.IsLevelEnabled(TraceLevel)
}

// IsDebug returns true if Debug level is enabled
func (a *HCLogAdapter) IsDebug() bool {
	return a.logger.IsLevelEnabled(DebugLevel)
}

// IsInfo returns true if Info level is enabled
func (a *HCLogAdapter) IsInfo() bool {
	return a.logger.IsLevelEnabled(InfoLevel)
}

// IsWarn returns true if Warn level is enabled
func (a *HCLogAdapter) IsWarn() bool {
	return a.logger.IsLevelEnabled(WarnLevel)
}

// IsError returns true if Error level is enabled
func (a *HCLogAdapter) IsError() bool {
	return a.logger.IsLevelEnabled(ErrorLevel)
}

// GetLevel returns the current log level.
// Since GatedLogger doesn't expose level directly, we check each level.
func (a *HCLogAdapter) GetLevel() hclog.Level {
	if a.logger.IsLevelEnabled(TraceLevel) {
		return hclog.Trace
	}
	if a.logger.IsLevelEnabled(DebugLevel) {
		return hclog.Debug
	}
	if a.logger.IsLevelEnabled(InfoLevel) {
		return hclog.Info
	}
	if a.logger.IsLevelEnabled(WarnLevel) {
		return hclog.Warn
	}
	if a.logger.IsLevelEnabled(ErrorLevel) {
		return hclog.Error
	}
	return hclog.Off
}

// SetLevel sets the log level (no-op for adapter).
// GatedLogger level is controlled elsewhere through its Config.
func (a *HCLogAdapter) SetLevel(level hclog.Level) {
	// GatedLogger level is controlled elsewhere, ignore
}

// ImpliedArgs returns the implied key/value pairs set via With()
func (a *HCLogAdapter) ImpliedArgs() []interface{} {
	return a.args
}

// StandardLogger returns nil (not supported by this adapter).
// Use the underlying GatedLogger directly if standard library logging is needed.
func (a *HCLogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	return nil
}

// StandardWriter returns nil (not supported by this adapter).
// Use the underlying GatedLogger directly if io.Writer access is needed.
func (a *HCLogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return nil
}
