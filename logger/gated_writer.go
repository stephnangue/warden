package logger

import (
	"bytes"
	"io"
	"sync"
)

// GateState represents the state of the log gate
type GateState int

const (
	// GateClosed means logs are buffered but not written
	GateClosed GateState = iota
	// GateOpen means logs flow through immediately
	GateOpen
)

// GatedWriter is an io.Writer that can buffer logs until a gate is opened
type GatedWriter struct {
	mu         sync.RWMutex
	underlying io.Writer
	buffer     *bytes.Buffer
	state      GateState
	maxBuffer  int // Maximum buffer size in bytes (0 = unlimited)
}

// GatedWriterConfig configures a GatedWriter
type GatedWriterConfig struct {
	// Underlying writer to flush to when gate opens
	Underlying io.Writer

	// InitialState determines if gate starts open or closed
	InitialState GateState

	// MaxBufferSize limits buffered logs in bytes (0 = unlimited)
	// When exceeded, oldest logs are discarded
	MaxBufferSize int
}

// NewGatedWriter creates a new gated writer
func NewGatedWriter(config GatedWriterConfig) *GatedWriter {
	if config.Underlying == nil {
		config.Underlying = io.Discard
	}

	return &GatedWriter{
		underlying: config.Underlying,
		buffer:     &bytes.Buffer{},
		state:      config.InitialState,
		maxBuffer:  config.MaxBufferSize,
	}
}

// Write implements io.Writer
func (gw *GatedWriter) Write(p []byte) (n int, err error) {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	switch gw.state {
	case GateOpen:
		// Gate is open, write directly to underlying writer
		return gw.underlying.Write(p)

	case GateClosed:
		// Gate is closed, buffer the log
		// Check if we need to enforce buffer limit
		if gw.maxBuffer > 0 && gw.buffer.Len()+len(p) > gw.maxBuffer {
			// Buffer would exceed limit, discard oldest logs
			excess := (gw.buffer.Len() + len(p)) - gw.maxBuffer
			gw.buffer.Next(excess)
		}

		// Write to buffer
		return gw.buffer.Write(p)
	}

	return len(p), nil
}

// OpenGate opens the gate and flushes all buffered logs
func (gw *GatedWriter) OpenGate() error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.state == GateOpen {
		return nil // Already open
	}

	gw.state = GateOpen

	// Flush buffered logs to underlying writer
	if gw.buffer.Len() > 0 {
		_, err := gw.underlying.Write(gw.buffer.Bytes())
		if err != nil {
			return err
		}
		gw.buffer.Reset()
	}

	return nil
}

// CloseGate closes the gate, causing subsequent logs to be buffered
func (gw *GatedWriter) CloseGate() {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	gw.state = GateClosed
}

// Flush writes buffered logs without opening the gate
func (gw *GatedWriter) Flush() error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.buffer.Len() > 0 {
		_, err := gw.underlying.Write(gw.buffer.Bytes())
		if err != nil {
			return err
		}
		gw.buffer.Reset()
	}

	return nil
}

// IsOpen returns true if the gate is open
func (gw *GatedWriter) IsOpen() bool {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	return gw.state == GateOpen
}

// BufferedSize returns the current size of buffered logs in bytes
func (gw *GatedWriter) BufferedSize() int {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	return gw.buffer.Len()
}

// Clear discards all buffered logs without flushing
func (gw *GatedWriter) Clear() {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	gw.buffer.Reset()
}

// GatedLogger wraps a logger with gate control
type GatedLogger struct {
	Logger
	gate *GatedWriter
}

// NewGatedLogger creates a logger with gated output
func NewGatedLogger(config *Config, gateConfig GatedWriterConfig) (*GatedLogger, *GatedWriter) {
	if config == nil {
		config = DefaultConfig()
	}

	// If no underlying writer specified, use the first configured output
	if gateConfig.Underlying == nil && len(config.Outputs) > 0 {
		gateConfig.Underlying = config.Outputs[0]
	}

	gate := NewGatedWriter(gateConfig)

	// Replace outputs with gated writer
	config.Outputs = []io.Writer{gate}

	logger := NewZerologLogger(config)

	return &GatedLogger{
		Logger: logger,
		gate:   gate,
	}, gate
}

// WithSystem creates a new logger with a system name, preserving gate access
func (gl *GatedLogger) WithSystem(name string) *GatedLogger {
	return &GatedLogger{
		Logger: gl.Logger.WithSystem(name),
		gate:   gl.gate, // Share the same gate
	}
}

// WithSubsystem creates a new logger with a subsystem, preserving gate access
func (gl *GatedLogger) WithSubsystem(name string) *GatedLogger {
	return &GatedLogger{
		Logger: gl.Logger.WithSubsystem(name),
		gate:   gl.gate, // Share the same gate
	}
}

// WithFields creates a new logger with additional fields, preserving gate access
func (gl *GatedLogger) WithFields(fields ...TypedField) *GatedLogger {
	return &GatedLogger{
		Logger: gl.Logger.WithFields(fields...),
		gate:   gl.gate, // Share the same gate
	}
}

// OpenGate opens the gate and flushes buffered logs
func (gl *GatedLogger) OpenGate() error {
	return gl.gate.OpenGate()
}

// CloseGate closes the gate
func (gl *GatedLogger) CloseGate() {
	gl.gate.CloseGate()
}

// IsGateOpen returns true if the gate is open
func (gl *GatedLogger) IsGateOpen() bool {
	return gl.gate.IsOpen()
}

// FlushGate flushes buffered logs without opening the gate
func (gl *GatedLogger) FlushGate() error {
	return gl.gate.Flush()
}

// ClearGate discards buffered logs
func (gl *GatedLogger) ClearGate() {
	gl.gate.Clear()
}

// BufferedSize returns the size of buffered logs
func (gl *GatedLogger) BufferedSize() int {
	return gl.gate.BufferedSize()
}
