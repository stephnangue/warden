package logger

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestGatedWriter_ClosedGate(t *testing.T) {
	var buf bytes.Buffer
	gw := NewGatedWriter(GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	})

	// Write some logs while gate is closed
	gw.Write([]byte("log line 1\n"))
	gw.Write([]byte("log line 2\n"))
	gw.Write([]byte("log line 3\n"))

	// Verify nothing was written to underlying writer
	if buf.Len() != 0 {
		t.Errorf("Expected no output to underlying writer, got %d bytes", buf.Len())
	}

	// Verify logs are buffered
	if gw.BufferedSize() == 0 {
		t.Error("Expected logs to be buffered")
	}
}

func TestGatedWriter_OpenGate(t *testing.T) {
	var buf bytes.Buffer
	gw := NewGatedWriter(GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	})

	// Write logs while closed
	gw.Write([]byte("log line 1\n"))
	gw.Write([]byte("log line 2\n"))

	// Open the gate
	err := gw.OpenGate()
	if err != nil {
		t.Fatalf("OpenGate failed: %v", err)
	}

	// Verify buffered logs were flushed
	output := buf.String()
	if !strings.Contains(output, "log line 1") || !strings.Contains(output, "log line 2") {
		t.Errorf("Expected buffered logs to be flushed, got: %s", output)
	}

	// Verify buffer is now empty
	if gw.BufferedSize() != 0 {
		t.Errorf("Expected buffer to be empty after opening gate, got %d bytes", gw.BufferedSize())
	}

	// Write a new log - should go directly through
	buf.Reset()
	gw.Write([]byte("log line 3\n"))

	if !strings.Contains(buf.String(), "log line 3") {
		t.Error("Expected new log to pass through open gate")
	}
}

func TestGatedWriter_MaxBufferSize(t *testing.T) {
	var buf bytes.Buffer
	gw := NewGatedWriter(GatedWriterConfig{
		Underlying:    &buf,
		InitialState:  GateClosed,
		MaxBufferSize: 50, // Small buffer for testing
	})

	// Write logs that exceed the buffer
	for i := 0; i < 10; i++ {
		gw.Write([]byte("this is a log line\n"))
	}

	// Verify buffer doesn't exceed max size
	if gw.BufferedSize() > 50 {
		t.Errorf("Buffer size %d exceeds max %d", gw.BufferedSize(), 50)
	}

	// Open gate and verify some logs were written (not all, due to overflow)
	gw.OpenGate()
	if buf.Len() == 0 {
		t.Error("Expected some logs to be written")
	}
}

func TestGatedWriter_Flush(t *testing.T) {
	var buf bytes.Buffer
	gw := NewGatedWriter(GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	})

	// Write logs while closed
	gw.Write([]byte("log line 1\n"))

	// Flush without opening gate
	err := gw.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Verify logs were flushed
	if !strings.Contains(buf.String(), "log line 1") {
		t.Error("Expected log to be flushed")
	}

	// Verify gate is still closed
	if gw.IsOpen() {
		t.Error("Expected gate to remain closed after flush")
	}

	// Verify buffer is empty
	if gw.BufferedSize() != 0 {
		t.Error("Expected buffer to be empty after flush")
	}

	// New logs should still be buffered
	buf.Reset()
	gw.Write([]byte("log line 2\n"))
	if buf.Len() != 0 {
		t.Error("Expected new logs to be buffered since gate is still closed")
	}
}

func TestGatedWriter_Clear(t *testing.T) {
	var buf bytes.Buffer
	gw := NewGatedWriter(GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	})

	// Write logs
	gw.Write([]byte("log line 1\n"))
	gw.Write([]byte("log line 2\n"))

	// Clear buffer
	gw.Clear()

	// Verify buffer is empty
	if gw.BufferedSize() != 0 {
		t.Errorf("Expected buffer to be empty, got %d bytes", gw.BufferedSize())
	}

	// Open gate - nothing should be written
	gw.OpenGate()
	if buf.Len() != 0 {
		t.Error("Expected no logs to be written after clear")
	}
}

func TestGatedLogger_Integration(t *testing.T) {
	var buf bytes.Buffer

	config := &Config{
		Level:       DebugLevel,
		Format:      JSONFormat,
		Outputs:     []io.Writer{&buf},
		Environment: "production",
	}

	gateConfig := GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	}

	logger, gate := NewGatedLogger(config, gateConfig)

	// Log some messages while gate is closed
	logger.Info("message 1")
	logger.Debug("message 2")
	logger.Warn("message 3")

	// Verify nothing written yet
	if buf.Len() != 0 {
		t.Error("Expected no output while gate is closed")
	}

	// Verify logs are buffered
	if gate.BufferedSize() == 0 {
		t.Error("Expected logs to be buffered")
	}

	// Open the gate
	err := logger.OpenGate()
	if err != nil {
		t.Fatalf("Failed to open gate: %v", err)
	}

	// Verify logs were flushed
	output := buf.String()
	if !strings.Contains(output, "message 1") ||
		!strings.Contains(output, "message 2") ||
		!strings.Contains(output, "message 3") {
		t.Errorf("Expected all messages in output, got: %s", output)
	}

	// New logs should flow through
	buf.Reset()
	logger.Info("message 4")

	if !strings.Contains(buf.String(), "message 4") {
		t.Error("Expected new message to flow through open gate")
	}
}

func TestGatedLogger_CloseReopenGate(t *testing.T) {
	var buf bytes.Buffer

	config := DefaultConfig()
	config.Format = JSONFormat
	config.Environment = "production"

	gateConfig := GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateOpen,
	}

	logger, _ := NewGatedLogger(config, gateConfig)

	// Log with gate open
	logger.Info("immediate log")
	if !strings.Contains(buf.String(), "immediate log") {
		t.Error("Expected log to appear immediately")
	}

	// Close the gate
	buf.Reset()
	logger.CloseGate()
	logger.Info("buffered log")

	if buf.Len() != 0 {
		t.Error("Expected no output while gate is closed")
	}

	// Open again
	logger.OpenGate()
	if !strings.Contains(buf.String(), "buffered log") {
		t.Error("Expected buffered log to be flushed")
	}
}
