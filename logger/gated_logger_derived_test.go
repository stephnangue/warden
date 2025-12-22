package logger

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestGatedLogger_WithSystemPreservesGate(t *testing.T) {
	var buf bytes.Buffer

	config := DefaultConfig()
	config.Format = JSONFormat
	config.Environment = "production"

	gateConfig := GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	}

	rootLogger, _ := NewGatedLogger(config, gateConfig)

	// Create derived loggers with WithSystem
	authLogger := rootLogger.WithSystem("auth")
	storageLogger := rootLogger.WithSystem("storage")

	// Log from different loggers while gate is closed
	rootLogger.Info("root message")
	authLogger.Info("auth message")
	storageLogger.Info("storage message")

	// Nothing should be written yet
	if buf.Len() != 0 {
		t.Error("Expected no output while gate is closed")
	}

	// Open gate from any derived logger
	err := authLogger.OpenGate()
	if err != nil {
		t.Fatalf("Failed to open gate: %v", err)
	}

	// All messages should now be visible
	output := buf.String()
	if !strings.Contains(output, "root message") {
		t.Error("Expected root message in output")
	}
	if !strings.Contains(output, "auth message") {
		t.Error("Expected auth message in output")
	}
	if !strings.Contains(output, "storage message") {
		t.Error("Expected storage message in output")
	}

	// Verify gate is open for all loggers
	if !rootLogger.IsGateOpen() {
		t.Error("Expected root logger gate to be open")
	}
	if !authLogger.IsGateOpen() {
		t.Error("Expected auth logger gate to be open")
	}
	if !storageLogger.IsGateOpen() {
		t.Error("Expected storage logger gate to be open")
	}
}

func TestGatedLogger_WithSubsystemPreservesGate(t *testing.T) {
	var buf bytes.Buffer

	config := DefaultConfig()
	config.Format = JSONFormat
	config.Environment = "production"

	gateConfig := GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	}

	rootLogger, _ := NewGatedLogger(config, gateConfig)

	// Create nested subsystems
	apiLogger := rootLogger.WithSubsystem("api")
	httpLogger := apiLogger.WithSubsystem("http")

	// Log from different levels
	rootLogger.Info("root")
	apiLogger.Info("api")
	httpLogger.Info("http")

	// Close gate from nested logger
	httpLogger.CloseGate()

	// Verify buffer is empty (gate was already closed)
	if buf.Len() != 0 {
		t.Error("Expected no output")
	}

	// Open from root
	rootLogger.OpenGate()

	output := buf.String()
	if !strings.Contains(output, "root") || !strings.Contains(output, "api") || !strings.Contains(output, "http") {
		t.Errorf("Expected all messages in output, got: %s", output)
	}
}

func TestGatedLogger_WithFieldsPreservesGate(t *testing.T) {
	var buf bytes.Buffer

	config := DefaultConfig()
	config.Format = JSONFormat
	config.Environment = "production"

	gateConfig := GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	}

	rootLogger, _ := NewGatedLogger(config, gateConfig)

	// Create logger with fields
	userLogger := rootLogger.WithFields(
		String("user_id", "123"),
		String("tenant", "acme"),
	)

	userLogger.Info("user action")

	// Verify nothing written yet
	if buf.Len() != 0 {
		t.Error("Expected no output while gate is closed")
	}

	// Open gate and verify fields are preserved
	userLogger.OpenGate()

	output := buf.String()
	if !strings.Contains(output, "user action") {
		t.Error("Expected message in output")
	}
	if !strings.Contains(output, "user_id") || !strings.Contains(output, "123") {
		t.Error("Expected user_id field in output")
	}
}

func TestGatedLogger_MultipleModulesScenario(t *testing.T) {
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

	rootLogger, _ := NewGatedLogger(config, gateConfig)

	// Simulate module initialization
	modules := []string{"auth", "storage", "api"}
	moduleLoggers := make(map[string]*GatedLogger)

	for _, moduleName := range modules {
		moduleLogger := rootLogger.WithSystem(moduleName)
		moduleLoggers[moduleName] = moduleLogger

		moduleLogger.Debug("initializing")
		moduleLogger.Info("ready")
	}

	// Verify nothing written yet
	if buf.Len() != 0 {
		t.Error("Expected no output while gate is closed")
	}

	// Simulate an error in one module
	moduleLoggers["storage"].Error("connection failed")

	// Open gate from storage module
	moduleLoggers["storage"].OpenGate()

	// All logs from all modules should be visible
	output := buf.String()
	for _, moduleName := range modules {
		if !strings.Contains(output, moduleName) {
			t.Errorf("Expected logs from %s module", moduleName)
		}
	}
	if !strings.Contains(output, "connection failed") {
		t.Error("Expected error message in output")
	}
}

func TestGatedLogger_ClearFromDerivedLogger(t *testing.T) {
	var buf bytes.Buffer

	config := DefaultConfig()
	config.Format = JSONFormat
	config.Environment = "production"

	gateConfig := GatedWriterConfig{
		Underlying:   &buf,
		InitialState: GateClosed,
	}

	rootLogger, _ := NewGatedLogger(config, gateConfig)
	moduleLogger := rootLogger.WithSystem("module")

	// Log from both
	rootLogger.Info("root")
	moduleLogger.Info("module")

	// Clear from module logger
	moduleLogger.ClearGate()

	// Open gate
	rootLogger.OpenGate()

	// Nothing should be written (buffer was cleared)
	if buf.Len() != 0 {
		t.Error("Expected no output after clearing buffer")
	}
}
