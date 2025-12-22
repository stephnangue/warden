package logger_test

import (
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/stephnangue/warden/logger"
)

// Example_gatedLogger demonstrates basic usage of the gated logger
func Example_gatedLogger() {
	// Create a logger with closed gate
	config := log.DefaultConfig()
	gateConfig := log.GatedWriterConfig{
		Underlying:   os.Stdout,
		InitialState: log.GateClosed,
	}

	logger, gate := log.NewGatedLogger(config, gateConfig)

	// These logs are buffered, not shown yet
	logger.Info("Initializing system...")
	logger.Debug("Loading configuration")
	logger.Info("Connecting to database...")

	fmt.Printf("Buffered %d bytes\n", gate.BufferedSize())

	// Decision point: open the gate to show all logs
	logger.OpenGate()
	fmt.Println("Gate opened - all buffered logs flushed")

	// Future logs flow through immediately
	logger.Info("System ready")
}

// Example_conditionalLogging shows how to use gated logging for conditional output
func Example_conditionalLogging() {
	config := log.DefaultConfig()
	gateConfig := log.GatedWriterConfig{
		Underlying:   os.Stdout,
		InitialState: log.GateClosed,
	}

	logger, _ := log.NewGatedLogger(config, gateConfig)

	// Simulate an operation that might fail
	success := performOperation(logger)

	if !success {
		// Operation failed, show all debug logs
		logger.OpenGate()
		logger.Error("Operation failed - see logs above")
	} else {
		// Operation succeeded, discard debug logs
		logger.ClearGate()
		logger.Info("Operation completed successfully")
	}
}

func performOperation(logger *log.GatedLogger) bool {
	logger.Debug("Step 1: Validating input")
	logger.Debug("Step 2: Processing data")
	logger.Debug("Step 3: Writing results")
	return false // Simulate failure
}

// Example_startupLogging demonstrates logging during system initialization
// where each module derives its own logger using WithSystem
func Example_startupLogging() {
	config := &log.Config{
		Level:       log.DebugLevel,
		Format:      log.DefaultFormat,
		Outputs:     []io.Writer{os.Stdout},
		Environment: "development",
	}

	gateConfig := log.GatedWriterConfig{
		Underlying:    os.Stdout,
		InitialState:  log.GateClosed,
		MaxBufferSize: 1024 * 1024, // 1MB buffer
	}

	gatedLogger, _ := log.NewGatedLogger(config, gateConfig)

	// Perform initialization
	gatedLogger.Info("Starting initialization...")
	gatedLogger.Debug("Loading modules...")

	// Simulate initialization steps with module-specific loggers
	modules := []string{"auth", "storage", "api", "cache"}
	allSuccess := true

	for _, moduleName := range modules {
		// Each module gets its own logger derived from the root logger
		// WithSystem returns a *GatedLogger, preserving gate control
		moduleLogger := gatedLogger.WithSystem(moduleName)

		moduleLogger.Debug("Initializing module...")
		if err := initModuleWithLogger(moduleName, moduleLogger.Logger); err != nil {
			moduleLogger.Error(fmt.Sprintf("Initialization failed: %v", err))
			allSuccess = false
			break
		}
		moduleLogger.Debug("Module initialized successfully")
	}

	if allSuccess {
		// Success: only show summary, discard debug logs
		gatedLogger.ClearGate()
		gatedLogger.OpenGate()
		gatedLogger.Info("System initialized successfully")
	} else {
		// Failure: show all debug logs for troubleshooting
		gatedLogger.OpenGate()
		gatedLogger.Error("System initialization failed")
	}
}

func initModuleWithLogger(name string, logger log.Logger) error {
	// Each module uses its own logger for detailed logging
	logger.Debug("Loading configuration")
	logger.Debug("Setting up connections")
	logger.Debug("Validating dependencies")

	time.Sleep(10 * time.Millisecond)

	// Simulate occasional failures
	if name == "storage" && false { // Change to true to test failure path
		return fmt.Errorf("connection timeout")
	}

	logger.Debug("Module ready")
	return nil
}

func initModule(name string) error {
	time.Sleep(10 * time.Millisecond)
	return nil
}

// Example_testLogging shows how to use gated logging in tests
func Example_testLogging() {
	config := log.DefaultConfig()
	gateConfig := log.GatedWriterConfig{
		Underlying:   os.Stdout,
		InitialState: log.GateClosed,
	}

	logger, _ := log.NewGatedLogger(config, gateConfig)

	// Run test
	testPassed := runTest(logger)

	if !testPassed {
		// Test failed, show all logs
		logger.OpenGate()
		fmt.Println("Test failed - logs above")
	} else {
		// Test passed, discard logs
		logger.ClearGate()
		fmt.Println("Test passed")
	}
}

func runTest(logger *log.GatedLogger) bool {
	logger.Debug("Setting up test environment")
	logger.Debug("Running test case 1")
	logger.Debug("Running test case 2")
	return true
}

// Example_errorThreshold demonstrates opening gate on error threshold
func Example_errorThreshold() {
	config := log.DefaultConfig()
	gateConfig := log.GatedWriterConfig{
		Underlying:   os.Stdout,
		InitialState: log.GateClosed,
	}

	logger, _ := log.NewGatedLogger(config, gateConfig)

	errorCount := 0
	maxErrors := 3

	for i := 0; i < 10; i++ {
		logger.Debug(fmt.Sprintf("Processing item %d", i))

		if i%3 == 0 && i > 0 {
			errorCount++
			logger.Warn(fmt.Sprintf("Warning on item %d", i))

			if errorCount >= maxErrors {
				// Too many errors, open gate to show what's happening
				logger.OpenGate()
				logger.Error("Error threshold exceeded, dumping logs")
				break
			}
		}
	}
}

// Example_manualFlush shows how to flush logs without opening gate permanently
func Example_manualFlush() {
	config := log.DefaultConfig()
	gateConfig := log.GatedWriterConfig{
		Underlying:   os.Stdout,
		InitialState: log.GateClosed,
	}

	logger, _ := log.NewGatedLogger(config, gateConfig)

	// Log some work
	logger.Debug("Phase 1 starting")
	logger.Debug("Phase 1 processing")
	logger.Info("Phase 1 completed")

	// Flush logs for this phase, but keep gate closed for next phase
	logger.FlushGate()

	// Continue logging for next phase (still buffered)
	logger.Debug("Phase 2 starting")
	logger.Debug("Phase 2 processing")

	// Final flush at the end
	logger.FlushGate()
}

// Example_adaptiveLogging shows gate control based on runtime conditions
func Example_adaptiveLogging() {
	config := &log.Config{
		Level:       log.DebugLevel,
		Format:      log.DefaultFormat,
		Outputs:     []io.Writer{os.Stdout},
		Environment: "production",
	}

	gateConfig := log.GatedWriterConfig{
		Underlying:   os.Stdout,
		InitialState: log.GateClosed,
	}

	logger, _ := log.NewGatedLogger(config, gateConfig)

	// Monitor system health
	cpuUsage := 85.0
	memUsage := 90.0

	logger.Debug(fmt.Sprintf("CPU: %.2f%%", cpuUsage))
	logger.Debug(fmt.Sprintf("Memory: %.2f%%", memUsage))

	// Open gate if system is under stress
	if cpuUsage > 80 || memUsage > 80 {
		logger.OpenGate()
		logger.Warn("System under stress - enabling verbose logging")
	} else {
		logger.ClearGate()
		logger.Info("System healthy")
	}
}
