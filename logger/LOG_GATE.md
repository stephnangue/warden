# Log Gate

The log gate feature allows you to buffer logs in memory and decide when to flush them to the output. This is useful for scenarios where you want to:

1. **Conditional Logging**: Only show detailed logs if an operation fails
2. **Error Threshold**: Start showing logs when errors exceed a threshold
3. **Startup Logging**: Hide verbose initialization logs unless startup fails
4. **Test Logging**: Only show logs for failing tests

## How It Works

The log gate acts as a valve between your logger and the output:

- **Gate Closed**: Logs are buffered in memory, not written to output
- **Gate Open**: Logs flow through immediately to the output
- **Open Gate**: Flushes all buffered logs and keeps gate open
- **Flush**: Writes buffered logs but keeps gate closed
- **Clear**: Discards buffered logs without writing them

## Basic Usage

### Creating a Gated Logger

```go
import log "github.com/stephnangue/warden/logger"

// Create logger with closed gate
config := log.DefaultConfig()
gateConfig := log.GatedWriterConfig{
    Underlying:   os.Stdout,
    InitialState: log.GateClosed,
}

logger, gate := log.NewGatedLogger(config, gateConfig)

// These logs are buffered, not shown yet
logger.Info("Starting operation...")
logger.Debug("Processing step 1")
logger.Debug("Processing step 2")

// Decide whether to show logs
if operationFailed {
    // Show all buffered logs
    logger.OpenGate()
    logger.Error("Operation failed - see logs above")
} else {
    // Discard buffered logs
    logger.ClearGate()
    logger.Info("Operation succeeded")
}
```

### Configuration Options

```go
gateConfig := log.GatedWriterConfig{
    // Writer to flush to when gate opens
    Underlying: os.Stdout,

    // Start with gate open or closed
    InitialState: log.GateClosed, // or log.GateOpen

    // Max buffer size in bytes (0 = unlimited)
    // When exceeded, oldest logs are discarded
    MaxBufferSize: 1024 * 1024, // 1MB
}
```

## Derived Loggers with Modules

When using `WithSystem()` or `WithSubsystem()` to create module-specific loggers, all derived loggers share the same gate:

```go
// Create root logger with closed gate
rootLogger, _ := log.NewGatedLogger(config, gateConfig)

// Create module loggers - they share the same gate
authLogger := rootLogger.WithSystem("auth")
storageLogger := rootLogger.WithSystem("storage")
apiLogger := rootLogger.WithSystem("api")

// All these logs are buffered
authLogger.Debug("Initializing auth module")
storageLogger.Debug("Connecting to database")
apiLogger.Debug("Starting HTTP server")

// Open gate from any logger - affects all loggers
if initializationFailed {
    storageLogger.OpenGate() // Can open from any derived logger
    rootLogger.Error("Initialization failed")
} else {
    rootLogger.ClearGate()
    rootLogger.Info("All modules initialized")
}
```

### Passing to Module Functions

When passing loggers to module initialization functions, you have two options:

```go
// Option 1: Pass the Logger interface (if module doesn't need gate control)
func initModule(name string, logger log.Logger) error {
    logger.Debug("Initializing...")
    return nil
}

moduleLogger := gatedLogger.WithSystem("module")
initModule("module", moduleLogger.Logger)

// Option 2: Pass *GatedLogger (if module needs gate control)
func initModuleWithGate(name string, logger *log.GatedLogger) error {
    logger.Debug("Initializing...")
    if err := doSomething(); err != nil {
        logger.OpenGate() // Module can control the gate
        return err
    }
    return nil
}

moduleLogger := gatedLogger.WithSystem("module")
initModuleWithGate("module", moduleLogger)
```

## Common Patterns

### 1. Conditional Logging on Failure

```go
logger, _ := log.NewGatedLogger(config, log.GatedWriterConfig{
    Underlying:   os.Stdout,
    InitialState: log.GateClosed,
})

logger.Debug("Step 1: Validating input")
logger.Debug("Step 2: Processing data")

if err := processData(); err != nil {
    logger.OpenGate() // Show all debug logs
    logger.Error("Processing failed", log.Err(err))
} else {
    logger.ClearGate() // Discard debug logs
    logger.Info("Processing completed")
}
```

### 2. Error Threshold

```go
logger, _ := log.NewGatedLogger(config, log.GatedWriterConfig{
    Underlying:   os.Stdout,
    InitialState: log.GateClosed,
})

errorCount := 0
maxErrors := 3

for _, item := range items {
    logger.Debug("Processing", log.String("item", item))

    if err := process(item); err != nil {
        errorCount++
        logger.Warn("Error processing item", log.Err(err))

        if errorCount >= maxErrors {
            logger.OpenGate() // Too many errors, show everything
            logger.Error("Error threshold exceeded")
            break
        }
    }
}
```

### 3. System Initialization

```go
logger, _ := log.NewGatedLogger(config, log.GatedWriterConfig{
    Underlying:    os.Stdout,
    InitialState:  log.GateClosed,
    MaxBufferSize: 1024 * 1024,
})

modules := []string{"auth", "storage", "api", "cache"}
success := true

for _, name := range modules {
    moduleLogger := logger.WithSystem(name)

    moduleLogger.Debug("Loading configuration")
    moduleLogger.Debug("Initializing connections")

    if err := initModule(name, moduleLogger.Logger); err != nil {
        moduleLogger.Error("Initialization failed", log.Err(err))
        success = false
        break
    }

    moduleLogger.Info("Module ready")
}

if success {
    logger.ClearGate() // Hide debug logs
    logger.OpenGate()
    logger.Info("System ready")
} else {
    logger.OpenGate() // Show all debug logs for troubleshooting
    logger.Error("System initialization failed")
}
```

### 4. Test Logging

```go
func TestFeature(t *testing.T) {
    logger, _ := log.NewGatedLogger(config, log.GatedWriterConfig{
        Underlying:   os.Stdout,
        InitialState: log.GateClosed,
    })

    logger.Debug("Setting up test")
    logger.Debug("Running test case 1")
    logger.Debug("Running test case 2")

    if testFailed {
        logger.OpenGate() // Show logs for failed test
        t.Error("Test failed - see logs above")
    } else {
        logger.ClearGate() // Hide logs for passing test
    }
}
```

### 5. Adaptive Logging Based on System Health

```go
logger, _ := log.NewGatedLogger(config, log.GatedWriterConfig{
    Underlying:   os.Stdout,
    InitialState: log.GateClosed,
})

cpuUsage := getCP Usage()
memUsage := getMemUsage()

logger.Debug("CPU", log.Float64("usage", cpuUsage))
logger.Debug("Memory", log.Float64("usage", memUsage))

if cpuUsage > 80 || memUsage > 80 {
    logger.OpenGate() // System under stress, show details
    logger.Warn("System under stress")
} else {
    logger.ClearGate() // System healthy, hide details
    logger.Info("System healthy")
}
```

### 6. Manual Flush (Checkpoint Pattern)

```go
logger, _ := log.NewGatedLogger(config, log.GatedWriterConfig{
    Underlying:   os.Stdout,
    InitialState: log.GateClosed,
})

// Phase 1
logger.Debug("Phase 1: Starting")
logger.Info("Phase 1: Processing")
logger.FlushGate() // Write phase 1 logs, keep gate closed

// Phase 2
logger.Debug("Phase 2: Starting")
logger.Info("Phase 2: Processing")
logger.FlushGate() // Write phase 2 logs

// Final
logger.OpenGate() // Keep gate open for remaining execution
```

## API Reference

### GatedWriter

```go
type GatedWriter struct { /* ... */ }

// Create new gated writer
func NewGatedWriter(config GatedWriterConfig) *GatedWriter

// Open gate and flush buffered logs
func (gw *GatedWriter) OpenGate() error

// Close gate (buffer subsequent logs)
func (gw *GatedWriter) CloseGate()

// Flush buffered logs without opening gate
func (gw *GatedWriter) Flush() error

// Check if gate is open
func (gw *GatedWriter) IsOpen() bool

// Get size of buffered logs in bytes
func (gw *GatedWriter) BufferedSize() int

// Discard buffered logs without flushing
func (gw *GatedWriter) Clear()
```

### GatedLogger

```go
type GatedLogger struct {
    Logger
    // ... internal fields
}

// Create new gated logger
func NewGatedLogger(config *Config, gateConfig GatedWriterConfig) (*GatedLogger, *GatedWriter)

// Create derived logger with system name (preserves gate access)
func (gl *GatedLogger) WithSystem(name string) *GatedLogger

// Create derived logger with subsystem (preserves gate access)
func (gl *GatedLogger) WithSubsystem(name string) *GatedLogger

// Create derived logger with fields (preserves gate access)
func (gl *GatedLogger) WithFields(fields ...TypedField) *GatedLogger

// Gate control methods
func (gl *GatedLogger) OpenGate() error
func (gl *GatedLogger) CloseGate()
func (gl *GatedLogger) FlushGate() error
func (gl *GatedLogger) IsGateOpen() bool
func (gl *GatedLogger) ClearGate()
func (gl *GatedLogger) BufferedSize() int
```

## Performance Considerations

1. **Buffer Size**: Set `MaxBufferSize` to prevent unbounded memory growth in long-running operations
2. **Shared Gate**: All derived loggers share the same gate and buffer, so opening/closing affects all loggers
3. **Thread Safety**: All gate operations are thread-safe with mutex protection
4. **Memory Usage**: Buffered logs consume memory - clear or flush periodically for long operations

## Best Practices

1. **Clear or Flush**: Always decide whether to clear or flush buffered logs at the end of an operation
2. **Max Buffer**: Set a reasonable `MaxBufferSize` for production use
3. **Module Loggers**: Use `WithSystem()` to create module-specific loggers that share the gate
4. **Error Handling**: Always check the error from `OpenGate()` and `FlushGate()`
5. **Documentation**: Document when and why the gate opens in your code
