package logger

import (
	"fmt"
	"io"
	"os"
)

// Config holds the configuration for the logger
type Config struct {
	Level          LogLevel
	Format         OutputFormat
	Outputs        []io.Writer
	Environment    string // "development" or "production"
	Subsystem      string
	FileConfig     *FileConfig
	EnableCaller   bool // Include caller information
	EnableSampling bool // Enable log sampling for high-throughput scenarios
	CallerSkip     int  // Number of stack frames to skip when logging caller
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Level:          TraceLevel,
		Format:         DefaultFormat,
		Outputs:        []io.Writer{os.Stdout},
		Environment:    "development",
		Subsystem:      "",
		EnableCaller:   false,
		EnableSampling: false,
		CallerSkip:     0,
	}
}

// ProductionConfig returns a production-ready configuration with file logging
func ProductionConfig(appName string) *Config {
	return &Config{
		Level:       InfoLevel,
		Format:      JSONFormat,
		Environment: "production",
		FileConfig: &FileConfig{
			Filename:   fmt.Sprintf("logs/%s.log", appName),
			MaxSize:    100,
			MaxAge:     30,
			MaxBackups: 10,
			Compress:   true,
		},
		EnableCaller:   true,
		EnableSampling: true,
		CallerSkip:     0,
	}
}
