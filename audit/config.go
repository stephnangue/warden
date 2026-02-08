package audit

import (
	"encoding/json"
	"fmt"
	"time"
)

type FileDeviceConfig struct {
	// Sink params
	Path        string `json:"file_path" default:"warden_audit.log"`
	RotateSize  int64  `json:"rotate_size" default:"1048576000"`
	RotateDaily bool   `json:"rotate_daily" default:"true"`
	MaxBackups  int    `json:"max_backups" default:"5"`

	// Device params
	Enabled bool   `json:"enabled" default:"true"`
	Format  string `json:"format" default:"json"`
	Prefix  string `json:"prefix,omitempty"`

	// Performance options
	BufferSize  int           `json:"buffer_size" default:"100"`
	FlushPeriod time.Duration `json:"flush_period" default:"5s"`

	Mode string `json:"file_mode" default:"0600"`

	// Salting options
	HMACKey    string   `json:"hmac_key,omitempty"`
	SaltFields []string `json:"salt_fields,omitempty"`

	// Omission options
	OmitFields []string `json:"omit_fields,omitempty"`

	SkipTest bool `json:"skip_test" default:"false"`
}

// Configuration validation limits
const (
	MinBufferSize   = 1
	MaxBufferSize   = 100000
	MinFlushPeriod  = 100 * time.Millisecond
	MaxFlushPeriod  = 1 * time.Hour
	MinRotateSize   = 0 // 0 means no size-based rotation
	MaxRotateSize   = 100 * 1024 * 1024 * 1024 // 100GB
	MinMaxBackups   = 1
	MaxMaxBackups   = 1000
)

func mapToFileDeviceConfig(data map[string]any) (*FileDeviceConfig, error) {
	// Set defaults first
	config := FileDeviceConfig{
		Path:        "warden_audit.log",
		RotateSize:  104857600, // 100MB (more reasonable default)
		RotateDaily: true,
		MaxBackups:  5,
		Enabled:     true,
		Format:      "json",
		BufferSize:  100,
		FlushPeriod: 5 * time.Second,
		Mode:        "0600",
		SaltFields: []string{
			"response.credential.data", // HMAC salt all credential values (access_key, secret_key, password, etc.)
		},
		OmitFields: []string{
			"request.data",
			"request.headers",
			"response.data",
			"response.headers",
		},
		SkipTest: false,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal map: %w", err)
	}

	// Unmarshal JSON to struct
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to FileDeviceConfig: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

// Validate checks the configuration for invalid values
func (c *FileDeviceConfig) Validate() error {
	// Validate file path is provided
	if c.Path == "" {
		return fmt.Errorf("file_path is required")
	}

	// Validate buffer size
	if c.BufferSize < MinBufferSize || c.BufferSize > MaxBufferSize {
		return fmt.Errorf("buffer_size must be between %d and %d, got %d", MinBufferSize, MaxBufferSize, c.BufferSize)
	}

	// Validate flush period
	if c.FlushPeriod < MinFlushPeriod || c.FlushPeriod > MaxFlushPeriod {
		return fmt.Errorf("flush_period must be between %v and %v, got %v", MinFlushPeriod, MaxFlushPeriod, c.FlushPeriod)
	}

	// Validate rotate size
	if c.RotateSize < MinRotateSize || c.RotateSize > MaxRotateSize {
		return fmt.Errorf("rotate_size must be between %d and %d, got %d", MinRotateSize, MaxRotateSize, c.RotateSize)
	}

	// Validate max backups
	if c.MaxBackups < MinMaxBackups || c.MaxBackups > MaxMaxBackups {
		return fmt.Errorf("max_backups must be between %d and %d, got %d", MinMaxBackups, MaxMaxBackups, c.MaxBackups)
	}

	// Validate file mode format (must be valid octal)
	if c.Mode != "" {
		for _, ch := range c.Mode {
			if ch < '0' || ch > '7' {
				return fmt.Errorf("file_mode must be a valid octal string (e.g., '0600'), got '%s'", c.Mode)
			}
		}
	}

	// Validate format
	if c.Format != "json" {
		return fmt.Errorf("only 'json' format is supported, got '%s'", c.Format)
	}

	return nil
}
