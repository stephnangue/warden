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

func mapToFileDeviceConfig(data map[string]any) (*FileDeviceConfig, error) {
	// Set defaults first
	config := FileDeviceConfig{
		Path:        "warden_audit.log",
		RotateSize:  1048576000, // 1000MB
		RotateDaily: true,
		MaxBackups:  5,
		Enabled:     true,
		Format:      "json",
		BufferSize:  100,
		FlushPeriod: 5 * time.Second,
		Mode:        "0600",
		SaltFields: []string{
			"response.data.secret_access_key",
			"auth.client_token.data",
			"response.auth.client_token.data",
			"response.cred.data",
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

	return &config, nil
}
