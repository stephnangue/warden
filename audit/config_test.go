package audit

import (
	"testing"
	"time"
)

func TestMapToFileDeviceConfig_Defaults(t *testing.T) {
	config, err := mapToFileDeviceConfig(map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.Path != "warden_audit.log" {
		t.Errorf("expected default path, got %s", config.Path)
	}
	if config.Format != "json" {
		t.Errorf("expected json format, got %s", config.Format)
	}
	if !config.Enabled {
		t.Error("expected enabled by default")
	}
	if config.BufferSize != 100 {
		t.Errorf("expected buffer size 100, got %d", config.BufferSize)
	}
	if config.FlushPeriod != 5*time.Second {
		t.Errorf("expected flush period 5s, got %v", config.FlushPeriod)
	}
	if config.Mode != "0600" {
		t.Errorf("expected mode 0600, got %s", config.Mode)
	}
	if !config.RotateDaily {
		t.Error("expected rotate daily by default")
	}
	if config.MaxBackups != 5 {
		t.Errorf("expected max backups 5, got %d", config.MaxBackups)
	}
}

func TestMapToFileDeviceConfig_Override(t *testing.T) {
	config, err := mapToFileDeviceConfig(map[string]any{
		"file_path":   "/tmp/custom.log",
		"buffer_size": float64(50),
		"max_backups": float64(10),
		"enabled":     false,
		"hmac_key":    "mykey",
		"skip_test":   true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.Path != "/tmp/custom.log" {
		t.Errorf("expected /tmp/custom.log, got %s", config.Path)
	}
	if config.BufferSize != 50 {
		t.Errorf("expected buffer size 50, got %d", config.BufferSize)
	}
	if config.MaxBackups != 10 {
		t.Errorf("expected max backups 10, got %d", config.MaxBackups)
	}
	if config.Enabled {
		t.Error("expected disabled")
	}
	if config.HMACKey != "mykey" {
		t.Errorf("expected hmac key mykey, got %s", config.HMACKey)
	}
	if !config.SkipTest {
		t.Error("expected skip_test true")
	}
}

func TestMapToFileDeviceConfig_InvalidData(t *testing.T) {
	// Pass something that can't be marshaled properly for unmarshal to fail
	// Actually json.Marshal/Unmarshal is quite permissive, test validation failures instead
	_, err := mapToFileDeviceConfig(map[string]any{
		"file_path": "",
	})
	if err == nil {
		t.Error("expected validation error for empty path")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  FileDeviceConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  100,
				FlushPeriod: 5 * time.Second,
				RotateSize:  1048576,
				MaxBackups:  5,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: false,
		},
		{
			name: "empty path",
			config: FileDeviceConfig{
				Path:        "",
				BufferSize:  100,
				FlushPeriod: 5 * time.Second,
				MaxBackups:  5,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "buffer size too small",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  0,
				FlushPeriod: 5 * time.Second,
				MaxBackups:  5,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "buffer size too large",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  MaxBufferSize + 1,
				FlushPeriod: 5 * time.Second,
				MaxBackups:  5,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "flush period too small",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  100,
				FlushPeriod: 1 * time.Millisecond,
				MaxBackups:  5,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "flush period too large",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  100,
				FlushPeriod: 2 * time.Hour,
				MaxBackups:  5,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "rotate size too large",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  100,
				FlushPeriod: 5 * time.Second,
				RotateSize:  MaxRotateSize + 1,
				MaxBackups:  5,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "max backups too small",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  100,
				FlushPeriod: 5 * time.Second,
				MaxBackups:  0,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "max backups too large",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  100,
				FlushPeriod: 5 * time.Second,
				MaxBackups:  MaxMaxBackups + 1,
				Mode:        "0600",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "invalid file mode",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  100,
				FlushPeriod: 5 * time.Second,
				MaxBackups:  5,
				Mode:        "9999",
				Format:      "json",
			},
			wantErr: true,
		},
		{
			name: "unsupported format",
			config: FileDeviceConfig{
				Path:        "/tmp/audit.log",
				BufferSize:  100,
				FlushPeriod: 5 * time.Second,
				MaxBackups:  5,
				Mode:        "0600",
				Format:      "xml",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
