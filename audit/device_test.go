package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"net/http"
)

func TestDevice(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	sink, err := NewFileSink(FileSinkConfig{
		Path: logPath,
	})
	if err != nil {
		t.Fatalf("Failed to create file sink: %v", err)
	}

	format := NewJSONFormat()
	device := NewDevice("test", format, sink, &DeviceConfig{
		Name:    "test",
		Enabled: true,
	})
	defer device.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-456",
			Operation: "write",
			Path:      "/v1/secret/data/test",
			ClientIP:  "192.168.1.101",
		},
	}

	ctx := context.Background()
	if err := device.LogRequest(ctx, entry); err != nil {
		t.Errorf("Failed to log request: %v", err)
	}

	// Verify file contains data
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Errorf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty after logging")
	}
}

func TestDeviceLogResponse(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	sink, err := NewFileSink(FileSinkConfig{Path: logPath})
	if err != nil {
		t.Fatalf("Failed to create sink: %v", err)
	}

	format := NewJSONFormat()
	dev := NewDevice("test", format, sink, &DeviceConfig{
		Name:    "test",
		Enabled: true,
	})
	defer dev.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request:   &Request{ID: "req-1", Path: "/test"},
		Response:  &Response{StatusCode: 200},
	}

	if err := dev.LogResponse(context.Background(), entry); err != nil {
		t.Errorf("LogResponse failed: %v", err)
	}
}

func TestDeviceLogResponseDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "audit.log")})
	format := NewJSONFormat()
	dev := NewDevice("test", format, sink, &DeviceConfig{Name: "test", Enabled: false})
	defer dev.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request:   &Request{ID: "req-1", Path: "/test"},
		Response:  &Response{StatusCode: 200},
	}

	if err := dev.LogResponse(context.Background(), entry); err != nil {
		t.Errorf("LogResponse on disabled device should not error: %v", err)
	}
}

func TestDeviceLogTestRequest(t *testing.T) {
	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "audit.log")})
	format := NewJSONFormat()
	dev := NewDevice("test", format, sink, &DeviceConfig{Name: "test", Enabled: true})
	defer dev.Close()

	if err := dev.LogTestRequest(context.Background()); err != nil {
		t.Errorf("LogTestRequest failed: %v", err)
	}
}

func TestDeviceSetEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "audit.log")})
	format := NewJSONFormat()
	dev := NewDevice("test", format, sink, &DeviceConfig{Name: "test", Enabled: true})
	defer dev.Close()

	if !dev.Enabled() {
		t.Error("expected enabled")
	}
	dev.SetEnabled(false)
	if dev.Enabled() {
		t.Error("expected disabled after SetEnabled(false)")
	}
}

func TestDeviceConfig(t *testing.T) {
	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "audit.log")})
	format := NewJSONFormat()

	devConfig := &DeviceConfig{
		Name:        "mydev",
		Type:        "file",
		Class:       "audit",
		Description: "test device",
		Accessor:    "acc-123",
		Enabled:     true,
		Format:      "json",
		Prefix:      "prefix-",
		HMACKey:     "key",
	}
	dev := NewDevice("mydev", format, sink, devConfig)
	defer dev.Close()

	cfg := dev.(*device).Config()
	if cfg["name"] != "mydev" {
		t.Errorf("expected name mydev, got %v", cfg["name"])
	}
	if cfg["type"] != "file" {
		t.Errorf("expected type file, got %v", cfg["type"])
	}
	if cfg["description"] != "test device" {
		t.Errorf("expected description, got %v", cfg["description"])
	}
	if cfg["accessor"] != "acc-123" {
		t.Errorf("expected accessor, got %v", cfg["accessor"])
	}
}

func TestDeviceConfigNil(t *testing.T) {
	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "audit.log")})
	format := NewJSONFormat()
	dev := NewDevice("test", format, sink, nil)
	defer dev.Close()

	// Config should not panic with the default config
	d := dev.(*device)
	cfg := d.Config()
	if cfg["name"] != "test" {
		t.Errorf("expected name test from default config, got %v", cfg["name"])
	}
}

func TestDeviceBackendMethods(t *testing.T) {
	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "audit.log")})
	format := NewJSONFormat()
	devConfig := &DeviceConfig{
		Name:        "test",
		Type:        "file",
		Class:       "audit",
		Description: "a test",
		Accessor:    "acc-1",
		Enabled:     true,
	}
	dev := NewDevice("test", format, sink, devConfig)
	defer dev.Close()

	d := dev.(*device)

	if err := d.Setup(context.Background(), nil); err != nil {
		t.Errorf("Setup should return nil: %v", err)
	}
	if d.GetType() != "file" {
		t.Errorf("expected file, got %s", d.GetType())
	}
	if d.Type() != "file" {
		t.Errorf("expected file, got %s", d.Type())
	}
	if d.GetClass() != "audit" {
		t.Errorf("expected audit, got %s", d.GetClass())
	}
	if d.Class() != 0 { // ClassUnknown
		t.Errorf("expected ClassUnknown, got %v", d.Class())
	}
	if d.GetDescription() != "a test" {
		t.Errorf("expected 'a test', got %s", d.GetDescription())
	}
	if d.GetAccessor() != "acc-1" {
		t.Errorf("expected acc-1, got %s", d.GetAccessor())
	}

	resp, err := d.HandleRequest(context.Background(), nil)
	if resp != nil || err != nil {
		t.Error("HandleRequest should return nil, nil")
	}

	d.Cleanup(context.Background())

	if err := d.Initialize(context.Background()); err != nil {
		t.Errorf("Initialize should return nil: %v", err)
	}

	if token := d.ExtractToken(&http.Request{}); token != "" {
		t.Errorf("expected empty token, got %s", token)
	}

	found, exists, err := d.HandleExistenceCheck(context.Background(), nil)
	if found || exists || err != nil {
		t.Error("HandleExistenceCheck should return false, false, nil")
	}

	if paths := d.SpecialPaths(); paths != nil {
		t.Error("SpecialPaths should return nil")
	}
}

func TestDevicePathFilters(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("exclude paths", func(t *testing.T) {
		sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "exclude.log")})
		format := NewJSONFormat()
		dev := NewDevice("test", format, sink, &DeviceConfig{
			Name:         "test",
			Enabled:      true,
			ExcludePaths: []string{"/sys/health", "/v1/secret/*"},
		})
		defer dev.Close()

		// Excluded path - should not log (no error, just skip)
		entry := &LogEntry{
			Timestamp: time.Now(),
			Request:   &Request{ID: "req-1", Path: "/sys/health"},
		}
		if err := dev.LogRequest(context.Background(), entry); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Non-excluded path - should log
		entry2 := &LogEntry{
			Timestamp: time.Now(),
			Request:   &Request{ID: "req-2", Path: "/v1/auth/login"},
		}
		if err := dev.LogRequest(context.Background(), entry2); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("include paths", func(t *testing.T) {
		sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "include.log")})
		format := NewJSONFormat()
		dev := NewDevice("test", format, sink, &DeviceConfig{
			Name:         "test",
			Enabled:      true,
			IncludePaths: []string{"/v1/secret"},
		})
		defer dev.Close()

		// Non-included path
		entry := &LogEntry{
			Timestamp: time.Now(),
			Request:   &Request{ID: "req-1", Path: "/v1/auth/login"},
		}
		if err := dev.LogRequest(context.Background(), entry); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Included path (prefix match)
		entry2 := &LogEntry{
			Timestamp: time.Now(),
			Request:   &Request{ID: "req-2", Path: "/v1/secret/data/foo"},
		}
		if err := dev.LogRequest(context.Background(), entry2); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("include paths nil request", func(t *testing.T) {
		sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "include_nil.log")})
		format := NewJSONFormat()
		dev := NewDevice("test", format, sink, &DeviceConfig{
			Name:         "test",
			Enabled:      true,
			IncludePaths: []string{"/v1/secret"},
		})
		defer dev.Close()

		entry := &LogEntry{Timestamp: time.Now()}
		if err := dev.LogRequest(context.Background(), entry); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("exclude paths nil request", func(t *testing.T) {
		sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "exclude_nil.log")})
		format := NewJSONFormat()
		dev := NewDevice("test", format, sink, &DeviceConfig{
			Name:         "test",
			Enabled:      true,
			ExcludePaths: []string{"/sys/health"},
		})
		defer dev.Close()

		entry := &LogEntry{Timestamp: time.Now()}
		if err := dev.LogRequest(context.Background(), entry); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
