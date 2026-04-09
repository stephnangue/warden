package audit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stephnangue/warden/logger"
)

func TestFileDeviceFactory(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	f := &FileDeviceFactory{}

	if f.Type() != "file" {
		t.Errorf("expected file, got %s", f.Type())
	}
	if f.Class() != "audit" {
		t.Errorf("expected audit, got %s", f.Class())
	}

	if err := f.Initialize(log); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	dev, err := f.Create(context.Background(), "test/", "test device", "", map[string]any{
		"file_path": logPath,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer dev.Close()

	if dev.Name() != "test/" {
		t.Errorf("expected name test/, got %s", dev.Name())
	}
}

func TestFileDeviceFactoryWithOptions(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	f := &FileDeviceFactory{}
	f.Initialize(log)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	dev, err := f.Create(context.Background(), "test/", "test device", "custom-accessor", map[string]any{
		"file_path":   logPath,
		"hmac_key":    "secret-key",
		"salt_fields": []any{"auth.token_id"},
		"omit_fields": []any{"request.data"},
		"prefix":      "AUDIT: ",
		"buffer_size": float64(50),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer dev.Close()
}

func TestFileDeviceFactoryInvalidFormat(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	f := &FileDeviceFactory{}
	f.Initialize(log)

	_, err := f.Create(context.Background(), "test/", "", "", map[string]any{
		"file_path": "/tmp/test.log",
		"format":    "xml",
	})
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestFileDeviceFactoryInvalidMode(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	f := &FileDeviceFactory{}
	f.Initialize(log)

	_, err := f.Create(context.Background(), "test/", "", "", map[string]any{
		"file_path": "/tmp/test.log",
		"file_mode": "invalid",
	})
	if err == nil {
		t.Error("expected error for invalid file mode")
	}
}
