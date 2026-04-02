package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fmt"
)

func TestFileSink(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	sink, err := NewFileSink(FileSinkConfig{
		Path: logPath,
	})
	if err != nil {
		t.Fatalf("Failed to create file sink: %v", err)
	}
	defer sink.Close()

	ctx := context.Background()
	testData := []byte(`{"type":"request","operation":"read"}`)

	if err := sink.Write(ctx, testData); err != nil {
		t.Errorf("Failed to write to sink: %v", err)
	}

	// Verify file exists and contains data
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Errorf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty")
	}
}

func TestPathFiltering(t *testing.T) {
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
		Name:         "test",
		Enabled:      true,
		ExcludePaths: []string{"/health", "/metrics"},
	})
	defer device.Close()

	ctx := context.Background()

	// Log excluded path
	excludedEntry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-001",
			Operation: "read",
			Path:      "/health",
			ClientIP:  "192.168.1.100",
		},
	}

	if err := device.LogRequest(ctx, excludedEntry); err != nil {
		t.Errorf("Failed to log request: %v", err)
	}

	// Log included path
	includedEntry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-002",
			Operation: "read",
			Path:      "/v1/secret/data/test",
			ClientIP:  "192.168.1.100",
		},
	}

	if err := device.LogRequest(ctx, includedEntry); err != nil {
		t.Errorf("Failed to log request: %v", err)
	}

	// Verify only included path was logged
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Errorf("Failed to read log file: %v", err)
	}

	if contains(content, "/health") {
		t.Error("Excluded path /health was logged")
	}

	if !contains(content, "/v1/secret/data/test") {
		t.Error("Included path /v1/secret/data/test was not logged")
	}
}

func contains(data []byte, substr string) bool {
	return len(data) > 0 && len(substr) > 0 &&
		len(data) >= len(substr) &&
		string(data) != "" &&
		findSubstring(string(data), substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFileSinkNameAndType(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "audit.log")
	sink, err := NewFileSink(FileSinkConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileSink failed: %v", err)
	}
	defer sink.Close()

	if sink.Name() != path {
		t.Errorf("expected %s, got %s", path, sink.Name())
	}
	if sink.Type() != "file" {
		t.Errorf("expected file, got %s", sink.Type())
	}
}

func TestFileSinkRotateBySize(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "audit.log")

	sink, err := NewFileSink(FileSinkConfig{
		Path:       path,
		RotateSize: 50, // Very small to trigger rotation
		MaxBackups: 2,
	})
	if err != nil {
		t.Fatalf("NewFileSink failed: %v", err)
	}
	defer sink.Close()

	ctx := context.Background()

	// Write enough data to trigger rotation
	for i := 0; i < 10; i++ {
		data := []byte(`{"message":"this is a test log entry that is long enough"}`)
		if err := sink.Write(ctx, data); err != nil {
			t.Fatalf("Write failed on iteration %d: %v", i, err)
		}
	}

	// Wait for async cleanup
	time.Sleep(100 * time.Millisecond)

	// Check that backup files exist
	matches, _ := filepath.Glob(path + ".*")
	if len(matches) == 0 {
		t.Error("expected backup files after rotation")
	}
}

func TestFileSinkRotateDaily(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "audit.log")

	sink, err := NewFileSink(FileSinkConfig{
		Path:        path,
		RotateDaily: true,
		MaxBackups:  2,
	})
	if err != nil {
		t.Fatalf("NewFileSink failed: %v", err)
	}

	// Force lastRotate to yesterday to trigger daily rotation
	sink.lastRotate = time.Now().Add(-25 * time.Hour)

	ctx := context.Background()
	if err := sink.Write(ctx, []byte(`{"test":"daily rotation"}`)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	sink.Close()

	// Check backup exists
	matches, _ := filepath.Glob(path + ".*")
	if len(matches) == 0 {
		t.Error("expected backup file after daily rotation")
	}
}

func TestCleanupBackupsAsync(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "audit.log")

	// Create several backup files
	for i := 0; i < 5; i++ {
		f, err := os.Create(basePath + "." + time.Now().Add(time.Duration(i)*time.Second).Format("20060102-150405") + fmt.Sprintf("%d", i))
		if err != nil {
			t.Fatalf("failed to create backup: %v", err)
		}
		f.Close()
	}

	cleanupBackupsAsync(basePath, 2)
	time.Sleep(100 * time.Millisecond)

	matches, _ := filepath.Glob(basePath + ".*")
	if len(matches) > 2 {
		t.Errorf("expected at most 2 backups, got %d", len(matches))
	}
}
