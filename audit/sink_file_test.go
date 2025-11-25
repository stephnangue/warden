package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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