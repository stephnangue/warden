package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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

