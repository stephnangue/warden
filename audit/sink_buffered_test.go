package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBufferedSink(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	fileSink, err := NewFileSink(FileSinkConfig{
		Path: logPath,
	})
	if err != nil {
		t.Fatalf("Failed to create file sink: %v", err)
	}

	bufferedSink, err := NewBufferedSink(BufferedSinkConfig{
		Sink:        fileSink,
		BufferSize:  10,
		FlushPeriod: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create buffered sink: %v", err)
	}
	defer bufferedSink.Close()

	ctx := context.Background()

	// Write several entries
	for i := 0; i < 5; i++ {
		data := []byte(`{"entry":"` + string(rune(i)) + `"}`)
		if err := bufferedSink.Write(ctx, data); err != nil {
			t.Errorf("Failed to write entry %d: %v", i, err)
		}
	}

	// Wait for periodic flush
	time.Sleep(200 * time.Millisecond)

	// Verify file contains data
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Errorf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty after buffered writes")
	}
}
