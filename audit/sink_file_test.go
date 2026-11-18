package audit

import (
	"context"
	"errors"
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

// A batch is written as it is: its entries already end with a newline each.
func TestFileSink_WriteBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := NewFileSink(FileSinkConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	ctx := context.Background()

	batch := []byte(sinkLines(1, 3))
	if n, err := sink.WriteBatch(ctx, batch); err != nil || n != len(batch) {
		t.Fatalf("WriteBatch: %d bytes, %v; want %d", n, err, len(batch))
	}
	if err := sink.Write(ctx, sinkEntry(4)); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), sinkLines(1, 4); got != want {
		t.Errorf("file:\n got %q\nwant %q", got, want)
	}
	if sink.currentSize != int64(len(content)) {
		t.Errorf("the sink counts %d bytes in a file of %d", sink.currentSize, len(content))
	}
}

// A file whose last line was cut by a crash has that line ended before the
// first entry of the next run is written, so the entry is not joined to it. A
// file that ends cleanly is left as it is.
func TestFileSink_OpensAFileLeftMidLine(t *testing.T) {
	for _, tc := range []struct {
		name, before, want string
	}{
		{"cut line", sinkLines(1, 1) + `{"n"`, sinkLines(1, 1) + `{"n"` + "\n" + sinkLines(2, 2)},
		{"whole lines", sinkLines(1, 1), sinkLines(1, 2)},
		{"empty", "", sinkLines(2, 2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			if err := os.WriteFile(path, []byte(tc.before), 0o600); err != nil {
				t.Fatal(err)
			}
			sink, err := NewFileSink(FileSinkConfig{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			if err := sink.Write(context.Background(), sinkEntry(2)); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != tc.want {
				t.Errorf("file:\n got %q\nwant %q", content, tc.want)
			}
		})
	}
}

// While the file cannot even take the newline that ends a cut line, nothing
// else is written to it: an entry written there would be joined to the
// fragment. Once it can, the newline comes first.
func TestFileSink_CutLineIsEndedFirst(t *testing.T) {
	sink, err := NewFileSink(FileSinkConfig{Path: filepath.Join(t.TempDir(), "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	file := &flakyFile{}
	sink.writer = file
	ctx := context.Background()

	const fragment = `{"n"`
	batch := []byte(sinkLines(1, 2))
	file.accept(len(fragment))
	if n, err := sink.WriteBatch(ctx, batch); n != len(fragment) || !errors.Is(err, errDiskFull) {
		t.Fatalf("the write cut short: %d bytes, %v", n, err)
	}
	if n, err := sink.WriteBatch(ctx, batch); n != 0 || !errors.Is(err, errDiskFull) {
		t.Fatalf("a write while the file is full: %d bytes, %v", n, err)
	}
	if got := file.content(); got != fragment {
		t.Fatalf("file while full: %q, want the fragment alone", got)
	}

	file.recover()
	if n, err := sink.WriteBatch(ctx, batch); err != nil || n != len(batch) {
		t.Fatalf("the write after recovery: %d bytes, %v", n, err)
	}
	if got, want := file.content(), fragment+"\n"+string(batch); got != want {
		t.Errorf("file:\n got %q\nwant %q", got, want)
	}
}

// A cut line does not hold rotation back: a sink that waited to end its line
// before rotating would wait for as long as the file refuses the newline. The
// file is rotated although the line could not be ended, and the new file
// starts with a whole entry, not with the newline owed to the old one.
func TestFileSink_CutLineDoesNotHoldRotationBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := NewFileSink(FileSinkConfig{Path: path, RotateDaily: true, MaxBackups: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	file := &flakyFile{}
	sink.writer = file
	ctx := context.Background()

	batch := []byte(sinkLines(1, 2))
	file.accept(4)
	if _, err := sink.WriteBatch(ctx, batch); !errors.Is(err, errDiskFull) {
		t.Fatalf("the write cut short: %v", err)
	}

	// The disk is still full, and the day has changed.
	file.accept(0)
	sink.lastRotate = time.Now().Add(-25 * time.Hour)
	if n, err := sink.WriteBatch(ctx, batch); err != nil || n != len(batch) {
		t.Fatalf("the write after the day changed: %d bytes, %v", n, err)
	}
	if backups, _ := filepath.Glob(path + ".*"); len(backups) != 1 {
		t.Errorf("backups after the rotation: %q, want one", backups)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(batch) {
		t.Errorf("the new file:\n got %q\nwant %q", content, batch)
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
