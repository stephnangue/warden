package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	if agent, user := d.ExtractTokens(&http.Request{}, false); agent != "" || user != "" {
		t.Errorf("expected empty tokens, got agent=%s user=%s", agent, user)
	}

	found, exists, err := d.HandleExistenceCheck(context.Background(), nil)
	if found || exists || err != nil {
		t.Error("HandleExistenceCheck should return false, false, nil")
	}

	if paths := d.SpecialPaths(); paths != nil {
		t.Error("SpecialPaths should return nil")
	}
}

// keepingSink is a sink that keeps a copy of each entry it is given.
type keepingSink struct {
	discardSink
	mu      sync.Mutex
	entries []string
}

func (s *keepingSink) Write(_ context.Context, entry []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, string(entry))
	return nil
}

// Devices format their entries in buffers they take from a common pool and
// put back. Entries logged at the same time, by devices that format them
// differently, each reach their sink whole: none holds bytes of another, or
// of the entry its buffer held before.
func TestDevice_EntriesDoNotShareABuffer(t *testing.T) {
	type sunk struct {
		prefix string
		sink   *keepingSink
		device Device
	}
	var devices []sunk
	for _, prefix := range []string{"first:", "second:"} {
		sink := &keepingSink{}
		format := NewJSONFormat(WithPrefix(prefix))
		devices = append(devices, sunk{prefix, sink, NewDevice(prefix, format, sink, &DeviceConfig{Name: prefix, Enabled: true})})
	}

	const loggers, perLogger = 8, 200
	ctx := context.Background()
	var wg sync.WaitGroup
	for l := range loggers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range perLogger {
				// Entries of very different sizes, each naming itself twice.
				id := fmt.Sprintf("logger-%d-entry-%d", l, n)
				entry := &LogEntry{
					Timestamp: time.Now(),
					Request:   &Request{ID: id, Path: strings.Repeat("/segment", n%40) + "/" + id},
				}
				for _, d := range devices {
					if err := d.device.LogRequest(ctx, entry); err != nil {
						t.Errorf("%s %s: %v", d.prefix, id, err)
						return
					}
					if err := d.device.LogResponse(ctx, entry); err != nil {
						t.Errorf("%s %s: %v", d.prefix, id, err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()

	for _, d := range devices {
		if got, want := len(d.sink.entries), 2*loggers*perLogger; got != want {
			t.Fatalf("%s %d entries, want %d", d.prefix, got, want)
		}
		for _, line := range d.sink.entries {
			body, ok := strings.CutPrefix(line, d.prefix)
			if !ok {
				t.Fatalf("%s an entry without the device's prefix: %q", d.prefix, line)
			}
			var entry LogEntry
			if err := json.Unmarshal([]byte(body), &entry); err != nil {
				t.Fatalf("%s an entry that is not JSON (%v): %q", d.prefix, err, line)
			}
			if entry.Request == nil || !strings.HasSuffix(entry.Request.Path, "/"+entry.Request.ID) {
				t.Fatalf("%s an entry made of two: %q", d.prefix, line)
			}
		}
	}
}

// Auditing a request allocates nothing once its device has run: the entry is
// redacted as it is encoded, in a buffer the device reuses, salted with a hash
// it reuses, and copied into a buffer its sink reuses. What a request costs to
// audit does not grow the heap, whatever the device salts and omits.
func TestDevice_AuditsWithoutAllocating(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	conf, err := mapToFileDeviceConfig(map[string]any{
		"hmac_key": "0123456789abcdef0123456789abcdef",
		"salt_fields": []string{
			"auth.principal_id", "auth.alias_name", "request.client_ip",
			"auth.policy_results.granting_policies", "response.credential.metadata.subject",
		},
		"omit_fields": []string{"auth.policy_results.mcp_client", "auth.groups", "response.upstream_url"},
	})
	if err != nil {
		t.Fatal(err)
	}
	format, warnings := jsonFormatFor(conf)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %q", warnings)
	}
	sink, err := NewBufferedSink(BufferedSinkConfig{Sink: batchDiscardSink{}, BufferSize: 10, FlushPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	device := NewDevice("file/", format, sink, &DeviceConfig{Name: "file/", Enabled: true})
	defer device.Close()

	ctx := context.Background()
	request, response := gatewayRequestEntry(), gatewayResponseEntry()
	got := testing.AllocsPerRun(200, func() {
		if err := device.LogRequest(ctx, request); err != nil {
			t.Fatal(err)
		}
		if err := device.LogResponse(ctx, response); err != nil {
			t.Fatal(err)
		}
	})
	if got != 0 {
		t.Errorf("%v allocations to audit a request, want none", got)
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
