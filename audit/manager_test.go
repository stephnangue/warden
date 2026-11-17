package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// An entry is written once by every registered device.
func TestManagerLogsToEveryDevice(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)

	paths := make([]string, 5)
	for i := range paths {
		paths[i] = filepath.Join(t.TempDir(), fmt.Sprintf("audit-%d.log", i))
		sink, err := NewFileSink(FileSinkConfig{Path: paths[i]})
		if err != nil {
			t.Fatalf("Failed to create sink: %v", err)
		}
		name := fmt.Sprintf("device-%d", i)
		device := NewDevice(name, NewJSONFormat(), sink, &DeviceConfig{Name: name, Enabled: true})
		if err := manager.RegisterDevice(name, device); err != nil {
			t.Fatalf("Failed to register device: %v", err)
		}
	}
	defer manager.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-test",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}
	continued, err := manager.LogRequest(context.Background(), entry)
	if err != nil {
		t.Errorf("LogRequest failed: %v", err)
	}
	if !continued {
		t.Error("Expected continue=true but got false")
	}

	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(content), "\n") != 1 || !strings.Contains(string(content), "req-test") {
			t.Errorf("%s: want the entry, once: %q", filepath.Base(path), content)
		}
	}
}

func TestManagerSingleDeviceOptimization(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	sink, err := NewFileSink(FileSinkConfig{
		Path: logPath,
	})
	if err != nil {
		t.Fatalf("Failed to create sink: %v", err)
	}

	format := NewJSONFormat()
	device := NewDevice("single", format, sink, &DeviceConfig{
		Name:    "single",
		Enabled: true,
	})

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	if err := manager.RegisterDevice("single", device); err != nil {
		t.Fatalf("Failed to register device: %v", err)
	}
	defer manager.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-single",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}

	ctx := context.Background()

	// Should use optimized single-device path
	continued, err := manager.LogRequest(ctx, entry)
	if err != nil {
		t.Errorf("LogRequest failed: %v", err)
	}
	if !continued {
		t.Error("Expected continue=true but got false")
	}

	// Verify log was written
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Errorf("Failed to read log: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty")
	}
}

func TestManagerEmptyDevices(t *testing.T) {
	// Fail-open at zero devices: the broker should return (true, nil)
	// so the request handler doesn't block traffic on a cluster with no
	// configured audit. Operators can then bootstrap their first audit
	// device via sys/audit/{path} on a freshly-installed cluster.
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	defer manager.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-empty",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}

	ctx := context.Background()

	continued, err := manager.LogRequest(ctx, entry)
	if err != nil {
		t.Errorf("LogRequest with no devices should not error: %v", err)
	}
	if !continued {
		t.Error("Expected continue=true with no devices (fail-open) but got false")
	}

	continued, err = manager.LogResponse(ctx, entry)
	if err != nil {
		t.Errorf("LogResponse with no devices should not error: %v", err)
	}
	if !continued {
		t.Error("Expected continue=true with no devices (fail-open) but got false")
	}
}

func TestManagerDisabledDevices(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	sink, err := NewFileSink(FileSinkConfig{
		Path: logPath,
	})
	if err != nil {
		t.Fatalf("Failed to create sink: %v", err)
	}

	format := NewJSONFormat()
	device := NewDevice("disabled", format, sink, &DeviceConfig{
		Name:    "disabled",
		Enabled: false, // Disabled!
	})

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	if err := manager.RegisterDevice("disabled", device); err != nil {
		t.Fatalf("Failed to register device: %v", err)
	}
	defer manager.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-disabled",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}

	ctx := context.Background()

	// Should skip disabled devices
	continued, err := manager.LogRequest(ctx, entry)
	if err != nil {
		t.Errorf("LogRequest should not error with disabled devices: %v", err)
	}
	if continued {
		t.Error("Expected continue=false with disabled devices but got true")
	}

	// Verify no log was written
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Errorf("Failed to read log: %v", err)
	}

	if len(content) > 0 {
		t.Error("Disabled device should not write logs")
	}
}

// errSinkDown is what a faultySink refuses an entry with.
var errSinkDown = errors.New("sink is down")

// faultySink is a sink that refuses entries while down is set, and notes the
// ones it takes otherwise.
type faultySink struct {
	recordingSink
	down *atomic.Bool
}

func (s faultySink) Write(ctx context.Context, entry []byte) error {
	if s.down.Load() {
		return errSinkDown
	}
	return s.recordingSink.Write(ctx, entry)
}

// faultyDevice is an enabled device named name, which writes to log unless
// down is set.
func faultyDevice(name string, log *writeLog, down *atomic.Bool) Device {
	sink := faultySink{recordingSink: recordingSink{name: name, log: log}, down: down}
	return NewDevice(name, NewJSONFormat(), sink, &DeviceConfig{Name: name, Enabled: true})
}

// managerWithServerLog is a manager and what it writes to the server log.
func managerWithServerLog(t *testing.T) (AuditManager, *bytes.Buffer) {
	t.Helper()
	var serverLog bytes.Buffer
	config := logger.DefaultConfig()
	config.Outputs = nil
	log, _ := logger.NewGatedLogger(config, logger.GatedWriterConfig{Underlying: &serverLog, InitialState: logger.GateOpen})
	return NewAuditManager(log), &serverLog
}

// terminalColours matches the colour codes the server log is written with.
var terminalColours = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// An entry one device takes is audited, whatever the others do: the request
// goes on, with no error for its handler to refuse it on. That is what a
// second device is for. The device that fails is reported in the server log,
// once when it starts to and once when it recovers, not once per entry.
func TestManagerPartialFailure(t *testing.T) {
	mgr, serverLog := managerWithServerLog(t)
	writes := &writeLog{}
	var down atomic.Bool
	down.Store(true)
	if err := mgr.RegisterDevice("failing/", faultyDevice("failing/", writes, &down)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RegisterDevice("healthy/", recordingDevice("healthy/", writes)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	entry := &LogEntry{Timestamp: time.Now(), Request: &Request{ID: "req-1"}}
	logBoth := func() {
		t.Helper()
		if ok, err := mgr.LogRequest(ctx, entry); err != nil || !ok {
			t.Fatalf("LogRequest: ok=%v err=%v, want the entry audited and no error", ok, err)
		}
		if ok, err := mgr.LogResponse(ctx, entry); err != nil || !ok {
			t.Fatalf("LogResponse: ok=%v err=%v, want the entry audited and no error", ok, err)
		}
	}

	logBoth()
	// Another device coming changes nothing for the one that is failing.
	if err := mgr.RegisterDevice("late/", recordingDevice("late/", writes)); err != nil {
		t.Fatal(err)
	}
	logBoth()
	if got, want := writes.written(), []string{"healthy/", "healthy/", "healthy/", "late/", "healthy/", "late/"}; !slices.Equal(got, want) {
		t.Errorf("devices written: %q, want %q", got, want)
	}
	if got := strings.Count(serverLog.String(), "audit device is failing"); got != 1 {
		t.Errorf("the failing device was reported %d times over 4 entries, want once: %s", got, serverLog)
	}
	if !strings.Contains(serverLog.String(), "failing/") || !strings.Contains(serverLog.String(), errSinkDown.Error()) {
		t.Errorf("the report names neither the device nor its error: %s", serverLog)
	}
	if strings.Contains(serverLog.String(), "audit device recovered") {
		t.Errorf("a recovery was reported while the device fails: %s", serverLog)
	}

	down.Store(false)
	logBoth()
	if got := strings.Count(serverLog.String(), "audit device recovered"); got != 1 {
		t.Errorf("the recovery was reported %d times, want once: %s", got, serverLog)
	}
	if plain := terminalColours.ReplaceAllString(serverLog.String(), ""); !strings.Contains(plain, "writes_refused=4") {
		t.Errorf("the recovery does not say 4 entries were refused: %s", plain)
	}

	// A device that fails again is reported again.
	down.Store(true)
	logBoth()
	if got := strings.Count(serverLog.String(), "audit device is failing"); got != 2 {
		t.Errorf("the device failing a second time was reported %d times in all, want 2: %s", got, serverLog)
	}
}

// With no enabled device taking the entry, it is not audited: the caller is
// told so, and why each device refused.
func TestManagerAllDevicesFail(t *testing.T) {
	mgr, _ := managerWithServerLog(t)
	writes := &writeLog{}
	var down atomic.Bool
	down.Store(true)
	ctx := context.Background()
	entry := &LogEntry{Timestamp: time.Now(), Request: &Request{ID: "req-1"}}

	if err := mgr.RegisterDevice("first/", faultyDevice("first/", writes, &down)); err != nil {
		t.Fatal(err)
	}
	ok, err := mgr.LogRequest(ctx, entry)
	if ok || !errors.Is(err, errSinkDown) || !strings.Contains(err.Error(), `"first/"`) {
		t.Errorf("one device, failing: ok=%v err=%v, want the device's failure", ok, err)
	}

	if err := mgr.RegisterDevice("second/", faultyDevice("second/", writes, &down)); err != nil {
		t.Fatal(err)
	}
	ok, err = mgr.LogResponse(ctx, entry)
	if ok || err == nil || !strings.Contains(err.Error(), `"first/"`) || !strings.Contains(err.Error(), `"second/"`) {
		t.Errorf("two devices, both failing: ok=%v err=%v, want both failures", ok, err)
	}

	// A healthy device that is disabled takes no entry, so it audits none.
	healthy := recordingDevice("third/", writes)
	healthy.SetEnabled(false)
	if err := mgr.RegisterDevice("third/", healthy); err != nil {
		t.Fatal(err)
	}
	if ok, err := mgr.LogRequest(ctx, entry); ok || err == nil {
		t.Errorf("failing devices and a disabled one: ok=%v err=%v, want the failures", ok, err)
	}
	if got := writes.written(); len(got) != 0 {
		t.Errorf("devices written: %q, want none", got)
	}

	healthy.SetEnabled(true)
	if ok, err := mgr.LogRequest(ctx, entry); err != nil || !ok {
		t.Errorf("once a device takes the entry: ok=%v err=%v", ok, err)
	}
}

func TestManagerConcurrentLogging(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	sink, err := NewFileSink(FileSinkConfig{
		Path: logPath,
	})
	if err != nil {
		t.Fatalf("Failed to create sink: %v", err)
	}

	format := NewJSONFormat()
	device := NewDevice("concurrent", format, sink, &DeviceConfig{
		Name:    "concurrent",
		Enabled: true,
	})

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	if err := manager.RegisterDevice("concurrent", device); err != nil {
		t.Fatalf("Failed to register device: %v", err)
	}
	defer manager.Close()

	ctx := context.Background()

	// Concurrent logging from multiple goroutines
	var wg sync.WaitGroup
	numGoroutines := 10
	entriesPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < entriesPerGoroutine; j++ {
				entry := &LogEntry{
					Timestamp: time.Now(),
					Request: &Request{
						ID:        fmt.Sprintf("req-%d-%d", id, j),
						Operation: "read",
						Path:      "/test",
						ClientIP:  "192.168.1.100",
					},
				}

				continued, err := manager.LogRequest(ctx, entry)
				if err != nil {
					t.Errorf("Concurrent LogRequest failed: %v", err)
				}
				if !continued {
					t.Error("Expected continue=true in concurrent logging")
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify logs were written
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Errorf("Failed to read log: %v", err)
	}

	if len(content) == 0 {
		t.Error("No logs written during concurrent test")
	}
}

func BenchmarkManagerSingleDevice(b *testing.B) {
	tmpDir := b.TempDir()
	logPath := filepath.Join(tmpDir, "bench.log")

	sink, _ := NewFileSink(FileSinkConfig{
		Path: logPath,
	})
	format := NewJSONFormat()
	device := NewDevice("bench", format, sink, &DeviceConfig{
		Name:    "bench",
		Enabled: true,
	})

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	manager.RegisterDevice("bench", device)
	defer manager.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-bench",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		manager.LogRequest(ctx, entry)
	}
}

// BenchmarkManagerMultiDeviceSequential logs one entry to five devices. The
// devices are written in turn, the only way the manager has; the name is kept
// so that results compare with those taken when it could also fan out.
func BenchmarkManagerMultiDeviceSequential(b *testing.B) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	defer manager.Close()

	numDevices := 5
	for i := 0; i < numDevices; i++ {
		tmpDir := b.TempDir()
		logPath := filepath.Join(tmpDir, fmt.Sprintf("bench-%d.log", i))

		sink, _ := NewFileSink(FileSinkConfig{
			Path: logPath,
		})
		format := NewJSONFormat()
		device := NewDevice(fmt.Sprintf("bench-%d", i), format, sink, &DeviceConfig{
			Name:    fmt.Sprintf("bench-%d", i),
			Enabled: true,
		})
		manager.RegisterDevice(fmt.Sprintf("bench-%d", i), device)
	}

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-bench",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		manager.LogRequest(ctx, entry)
	}
}

func TestManagerListDevices(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	defer mgr.Close()

	if devs := mgr.ListDevices(); len(devs) != 0 {
		t.Errorf("expected 0 devices, got %d", len(devs))
	}

	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "a.log")})
	dev := NewDevice("dev1", NewJSONFormat(), sink, &DeviceConfig{Name: "dev1", Enabled: true})
	mgr.RegisterDevice("dev1", dev)

	if devs := mgr.ListDevices(); len(devs) != 1 {
		t.Errorf("expected 1 device, got %d", len(devs))
	}
}

func TestManagerUnregisterDevice(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)

	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "a.log")})
	dev := NewDevice("dev1", NewJSONFormat(), sink, &DeviceConfig{Name: "dev1", Enabled: true})
	mgr.RegisterDevice("dev1", dev)

	if err := mgr.UnregisterDevice("dev1"); err != nil {
		t.Errorf("UnregisterDevice failed: %v", err)
	}

	if devs := mgr.ListDevices(); len(devs) != 0 {
		t.Errorf("expected 0 devices after unregister, got %d", len(devs))
	}

	// Unregister non-existent device
	if err := mgr.UnregisterDevice("nonexistent"); err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestManagerGetDevice(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	defer mgr.Close()

	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "a.log")})
	dev := NewDevice("dev1", NewJSONFormat(), sink, &DeviceConfig{Name: "dev1", Enabled: true})
	mgr.RegisterDevice("dev1", dev)

	got, err := mgr.GetDevice("dev1")
	if err != nil {
		t.Errorf("GetDevice failed: %v", err)
	}
	if got.Name() != "dev1" {
		t.Errorf("expected dev1, got %s", got.Name())
	}

	_, err = mgr.GetDevice("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestManagerReset(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)

	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "a.log")})
	dev := NewDevice("dev1", NewJSONFormat(), sink, &DeviceConfig{Name: "dev1", Enabled: true})
	mgr.RegisterDevice("dev1", dev)

	if err := mgr.Reset(context.Background()); err != nil {
		t.Errorf("Reset failed: %v", err)
	}

	if devs := mgr.ListDevices(); len(devs) != 0 {
		t.Errorf("expected 0 devices after reset, got %d", len(devs))
	}
}

// A reset closes its devices: an entry a device accepted and still buffers is
// in the file once the reset returns, and the device takes no entry after it.
// Before, a seal dropped the devices open, so the entries were lost when the
// process exited, and each device kept its file and its flush goroutine.
func TestManagerReset_ClosesDevices(t *testing.T) {
	ctx := context.Background()
	logPath := filepath.Join(t.TempDir(), "audit.log")
	device, err := (&FileDeviceFactory{}).Create(ctx, "file/", "", "", map[string]any{
		"file_path":    logPath,
		"hmac_key":     "k",
		"flush_period": int64(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	if err := mgr.RegisterDevice("file/", device); err != nil {
		t.Fatal(err)
	}

	entry := gatewayRequestEntry()
	if ok, err := mgr.LogRequest(ctx, entry); err != nil || !ok {
		t.Fatalf("LogRequest: ok=%v err=%v", ok, err)
	}
	if content, _ := os.ReadFile(logPath); len(content) != 0 {
		t.Fatalf("the entry was written before the reset, so this test shows nothing: %s", content)
	}

	if err := mgr.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), entry.Request.ID) {
		t.Errorf("the buffered entry is not in the file after the reset: %q", content)
	}
	if err := device.LogRequest(ctx, entry); err == nil {
		t.Error("the device still accepts entries after the reset")
	}
}

// A request still on its way through a seal is refused, not served unaudited.
// The devices stay listed until they are closed, and a closed device takes no
// entry. Emptied first, the list would be that of a server with no device
// yet, which serves every request: for as long as the devices took to close,
// a seal was a window with no audit. A device that refuses because it was
// closed is not reported as failing.
func TestManagerReset_RefusesRequestsWhileItCloses(t *testing.T) {
	mgr, serverLog := managerWithServerLog(t)
	sink, file := newGatedBufferedSink(t, 1)
	device := NewDevice("file/", NewJSONFormat(), sink, &DeviceConfig{Name: "file/", Enabled: true})
	if err := mgr.RegisterDevice("file/", device); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	entry := &LogEntry{Timestamp: time.Now(), Request: &Request{ID: "req-1"}}

	// The file holds a write, so the device cannot finish closing.
	held := make(chan error, 1)
	go func() {
		_, err := mgr.LogRequest(ctx, entry)
		held <- err
	}()
	file.attempt(t, "the entry's flush")

	reset := make(chan error, 1)
	go func() { reset <- mgr.Reset(ctx) }()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		sink.mu.Lock()
		closing := sink.closed
		sink.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the reset did not start closing the device")
		}
	}

	ok, err := mgr.LogRequest(ctx, entry)
	if ok || !errors.Is(err, errSinkClosed) {
		t.Errorf("a request during the reset: ok=%v err=%v, want it refused by the closed device", ok, err)
	}
	if strings.Contains(serverLog.String(), "audit device is failing") {
		t.Errorf("a device being closed was reported as failing: %s", serverLog)
	}

	// The device gives up on the held write, and the reset says so.
	if err := within(t, reset, "the reset, behind a write that does not return"); err == nil {
		t.Error("the reset reported nothing of the entry its device could not write")
	}
	file.gates <- gate{}
	if err := within(t, held, "the held write"); err != nil {
		t.Errorf("the held write, once the file answered: %v", err)
	}

	// Sealed: the list is empty, as before any device was registered.
	if ok, err := mgr.LogRequest(ctx, entry); err != nil || !ok {
		t.Errorf("after the reset: ok=%v err=%v", ok, err)
	}
}

// failingCloseSink is a sink that cannot be closed.
type failingCloseSink struct{ discardSink }

func (failingCloseSink) Close() error { return errors.New("close failed") }

// A device that fails to close is reported and unregistered all the same: the
// next unseal registers a device under the same name, and would be refused
// while this one stayed.
func TestManagerReset_DropsADeviceThatFailsToClose(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	for name, sink := range map[string]Sink{"good/": discardSink{}, "bad/": failingCloseSink{}} {
		device := NewDevice(name, NewJSONFormat(), sink, &DeviceConfig{Name: name, Enabled: true})
		if err := mgr.RegisterDevice(name, device); err != nil {
			t.Fatal(err)
		}
	}

	err := mgr.Reset(context.Background())
	if err == nil || !strings.Contains(err.Error(), `"bad/"`) || strings.Contains(err.Error(), `"good/"`) {
		t.Errorf("Reset: got %v, want the failure of bad/ alone", err)
	}
	if devices := mgr.ListDevices(); len(devices) != 0 {
		t.Errorf("devices left after the reset: %q", devices)
	}
	if err := mgr.RegisterDevice("bad/", NewDevice("bad/", NewJSONFormat(), discardSink{}, nil)); err != nil {
		t.Errorf("the name of the device that failed to close cannot be registered again: %v", err)
	}
}

func TestManagerDuplicateRegister(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	defer mgr.Close()

	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "a.log")})
	dev := NewDevice("dev1", NewJSONFormat(), sink, &DeviceConfig{Name: "dev1", Enabled: true})
	mgr.RegisterDevice("dev1", dev)

	sink2, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "b.log")})
	dev2 := NewDevice("dev1", NewJSONFormat(), sink2, &DeviceConfig{Name: "dev1", Enabled: true})
	if err := mgr.RegisterDevice("dev1", dev2); err == nil {
		t.Error("expected error registering duplicate device")
	}
}

func TestManagerLogResponse(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)

	tmpDir := t.TempDir()
	sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "a.log")})
	dev := NewDevice("dev1", NewJSONFormat(), sink, &DeviceConfig{Name: "dev1", Enabled: true})
	mgr.RegisterDevice("dev1", dev)
	defer mgr.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request:   &Request{ID: "req-1", Path: "/test"},
		Response:  &Response{StatusCode: 200},
	}

	continued, err := mgr.LogResponse(context.Background(), entry)
	if err != nil {
		t.Errorf("LogResponse failed: %v", err)
	}
	if !continued {
		t.Error("expected continue=true")
	}
}

func TestManagerFormatErrors(t *testing.T) {
	m := &manager{}

	if err := m.formatErrors(nil); err != nil {
		t.Errorf("expected nil for no errors, got %v", err)
	}

	if err := m.formatErrors([]error{fmt.Errorf("one error")}); err == nil {
		t.Error("expected error for single error")
	}

	err := m.formatErrors([]error{fmt.Errorf("err1"), fmt.Errorf("err2")})
	if err == nil {
		t.Error("expected aggregated error")
	}
}

func TestManagerMultiDeviceLogResponse(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)

	tmpDir := t.TempDir()
	for i := 0; i < 3; i++ {
		sink, _ := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, fmt.Sprintf("a%d.log", i))})
		dev := NewDevice(fmt.Sprintf("dev%d", i), NewJSONFormat(), sink, &DeviceConfig{Name: fmt.Sprintf("dev%d", i), Enabled: true})
		mgr.RegisterDevice(fmt.Sprintf("dev%d", i), dev)
	}
	defer mgr.Close()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request:   &Request{ID: "req-1", Path: "/test"},
		Response:  &Response{StatusCode: 200},
	}

	continued, err := mgr.LogResponse(context.Background(), entry)
	if err != nil {
		t.Errorf("LogResponse failed: %v", err)
	}
	if !continued {
		t.Error("expected continue=true")
	}
}

// gatewayAuth is the auth part of both entries of an MCP gateway request: an
// agent whose role a static group granted, calling a tool a contract allows
// for a user.
func gatewayAuth() *Auth {
	return &Auth{
		TokenID:       "hmac-sha256:5f2c9a1b7d3e4f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e",
		TokenAccessor: "acc_9f8e7d6c5b4a39281706f5e4d3c2b1a0",
		TokenType:     logical.TokenTypeIdentity,
		PrincipalID:   "spiffe://prod.example.com/ns/agents/sa/research-agent",
		RoleName:      "research",
		MountAccessor: "auth_jwt_3c1f9a2b",
		AliasName:     "system:serviceaccount:agents:research-agent",
		EntityKind:    "agent",
		RoleGrantedBy: "group:research-agents",
		RoleGroupType: string(logical.GroupTypeStatic),
		Groups:        []string{"platform-agents", "research-agents"},
		EntityID:      "ent_4b7a1c9e2d3f",
		EntityName:    "research-agent",
		GovernedBy:    "group:platform-team",
		Policies:      []string{"default", "research-tools"},
		PolicyResults: &PolicyResults{
			Allowed:          true,
			GrantingPolicies: []string{"research-tools"},
			MCPDecision: &logical.MCPDecision{
				Method:      "tools/call",
				Name:        "search_issues",
				Decision:    "allow",
				PolicyName:  "github-contract",
				MatchedRule: "search_*",
				RuleType:    "allowed_tools",
			},
			MCPClient: &MCPClientInfo{Name: "claude-code", Version: "2.1.0"},
		},
		TokenTTL:    3412,
		ExpiresAt:   1794829815,
		NamespaceID: "root",
		CreatedByIP: "10.42.7.19",
		User: &UserAttribution{
			Subject:     "alice@example.com",
			TokenID:     "hmac-sha256:0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
			NamespaceID: "root",
		},
	}
}

// gatewayRequest is the request part of both entries.
func gatewayRequest() *Request {
	return &Request{
		ID:          "7c9e6679-7425-40de-944b-e07fc1f90ae7",
		Operation:   "stream",
		Path:        "github/role/research/gateway/mcp",
		MountPoint:  "github/",
		MountType:   "mcp_github",
		MountClass:  "provider",
		Method:      "POST",
		ClientIP:    "10.42.7.19",
		NamespaceID: "root",
		Streamed:    true,
		Transparent: true,
	}
}

// gatewayRequestEntry is the entry logged before an MCP gateway request is
// routed.
func gatewayRequestEntry() *LogEntry {
	return &LogEntry{
		Type:      string(EntryTypeRequest),
		Timestamp: time.Date(2026, 11, 16, 10, 30, 15, 123456789, time.UTC),
		Request:   gatewayRequest(),
		Auth:      gatewayAuth(),
	}
}

// gatewayResponseEntry is the entry logged once the upstream answered: the
// same request and auth, the response, and the credential minted for the call.
func gatewayResponseEntry() *LogEntry {
	return &LogEntry{
		Type:      string(EntryTypeResponse),
		Timestamp: time.Date(2026, 11, 16, 10, 30, 15, 187654321, time.UTC),
		Request:   gatewayRequest(),
		Auth:      gatewayAuth(),
		Response: &Response{
			StatusCode: 200,
			MountClass: "provider",
			Streamed:   true,
			Credential: &Credential{
				CredentialID: "2f1e4d3c-5b6a-4978-8695-a4b3c2d1e0f9",
				Type:         "github_token",
				Category:     "oauth",
				LeaseTTL:     3600,
				TokenID:      "hmac-sha256:5f2c9a1b7d3e4f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e",
				SourceName:   "github-app",
				SourceType:   "github",
				SpecName:     "research-readonly",
				Data:         map[string]string{"token": "ghs_16C7e42F292c6912E7710c838347Ae178B4a"},
				Metadata:     map[string]string{"subject": "alice@example.com"},
			},
			UpstreamURL: "https://api.githubcopilot.com/mcp/",
		},
	}
}

// writeLog is the order in which the sinks sharing it were written to.
type writeLog struct {
	mu    sync.Mutex
	names []string
}

func (l *writeLog) written() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.names)
}

// recordingSink notes each write it receives in a log it shares.
type recordingSink struct {
	discardSink
	name string
	log  *writeLog
}

func (s recordingSink) Write(context.Context, []byte) error {
	s.log.mu.Lock()
	defer s.log.mu.Unlock()
	s.log.names = append(s.log.names, s.name)
	return nil
}

// recordingDevice is an enabled device named name that writes to log.
func recordingDevice(name string, log *writeLog) Device {
	return NewDevice(name, NewJSONFormat(), recordingSink{name: name, log: log}, &DeviceConfig{Name: name, Enabled: true})
}

// Devices are written in the order of their names, whatever the order they
// were registered in: the same on every node and after every restart.
func TestManagerLogsInNameOrder(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	writes := &writeLog{}
	for _, name := range []string{"siem/", "archive/", "file/"} {
		if err := mgr.RegisterDevice(name, recordingDevice(name, writes)); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	entry := &LogEntry{Timestamp: time.Now(), Request: &Request{ID: "req-1"}}
	if ok, err := mgr.LogRequest(ctx, entry); err != nil || !ok {
		t.Fatalf("LogRequest: ok=%v err=%v", ok, err)
	}
	if got, want := writes.written(), []string{"archive/", "file/", "siem/"}; !slices.Equal(got, want) {
		t.Errorf("devices written in the order %q, want %q", got, want)
	}

	// A device unregistered is written no more, and the rest keep their order.
	if err := mgr.UnregisterDevice("file/"); err != nil {
		t.Fatal(err)
	}
	if ok, err := mgr.LogResponse(ctx, entry); err != nil || !ok {
		t.Fatalf("LogResponse: ok=%v err=%v", ok, err)
	}
	if got, want := writes.written()[3:], []string{"archive/", "siem/"}; !slices.Equal(got, want) {
		t.Errorf("after the unregister, devices written in the order %q, want %q", got, want)
	}
}

// slowCloseSink is a sink whose Close waits to be released.
type slowCloseSink struct {
	recordingSink
	closing chan struct{}
	release chan struct{}
}

func (s slowCloseSink) Close() error {
	close(s.closing)
	<-s.release
	return nil
}

// A device being unregistered is out of the way before it is closed. Closing
// one flushes it, which can take as long as its file does; requests neither
// wait for that nor write to the device meanwhile, which would refuse them.
func TestManagerUnregister_DoesNotStallLogging(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	writes := &writeLog{}
	slow := slowCloseSink{
		recordingSink: recordingSink{name: "leaving/", log: writes},
		closing:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	if err := mgr.RegisterDevice("leaving/", NewDevice("leaving/", NewJSONFormat(), slow, &DeviceConfig{Name: "leaving/", Enabled: true})); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RegisterDevice("staying/", recordingDevice("staying/", writes)); err != nil {
		t.Fatal(err)
	}

	unregistered := make(chan error, 1)
	go func() { unregistered <- mgr.UnregisterDevice("leaving/") }()
	<-slow.closing

	logged := make(chan error, 1)
	go func() {
		ok, err := mgr.LogRequest(context.Background(), &LogEntry{Timestamp: time.Now(), Request: &Request{ID: "req-1"}})
		if err == nil && !ok {
			err = errors.New("no device took the entry")
		}
		logged <- err
	}()
	select {
	case err := <-logged:
		if err != nil {
			t.Errorf("LogRequest while a device closes: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("LogRequest waits for the device being closed")
	}
	if got, want := writes.written(), []string{"staying/"}; !slices.Equal(got, want) {
		t.Errorf("written while a device closes: %q, want %q", got, want)
	}

	close(slow.release)
	if err := <-unregistered; err != nil {
		t.Errorf("UnregisterDevice: %v", err)
	}
}

// A device that fails to close is unregistered all the same, and the failure
// returned: left registered, a closed device refuses every request.
func TestManagerUnregister_DropsADeviceThatFailsToClose(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	device := NewDevice("bad/", NewJSONFormat(), failingCloseSink{}, &DeviceConfig{Name: "bad/", Enabled: true})
	if err := mgr.RegisterDevice("bad/", device); err != nil {
		t.Fatal(err)
	}

	if err := mgr.UnregisterDevice("bad/"); err == nil {
		t.Error("the close failure was not returned")
	}
	if devices := mgr.ListDevices(); len(devices) != 0 {
		t.Errorf("devices left: %q", devices)
	}
	if ok, err := mgr.LogRequest(context.Background(), &LogEntry{Timestamp: time.Now(), Request: &Request{ID: "req-1"}}); err != nil || !ok {
		t.Errorf("LogRequest with no device left: ok=%v err=%v", ok, err)
	}
}

// Choosing the devices to log to allocates nothing: what a request allocates
// to be audited is what its devices allocate.
func TestManagerDispatchAllocatesNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	ctx := context.Background()
	entry := gatewayRequestEntry()

	device := NewDevice("a/", NewJSONFormat(), discardSink{}, &DeviceConfig{Name: "a/", Enabled: true})
	perDevice := testing.AllocsPerRun(200, func() { device.LogRequest(ctx, entry) })

	for devices := 1; devices <= 3; devices++ {
		name := fmt.Sprintf("device-%d/", devices)
		if err := mgr.RegisterDevice(name, NewDevice(name, NewJSONFormat(), discardSink{}, &DeviceConfig{Name: name, Enabled: true})); err != nil {
			t.Fatal(err)
		}
		got := testing.AllocsPerRun(200, func() { mgr.LogRequest(ctx, entry) })
		if want := perDevice * float64(devices); got != want {
			t.Errorf("%d device(s): %v allocations per entry, want the devices' own %v", devices, got, want)
		}
	}
}

// Devices are registered, unregistered, enabled and disabled while requests
// are logged: every request still reaches the device that stays.
func TestManagerConcurrentChanges(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManager(log)
	staying := &countingSink{}
	if err := mgr.RegisterDevice("staying/", NewDevice("staying/", NewJSONFormat(), staying, &DeviceConfig{Name: "staying/", Enabled: true})); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	entry := &LogEntry{Timestamp: time.Now(), Request: &Request{ID: "req-1"}}

	stop := make(chan struct{})
	var changers, loggers sync.WaitGroup
	for c := 0; c < 2; c++ {
		changers.Add(1)
		go func() {
			defer changers.Done()
			name := fmt.Sprintf("coming-and-going-%d/", c)
			for {
				select {
				case <-stop:
					return
				default:
				}
				device := NewDevice(name, NewJSONFormat(), discardSink{}, &DeviceConfig{Name: name, Enabled: true})
				if err := mgr.RegisterDevice(name, device); err != nil {
					t.Errorf("RegisterDevice: %v", err)
					return
				}
				device.SetEnabled(false)
				device.SetEnabled(true)
				mgr.ListDevices()
				if err := mgr.UnregisterDevice(name); err != nil {
					t.Errorf("UnregisterDevice: %v", err)
					return
				}
			}
		}()
	}
	for l := 0; l < 4; l++ {
		loggers.Add(1)
		go func() {
			defer loggers.Done()
			for n := 0; n < 2000; n++ {
				if ok, err := mgr.LogRequest(ctx, entry); err != nil || !ok {
					t.Errorf("LogRequest: ok=%v err=%v", ok, err)
					return
				}
				if ok, err := mgr.LogResponse(ctx, entry); err != nil || !ok {
					t.Errorf("LogResponse: ok=%v err=%v", ok, err)
					return
				}
			}
		}()
	}
	loggers.Wait()
	close(stop)
	changers.Wait()

	// A manager with no device also says an entry is audited: only the
	// device's own count shows it was handed every one.
	if got, want := staying.entries.Load(), int64(4*2000*2); got != want {
		t.Errorf("the device that stays was handed %d entries, want %d", got, want)
	}
}

// countingSink is a sink that counts the entries it is handed.
type countingSink struct {
	discardSink
	entries atomic.Int64
}

func (s *countingSink) Write(context.Context, []byte) error {
	s.entries.Add(1)
	return nil
}

// discardSink accepts every entry and writes nothing.
type discardSink struct{}

func (discardSink) Write(context.Context, []byte) error { return nil }
func (discardSink) Close() error                        { return nil }
func (discardSink) Name() string                        { return "discard" }
func (discardSink) Type() string                        { return "discard" }

// benchFileDeviceConfig is a file device as an operator enables one, writing
// under dir. One backup bounds the disk a long run fills.
func benchFileDeviceConfig(dir string) map[string]any {
	return map[string]any{
		"file_path":   filepath.Join(dir, "audit.log"),
		"hmac_key":    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"max_backups": 1,
	}
}

// BenchmarkPipelineGatewayRequest measures what auditing one MCP gateway
// request costs: its request entry and its response entry.
//
//   - pipeline: the manager and one file device built by the factory, as the
//     server builds it (buffered file sink, HMAC key, default salt fields).
//   - no-sink: the same with a sink that writes nothing, so what is left is
//     the dispatch and the format.
//   - format: the format alone.
//   - sink: the buffered file sink alone, given entries already formatted.
//
// Each has a parallel twin: run it with -cpu 1,4,8 to see how the stage
// scales with its callers.
func BenchmarkPipelineGatewayRequest(b *testing.B) {
	ctx := context.Background()
	req, resp := gatewayRequestEntry(), gatewayResponseEntry()

	// run measures once, called in turn and then from every benchmark
	// goroutine.
	run := func(b *testing.B, name string, setup func(b *testing.B) (once func() error)) {
		b.Run(name, func(b *testing.B) {
			once := setup(b)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := once(); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(name+"-parallel", func(b *testing.B) {
			once := setup(b)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := once(); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}

	// managerWith registers device with a new manager and logs both entries.
	managerWith := func(b *testing.B, device Device) func() error {
		log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
		mgr := NewAuditManager(log)
		if err := mgr.RegisterDevice("bench/", device); err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { mgr.Close() })
		return func() error {
			if ok, err := mgr.LogRequest(ctx, req); err != nil || !ok {
				return fmt.Errorf("LogRequest: ok=%v err=%v", ok, err)
			}
			if ok, err := mgr.LogResponse(ctx, resp); err != nil || !ok {
				return fmt.Errorf("LogResponse: ok=%v err=%v", ok, err)
			}
			return nil
		}
	}

	// fileDeviceConfig is the parsed configuration of the benchmark's device.
	fileDeviceConfig := func(b *testing.B) *FileDeviceConfig {
		conf, err := mapToFileDeviceConfig(benchFileDeviceConfig(b.TempDir()))
		if err != nil {
			b.Fatal(err)
		}
		return conf
	}

	// factoryFormat is the format the factory gives that device.
	factoryFormat := func(b *testing.B) *JSONFormat {
		format, warnings := jsonFormatFor(fileDeviceConfig(b))
		if len(warnings) != 0 {
			b.Fatalf("unexpected warnings: %q", warnings)
		}
		return format
	}

	run(b, "pipeline", func(b *testing.B) func() error {
		device, err := (&FileDeviceFactory{}).Create(ctx, "bench/", "", "", benchFileDeviceConfig(b.TempDir()))
		if err != nil {
			b.Fatal(err)
		}
		return managerWith(b, device)
	})

	run(b, "no-sink", func(b *testing.B) func() error {
		return managerWith(b, NewDevice("bench/", factoryFormat(b), discardSink{}, &DeviceConfig{Name: "bench/", Enabled: true}))
	})

	run(b, "format", func(b *testing.B) func() error {
		format := factoryFormat(b)
		return func() error {
			if _, err := format.FormatRequest(ctx, req); err != nil {
				return err
			}
			_, err := format.FormatResponse(ctx, resp)
			return err
		}
	})

	run(b, "sink", func(b *testing.B) func() error {
		format := factoryFormat(b)
		reqLine, err := format.FormatRequest(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		respLine, err := format.FormatResponse(ctx, resp)
		if err != nil {
			b.Fatal(err)
		}
		conf := fileDeviceConfig(b)
		fileSink, err := NewFileSink(FileSinkConfig{
			Path:        conf.Path,
			RotateSize:  conf.RotateSize,
			RotateDaily: conf.RotateDaily,
			MaxBackups:  conf.MaxBackups,
		})
		if err != nil {
			b.Fatal(err)
		}
		sink, err := NewBufferedSink(BufferedSinkConfig{Sink: fileSink, BufferSize: conf.BufferSize, FlushPeriod: conf.FlushPeriod})
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { sink.Close() })
		return func() error {
			if err := sink.Write(ctx, reqLine); err != nil {
				return err
			}
			return sink.Write(ctx, respLine)
		}
	})
}
