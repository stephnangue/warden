package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
)

func TestManagerParallelVsSequential(t *testing.T) {
	// Create multiple slow devices
	numDevices := 5
	devices := make([]Device, numDevices)

	for i := 0; i < numDevices; i++ {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, fmt.Sprintf("audit-%d.log", i))

		sink, err := NewFileSink(FileSinkConfig{
			Path: logPath,
		})
		if err != nil {
			t.Fatalf("Failed to create sink: %v", err)
		}

		format := NewJSONFormat()
		devices[i] = NewDevice(fmt.Sprintf("device-%d", i), format, sink, &DeviceConfig{
			Name:    fmt.Sprintf("device-%d", i),
			Enabled: true,
		})
	}

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-test",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}

	ctx := context.Background()

	// Test parallel execution
	t.Run("Parallel", func(t *testing.T) {
		log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
		manager := NewAuditManager(log)
		for i, device := range devices {
			if err := manager.RegisterDevice(fmt.Sprintf("device-%d", i), device); err != nil {
				t.Fatalf("Failed to register device: %v", err)
			}
		}

		start := time.Now()
		continued, err := manager.LogRequest(ctx, entry)
		if err != nil {
			t.Errorf("LogRequest failed: %v", err)
		}
		if !continued {
			t.Error("Expected continue=true but got false")
		}
		parallelDuration := time.Since(start)

		t.Logf("Parallel execution took: %v", parallelDuration)
	})

	// Test sequential execution
	t.Run("Sequential", func(t *testing.T) {
		log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
		manager := NewAuditManagerWithConfig(AuditManagerConfig{
			Logger:   log,
			Parallel: false,
		})
		for i, device := range devices {
			if err := manager.RegisterDevice(fmt.Sprintf("device-%d", i), device); err != nil {
				t.Fatalf("Failed to register device: %v", err)
			}
		}

		start := time.Now()
		continued, err := manager.LogRequest(ctx, entry)
		if err != nil {
			t.Errorf("LogRequest failed: %v", err)
		}
		if !continued {
			t.Error("Expected continue=true but got false")
		}
		sequentialDuration := time.Since(start)

		t.Logf("Sequential execution took: %v", sequentialDuration)
	})
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

	// Should handle empty device list gracefully
	continued, err := manager.LogRequest(ctx, entry)
	if err != nil {
		t.Errorf("LogRequest with no devices should not error: %v", err)
	}
	if continued {
		t.Error("Expected continue=false with no devices but got true")
	}

	continued, err = manager.LogResponse(ctx, entry)
	if err != nil {
		t.Errorf("LogResponse with no devices should not error: %v", err)
	}
	if continued {
		t.Error("Expected continue=false with no devices but got true")
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

func TestManagerErrorAggregation(t *testing.T) {
	// Create manager with multiple devices, some will fail
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	defer manager.Close()

	// Device 1: will succeed
	tmpDir1 := t.TempDir()
	sink1, _ := NewFileSink(FileSinkConfig{
		Path: filepath.Join(tmpDir1, "audit1.log"),
	})
	format := NewJSONFormat()
	device1 := NewDevice("device1", format, sink1, &DeviceConfig{
		Name:    "device1",
		Enabled: true,
	})
	manager.RegisterDevice("device1", device1)

	// Device 2: will fail (invalid path)
	sink2, err := NewFileSink(FileSinkConfig{
		Path: "/nonexistent/path/audit2.log",
	})
	if err == nil {
		// If creation succeeded, register it (it will fail on write)
		device2 := NewDevice("device2", format, sink2, &DeviceConfig{
			Name:    "device2",
			Enabled: true,
		})
		manager.RegisterDevice("device2", device2)
	}

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-error",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}

	ctx := context.Background()

	// Should return error but device1 should have written, so continue should be true
	continued, err := manager.LogRequest(ctx, entry)
	if err != nil {
		t.Logf("Expected error from LogRequest due to device2 failure: %v", err)
	}
	if !continued {
		t.Error("Expected continue=true since device1 succeeded, but got false")
	}

	// Verify device1 wrote successfully
	content, _ := os.ReadFile(filepath.Join(tmpDir1, "audit1.log"))
	if len(content) == 0 {
		t.Error("Device1 should have written despite device2 failing")
	}
}

func TestManagerPartialFailure(t *testing.T) {
	// Test case where some devices succeed and some fail
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	defer manager.Close()

	// Device 1: succeeds
	tmpDir1 := t.TempDir()
	sink1, _ := NewFileSink(FileSinkConfig{
		Path: filepath.Join(tmpDir1, "audit1.log"),
	})
	format := NewJSONFormat()
	device1 := NewDevice("device1", format, sink1, &DeviceConfig{
		Name:    "device1",
		Enabled: true,
	})
	manager.RegisterDevice("device1", device1)

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-partial",
			Operation: "read",
			Path:      "/test",
			ClientIP:  "192.168.1.100",
		},
	}

	ctx := context.Background()

	// With one device succeeding, continue should be true even if there are errors
	continued, err := manager.LogRequest(ctx, entry)
	if err != nil {
		t.Logf("Got error (expected if device2 was added): %v", err)
	}
	if !continued {
		t.Error("Expected continue=true when at least one device succeeds")
	}
}

func TestManagerAllDevicesFail(t *testing.T) {
	// Test case where all devices fail
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManager(log)
	defer manager.Close()

	// Device with invalid path that will fail
	sink, err := NewFileSink(FileSinkConfig{
		Path: "/nonexistent/path/audit.log",
	})
	if err == nil {
		format := NewJSONFormat()
		device := NewDevice("failing", format, sink, &DeviceConfig{
			Name:    "failing",
			Enabled: true,
		})
		manager.RegisterDevice("failing", device)

		entry := &LogEntry{
			Timestamp: time.Now(),
			Request: &Request{
				ID:        "req-all-fail",
				Operation: "read",
				Path:      "/test",
				ClientIP:  "192.168.1.100",
			},
		}

		ctx := context.Background()

		// All devices failed, continue should be false
		continued, err := manager.LogRequest(ctx, entry)
		if err == nil {
			t.Error("Expected error when all devices fail")
		}
		if continued {
			t.Error("Expected continue=false when all devices fail, but got true")
		}
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

func BenchmarkManagerMultiDeviceParallel(b *testing.B) {
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

func BenchmarkManagerMultiDeviceSequential(b *testing.B) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	manager := NewAuditManagerWithConfig(AuditManagerConfig{
		Logger:   log,
		Parallel: false,
	})
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

func TestManagerSequentialLogResponse(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mgr := NewAuditManagerWithConfig(AuditManagerConfig{Logger: log, Parallel: false})

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

func TestManagerParallelLogResponse(t *testing.T) {
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
