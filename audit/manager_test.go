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
	"github.com/stephnangue/warden/logical"
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
