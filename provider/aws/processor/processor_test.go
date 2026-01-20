package processor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
)

// mockProcessor is a test processor implementation
type mockProcessor struct {
	BaseProcessor
	canProcess bool
}

func newMockProcessor(name string, priority int, proxyDomains []string, canProcess bool) *mockProcessor {
	return &mockProcessor{
		BaseProcessor: BaseProcessor{
			ProcName:     name,
			ProcPriority: priority,
			ProxyDomains: proxyDomains,
		},
		canProcess: canProcess,
	}
}

func (m *mockProcessor) CanProcess(ctx *ProcessorContext) bool {
	return m.canProcess
}

func (m *mockProcessor) Process(ctx *ProcessorContext) (*ProcessorResult, error) {
	return &ProcessorResult{
		TargetURL:  "https://test.amazonaws.com",
		TargetHost: "test.amazonaws.com",
		Service:    ctx.Service,
	}, nil
}

func (m *mockProcessor) Metadata() *ProcessorMetadata {
	return nil
}

// mockProcessorWithMetadata is a test processor with metadata
type mockProcessorWithMetadata struct {
	BaseProcessor
	canProcess bool
	metadata   *ProcessorMetadata
}

func newMockProcessorWithMetadata(name string, priority int, proxyDomains []string, canProcess bool, metadata *ProcessorMetadata) *mockProcessorWithMetadata {
	return &mockProcessorWithMetadata{
		BaseProcessor: BaseProcessor{
			ProcName:     name,
			ProcPriority: priority,
			ProxyDomains: proxyDomains,
		},
		canProcess: canProcess,
		metadata:   metadata,
	}
}

func (m *mockProcessorWithMetadata) CanProcess(ctx *ProcessorContext) bool {
	return m.canProcess
}

func (m *mockProcessorWithMetadata) Process(ctx *ProcessorContext) (*ProcessorResult, error) {
	return &ProcessorResult{
		TargetURL:  "https://test.amazonaws.com",
		TargetHost: "test.amazonaws.com",
		Service:    ctx.Service,
	}, nil
}

func (m *mockProcessorWithMetadata) Metadata() *ProcessorMetadata {
	return m.metadata
}

func TestBaseProcessor_Name(t *testing.T) {
	bp := BaseProcessor{ProcName: "test-processor"}
	if got := bp.Name(); got != "test-processor" {
		t.Errorf("Name() = %v, want %v", got, "test-processor")
	}
}

func TestBaseProcessor_Priority(t *testing.T) {
	bp := BaseProcessor{ProcPriority: 100}
	if got := bp.Priority(); got != 100 {
		t.Errorf("Priority() = %v, want %v", got, 100)
	}
}

func TestBaseProcessor_IsProxyDomain(t *testing.T) {
	tests := []struct {
		name         string
		proxyDomains []string
		domain       string
		expected     bool
	}{
		{
			name:         "exact match",
			proxyDomains: []string{"example.com"},
			domain:       "example.com",
			expected:     true,
		},
		{
			name:         "subdomain match",
			proxyDomains: []string{"example.com"},
			domain:       "test.example.com",
			expected:     true,
		},
		{
			name:         "deep subdomain match",
			proxyDomains: []string{"example.com"},
			domain:       "deep.test.example.com",
			expected:     true,
		},
		{
			name:         "no match",
			proxyDomains: []string{"example.com"},
			domain:       "other.com",
			expected:     false,
		},
		{
			name:         "partial match not accepted",
			proxyDomains: []string{"example.com"},
			domain:       "notexample.com",
			expected:     false,
		},
		{
			name:         "multiple proxy domains - first match",
			proxyDomains: []string{"example.com", "test.com"},
			domain:       "example.com",
			expected:     true,
		},
		{
			name:         "multiple proxy domains - second match",
			proxyDomains: []string{"example.com", "test.com"},
			domain:       "test.com",
			expected:     true,
		},
		{
			name:         "empty proxy domains",
			proxyDomains: []string{},
			domain:       "example.com",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bp := BaseProcessor{ProxyDomains: tt.proxyDomains}
			if got := bp.IsProxyDomain(tt.domain); got != tt.expected {
				t.Errorf("IsProxyDomain(%s) = %v, want %v", tt.domain, got, tt.expected)
			}
		})
	}
}

func TestNewProcessorRegistry(t *testing.T) {
	registry := NewProcessorRegistry()

	if registry == nil {
		t.Fatal("NewProcessorRegistry() returned nil")
	}
	if registry.serviceMap == nil {
		t.Error("serviceMap is nil")
	}
	if registry.hostPatternMap == nil {
		t.Error("hostPatternMap is nil")
	}
	if registry.fallbackProcessors == nil {
		t.Error("fallbackProcessors is nil")
	}
	if registry.allProcessors == nil {
		t.Error("allProcessors is nil")
	}
	if registry.stats.ProcessorCallCount == nil {
		t.Error("ProcessorCallCount is nil")
	}
}

func TestProcessorRegistry_Register(t *testing.T) {
	t.Run("register processor without metadata", func(t *testing.T) {
		registry := NewProcessorRegistry()
		proc := newMockProcessor("test", 100, []string{"example.com"}, true)

		registry.Register(proc)

		if len(registry.allProcessors) != 1 {
			t.Errorf("Expected 1 processor, got %d", len(registry.allProcessors))
		}
		if len(registry.fallbackProcessors) != 1 {
			t.Errorf("Expected 1 fallback processor, got %d", len(registry.fallbackProcessors))
		}
	})

	t.Run("register processor with service metadata", func(t *testing.T) {
		registry := NewProcessorRegistry()
		proc := newMockProcessorWithMetadata("s3", 100, []string{"example.com"}, true, &ProcessorMetadata{
			ServiceNames: []string{"s3"},
			Priority:     100,
		})

		registry.Register(proc)

		if len(registry.serviceMap["s3"]) != 1 {
			t.Errorf("Expected s3 service to have 1 processor, got %d", len(registry.serviceMap["s3"]))
		}
	})

	t.Run("register processor with host pattern metadata", func(t *testing.T) {
		registry := NewProcessorRegistry()
		proc := newMockProcessorWithMetadata("s3-accesspoint", 180, []string{"example.com"}, true, &ProcessorMetadata{
			HostPatterns: []string{"*.s3-accesspoint.*"},
			Priority:     180,
		})

		registry.Register(proc)

		if len(registry.hostPatternMap["*.s3-accesspoint.*"]) != 1 {
			t.Errorf("Expected host pattern to have 1 processor, got %d", len(registry.hostPatternMap["*.s3-accesspoint.*"]))
		}
	})

	t.Run("register fallback-only processor", func(t *testing.T) {
		registry := NewProcessorRegistry()
		proc := newMockProcessorWithMetadata("generic", 10, []string{"example.com"}, true, &ProcessorMetadata{
			FallbackOnly: true,
			Priority:     10,
		})

		registry.Register(proc)

		if len(registry.fallbackProcessors) != 1 {
			t.Errorf("Expected 1 fallback processor, got %d", len(registry.fallbackProcessors))
		}
	})

	t.Run("processors are sorted by priority", func(t *testing.T) {
		registry := NewProcessorRegistry()
		lowPriority := newMockProcessor("low", 10, []string{}, true)
		highPriority := newMockProcessor("high", 100, []string{}, true)

		// Register in wrong order
		registry.Register(lowPriority)
		registry.Register(highPriority)

		// Should be sorted by priority (high first)
		if registry.allProcessors[0].Priority() != 100 {
			t.Errorf("Expected first processor to have priority 100, got %d", registry.allProcessors[0].Priority())
		}
	})
}

func createTestContext(service, region, host, path string) *ProcessorContext {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host

	return &ProcessorContext{
		LogicalRequest: &logical.Request{
			HTTPRequest: req,
			Path:        path,
		},
		Service: service,
		Region:  region,
	}
}

func TestProcessorRegistry_FindProcessor(t *testing.T) {
	t.Run("find by service", func(t *testing.T) {
		registry := NewProcessorRegistry()
		s3Proc := newMockProcessorWithMetadata("s3", 100, []string{}, true, &ProcessorMetadata{
			ServiceNames: []string{"s3"},
			Priority:     100,
		})
		registry.Register(s3Proc)

		ctx := createTestContext("s3", "us-east-1", "bucket.s3.example.com", "/key")
		found := registry.FindProcessor(ctx)

		if found == nil {
			t.Fatal("Expected to find processor")
		}
		if found.Name() != "s3" {
			t.Errorf("Expected s3 processor, got %s", found.Name())
		}
	})

	t.Run("find by host pattern", func(t *testing.T) {
		registry := NewProcessorRegistry()
		apProc := newMockProcessorWithMetadata("s3-accesspoint", 180, []string{}, true, &ProcessorMetadata{
			HostPatterns: []string{"*.s3-accesspoint.*"},
			Priority:     180,
		})
		registry.Register(apProc)

		ctx := createTestContext("s3", "us-east-1", "myap.s3-accesspoint.us-east-1.amazonaws.com", "/key")
		found := registry.FindProcessor(ctx)

		if found == nil {
			t.Fatal("Expected to find processor")
		}
		if found.Name() != "s3-accesspoint" {
			t.Errorf("Expected s3-accesspoint processor, got %s", found.Name())
		}
	})

	t.Run("find by fallback", func(t *testing.T) {
		registry := NewProcessorRegistry()
		genericProc := newMockProcessorWithMetadata("generic", 10, []string{}, true, &ProcessorMetadata{
			FallbackOnly: true,
			Priority:     10,
		})
		registry.Register(genericProc)

		ctx := createTestContext("ec2", "us-east-1", "ec2.us-east-1.amazonaws.com", "/")
		found := registry.FindProcessor(ctx)

		if found == nil {
			t.Fatal("Expected to find processor")
		}
		if found.Name() != "generic" {
			t.Errorf("Expected generic processor, got %s", found.Name())
		}
	})

	t.Run("no processor found", func(t *testing.T) {
		registry := NewProcessorRegistry()
		// Processor that always returns false for CanProcess
		proc := newMockProcessor("never-match", 100, []string{}, false)
		registry.Register(proc)

		ctx := createTestContext("ec2", "us-east-1", "ec2.us-east-1.amazonaws.com", "/")
		found := registry.FindProcessor(ctx)

		if found != nil {
			t.Errorf("Expected no processor, got %s", found.Name())
		}
	})

	t.Run("priority ordering - higher priority checked first", func(t *testing.T) {
		registry := NewProcessorRegistry()

		// Both can process, but high priority should win (registration order matters within same service)
		// Register high priority first to ensure it's found first
		highProc := newMockProcessorWithMetadata("high", 100, []string{}, true, &ProcessorMetadata{
			ServiceNames: []string{"s3"},
			Priority:     100,
		})
		lowProc := newMockProcessorWithMetadata("low", 10, []string{}, true, &ProcessorMetadata{
			ServiceNames: []string{"s3"},
			Priority:     10,
		})

		registry.Register(highProc)
		registry.Register(lowProc)

		ctx := createTestContext("s3", "us-east-1", "bucket.s3.example.com", "/key")
		found := registry.FindProcessor(ctx)

		if found == nil {
			t.Fatal("Expected to find processor")
		}
		// Note: The registry finds the first processor in the service map that can process
		// Since we registered high first, it should be found first
		if found.Name() != "high" {
			t.Errorf("Expected high priority processor, got %s", found.Name())
		}
	})
}

func TestProcessorRegistry_GetStats(t *testing.T) {
	registry := NewProcessorRegistry()
	proc := newMockProcessorWithMetadata("s3", 100, []string{}, true, &ProcessorMetadata{
		ServiceNames: []string{"s3"},
		Priority:     100,
	})
	registry.Register(proc)

	// Make some lookups
	ctx := createTestContext("s3", "us-east-1", "bucket.s3.example.com", "/key")
	registry.FindProcessor(ctx)
	registry.FindProcessor(ctx)

	stats := registry.GetStats()

	if stats["total_requests"].(int64) != 2 {
		t.Errorf("Expected 2 total requests, got %v", stats["total_requests"])
	}
	if stats["service_map_hits"].(int64) != 2 {
		t.Errorf("Expected 2 service map hits, got %v", stats["service_map_hits"])
	}

	processorUsage := stats["processor_usage"].(map[string]int64)
	if processorUsage["s3"] != 2 {
		t.Errorf("Expected 2 s3 processor uses, got %v", processorUsage["s3"])
	}
}

func TestProcessorRegistry_GetProcessors(t *testing.T) {
	registry := NewProcessorRegistry()
	proc1 := newMockProcessor("proc1", 100, []string{}, true)
	proc2 := newMockProcessor("proc2", 50, []string{}, true)

	registry.Register(proc1)
	registry.Register(proc2)

	processors := registry.GetProcessors()

	if len(processors) != 2 {
		t.Errorf("Expected 2 processors, got %d", len(processors))
	}
}

func TestMatchHostPattern(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		pattern  string
		expected bool
	}{
		{
			name:     "wildcard matches anything",
			host:     "any.host.com",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "exact match",
			host:     "test.amazonaws.com",
			pattern:  "test.amazonaws.com",
			expected: true,
		},
		{
			name:     "exact match - no match",
			host:     "test.amazonaws.com",
			pattern:  "other.amazonaws.com",
			expected: false,
		},
		{
			name:     "prefix wildcard",
			host:     "bucket.s3.amazonaws.com",
			pattern:  "*.s3.amazonaws.com",
			expected: true,
		},
		{
			name:     "suffix wildcard",
			host:     "s3.us-east-1.amazonaws.com",
			pattern:  "s3.*",
			expected: true,
		},
		{
			name:     "middle wildcard",
			host:     "bucket.s3-accesspoint.us-east-1.amazonaws.com",
			pattern:  "*.s3-accesspoint.*",
			expected: true,
		},
		{
			name:     "multiple wildcards",
			host:     "ap.s3-accesspoint.us-east-1.amazonaws.com",
			pattern:  "*.s3-accesspoint.*.amazonaws.com",
			expected: true,
		},
		{
			name:     "no match with wildcard",
			host:     "bucket.s3.amazonaws.com",
			pattern:  "*.s3-accesspoint.*",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchHostPattern(tt.host, tt.pattern)
			if got != tt.expected {
				t.Errorf("matchHostPattern(%s, %s) = %v, want %v", tt.host, tt.pattern, got, tt.expected)
			}
		})
	}
}

func TestPercentage(t *testing.T) {
	tests := []struct {
		name     string
		part     int64
		total    int64
		expected float64
	}{
		{
			name:     "zero total",
			part:     5,
			total:    0,
			expected: 0,
		},
		{
			name:     "50 percent",
			part:     50,
			total:    100,
			expected: 50,
		},
		{
			name:     "100 percent",
			part:     100,
			total:    100,
			expected: 100,
		},
		{
			name:     "25 percent",
			part:     25,
			total:    100,
			expected: 25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := percentage(tt.part, tt.total)
			if got != tt.expected {
				t.Errorf("percentage(%d, %d) = %v, want %v", tt.part, tt.total, got, tt.expected)
			}
		})
	}
}

func BenchmarkProcessorRegistry_FindProcessor(b *testing.B) {
	registry := NewProcessorRegistry()

	// Register several processors
	s3Proc := newMockProcessorWithMetadata("s3", 100, []string{}, true, &ProcessorMetadata{
		ServiceNames: []string{"s3"},
		Priority:     100,
	})
	ec2Proc := newMockProcessorWithMetadata("ec2", 100, []string{}, true, &ProcessorMetadata{
		ServiceNames: []string{"ec2"},
		Priority:     100,
	})
	genericProc := newMockProcessorWithMetadata("generic", 10, []string{}, true, &ProcessorMetadata{
		FallbackOnly: true,
		Priority:     10,
	})

	registry.Register(s3Proc)
	registry.Register(ec2Proc)
	registry.Register(genericProc)

	ctx := createTestContext("s3", "us-east-1", "bucket.s3.example.com", "/key")

	b.ResetTimer()
	for b.Loop() {
		registry.FindProcessor(ctx)
	}
}
