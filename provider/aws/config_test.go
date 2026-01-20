package aws

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestParseConfig_ProxyDomains(t *testing.T) {
	tests := []struct {
		name     string
		conf     map[string]any
		expected []string
	}{
		{
			name:     "default when not provided",
			conf:     map[string]any{},
			expected: []string{"localhost"},
		},
		{
			name: "string slice",
			conf: map[string]any{
				"proxy_domains": []string{"example.com", "test.com"},
			},
			expected: []string{"example.com", "test.com"},
		},
		{
			name: "any slice with strings",
			conf: map[string]any{
				"proxy_domains": []any{"example.com", "test.com"},
			},
			expected: []string{"example.com", "test.com"},
		},
		{
			name: "any slice with mixed types (only strings kept)",
			conf: map[string]any{
				"proxy_domains": []any{"example.com", 123, "test.com"},
			},
			expected: []string{"example.com", "test.com"},
		},
		{
			name: "single domain",
			conf: map[string]any{
				"proxy_domains": []string{"single.com"},
			},
			expected: []string{"single.com"},
		},
		{
			name: "empty slice",
			conf: map[string]any{
				"proxy_domains": []string{},
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := parseConfig(tt.conf)
			if !reflect.DeepEqual(config.ProxyDomains, tt.expected) {
				t.Errorf("ProxyDomains = %v, want %v", config.ProxyDomains, tt.expected)
			}
		})
	}
}

func TestParseConfig_MaxBodySize(t *testing.T) {
	tests := []struct {
		name     string
		conf     map[string]any
		expected int64
	}{
		{
			name:     "default when not provided",
			conf:     map[string]any{},
			expected: 10485760, // 10MB default
		},
		{
			name: "int64 value",
			conf: map[string]any{
				"max_body_size": int64(5242880),
			},
			expected: 5242880,
		},
		{
			name: "int value",
			conf: map[string]any{
				"max_body_size": 5242880,
			},
			expected: 5242880,
		},
		{
			name: "float64 value",
			conf: map[string]any{
				"max_body_size": float64(5242880),
			},
			expected: 5242880,
		},
		{
			name: "json.Number value",
			conf: map[string]any{
				"max_body_size": json.Number("5242880"),
			},
			expected: 5242880,
		},
		{
			name: "string value",
			conf: map[string]any{
				"max_body_size": "5242880",
			},
			expected: 5242880,
		},
		{
			name: "zero value uses default",
			conf: map[string]any{
				"max_body_size": int64(0),
			},
			expected: 10485760,
		},
		{
			name: "negative value uses default",
			conf: map[string]any{
				"max_body_size": int64(-1),
			},
			expected: 10485760,
		},
		{
			name: "invalid string uses default",
			conf: map[string]any{
				"max_body_size": "invalid",
			},
			expected: 10485760,
		},
		{
			name: "large value",
			conf: map[string]any{
				"max_body_size": int64(1073741824), // 1GB
			},
			expected: 1073741824,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := parseConfig(tt.conf)
			if config.MaxBodySize != tt.expected {
				t.Errorf("MaxBodySize = %d, want %d", config.MaxBodySize, tt.expected)
			}
		})
	}
}

func TestParseConfig_Timeout(t *testing.T) {
	tests := []struct {
		name     string
		conf     map[string]any
		expected time.Duration
	}{
		{
			name:     "default when not provided",
			conf:     map[string]any{},
			expected: 30 * time.Second,
		},
		{
			name: "int seconds",
			conf: map[string]any{
				"timeout": 60,
			},
			expected: 60 * time.Second,
		},
		{
			name: "string duration - seconds",
			conf: map[string]any{
				"timeout": "45s",
			},
			expected: 45 * time.Second,
		},
		{
			name: "string duration - minutes",
			conf: map[string]any{
				"timeout": "2m",
			},
			expected: 2 * time.Minute,
		},
		{
			name: "string duration - complex",
			conf: map[string]any{
				"timeout": "1m30s",
			},
			expected: 90 * time.Second,
		},
		{
			name: "zero value uses default",
			conf: map[string]any{
				"timeout": 0,
			},
			expected: 30 * time.Second,
		},
		{
			name: "string zero uses default",
			conf: map[string]any{
				"timeout": "0s",
			},
			expected: 30 * time.Second,
		},
		{
			name: "invalid string uses default",
			conf: map[string]any{
				"timeout": "invalid",
			},
			expected: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := parseConfig(tt.conf)
			if config.Timeout != tt.expected {
				t.Errorf("Timeout = %v, want %v", config.Timeout, tt.expected)
			}
		})
	}
}

func TestParseConfig_Combined(t *testing.T) {
	conf := map[string]any{
		"proxy_domains": []string{"example.com", "test.com"},
		"max_body_size": int64(20971520), // 20MB
		"timeout":       "1m",
	}

	config := parseConfig(conf)

	if !reflect.DeepEqual(config.ProxyDomains, []string{"example.com", "test.com"}) {
		t.Errorf("ProxyDomains = %v, want [example.com test.com]", config.ProxyDomains)
	}
	if config.MaxBodySize != 20971520 {
		t.Errorf("MaxBodySize = %d, want 20971520", config.MaxBodySize)
	}
	if config.Timeout != time.Minute {
		t.Errorf("Timeout = %v, want 1m", config.Timeout)
	}
}

func TestParseConfig_NilMap(t *testing.T) {
	// Edge case: nil map should use all defaults
	var conf map[string]any = nil

	// This might panic without proper nil handling
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("parseConfig panicked with nil map: %v", r)
		}
	}()

	config := parseConfig(conf)

	// Should use defaults
	if len(config.ProxyDomains) != 1 || config.ProxyDomains[0] != "localhost" {
		t.Errorf("Expected default proxy domains, got %v", config.ProxyDomains)
	}
	if config.MaxBodySize != 10485760 {
		t.Errorf("Expected default max body size, got %d", config.MaxBodySize)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("Expected default timeout, got %v", config.Timeout)
	}
}

func BenchmarkParseConfig(b *testing.B) {
	conf := map[string]any{
		"proxy_domains": []string{"example.com", "test.com"},
		"max_body_size": int64(20971520),
		"timeout":       "1m",
	}

	b.ResetTimer()
	for b.Loop() {
		parseConfig(conf)
	}
}
