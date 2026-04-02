package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseDurationFromSeconds(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected time.Duration
	}{
		{"float64", float64(3600), time.Hour},
		{"int64", int64(60), time.Minute},
		{"json.Number", json.Number("120"), 2 * time.Minute},
		{"string duration", "30s", 30 * time.Second},
		{"string invalid", "notaduration", 0},
		{"nil", nil, 0},
		{"bool", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDurationFromSeconds(tt.input)
			if got != tt.expected {
				t.Errorf("parseDurationFromSeconds(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestConfigValueToString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"json.Number", json.Number("42"), "42"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"float64 int", float64(42), "42"},
		{"float64 frac", float64(3.14), "3.14"},
		{"int", int(7), "7"},
		{"int64", int64(99), "99"},
		{"uint", uint(5), "5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := configValueToString(tt.input)
			if got != tt.expected {
				t.Errorf("configValueToString(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseConfigMap(t *testing.T) {
	t.Run("valid map", func(t *testing.T) {
		input := map[string]interface{}{
			"key1": "val1",
			"key2": json.Number("42"),
			"key3": true,
		}
		result := parseConfigMap(input)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result["key1"] != "val1" {
			t.Errorf("expected val1, got %s", result["key1"])
		}
		if result["key2"] != "42" {
			t.Errorf("expected 42, got %s", result["key2"])
		}
		if result["key3"] != "true" {
			t.Errorf("expected true, got %s", result["key3"])
		}
	})

	t.Run("nil input", func(t *testing.T) {
		result := parseConfigMap(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		result := parseConfigMap("not a map")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})
}
