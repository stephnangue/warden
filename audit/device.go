package audit

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// device implements the Device interface
type device struct {
	mu      sync.RWMutex
	name    string
	format  Format
	sink    Sink
	enabled bool
	filters []FilterFunc
	config  *DeviceConfig
}

// NewDevice creates a new audit device
func NewDevice(name string, format Format, sink Sink, config *DeviceConfig) Device {
	if config == nil {
		config = &DeviceConfig{
			Name:    name,
			Enabled: true,
		}
	}
	
	d := &device{
		name:    name,
		format:  format,
		sink:    sink,
		enabled: config.Enabled,
		config:  config,
		filters: make([]FilterFunc, 0),
	}
	
	// Setup path filters if configured
	d.setupPathFilters()
	
	return d
}

// setupPathFilters creates filter functions based on path configuration
func (d *device) setupPathFilters() {
	if len(d.config.ExcludePaths) > 0 {
		d.AddFilter(func(entry *LogEntry) bool {
			if entry.Request == nil {
				return true
			}
			
			for _, pattern := range d.config.ExcludePaths {
				if matched, _ := filepath.Match(pattern, entry.Request.Path); matched {
					return false
				}
				// Also check if path starts with pattern
				if strings.HasPrefix(entry.Request.Path, pattern) {
					return false
				}
			}
			return true
		})
	}
	
	if len(d.config.IncludePaths) > 0 {
		d.AddFilter(func(entry *LogEntry) bool {
			if entry.Request == nil {
				return false
			}
			
			for _, pattern := range d.config.IncludePaths {
				if matched, _ := filepath.Match(pattern, entry.Request.Path); matched {
					return true
				}
				// Also check if path starts with pattern
				if strings.HasPrefix(entry.Request.Path, pattern) {
					return true
				}
			}
			return false
		})
	}
}

// AddFilter adds a filter function to the device
func (d *device) AddFilter(filter FilterFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.filters = append(d.filters, filter)
}

// shouldLog checks if an entry should be logged based on filters
func (d *device) shouldLog(entry *LogEntry) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	for _, filter := range d.filters {
		if !filter(entry) {
			return false
		}
	}
	
	return true
}

// LogRequest logs a request
func (d *device) LogRequest(ctx context.Context, entry *LogEntry) error {
	d.mu.RLock()
	enabled := d.enabled
	d.mu.RUnlock()
	
	if !enabled {
		return nil
	}
	
	if !d.shouldLog(entry) {
		return nil
	}
	
	// Format the entry
	formatted, err := d.format.FormatRequest(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to format request: %w", err)
	}
	
	// Write to sink
	if err := d.sink.Write(ctx, formatted); err != nil {
		return fmt.Errorf("failed to write to sink: %w", err)
	}
	
	return nil
}

// LogResponse logs a response
func (d *device) LogResponse(ctx context.Context, entry *LogEntry) error {
	d.mu.RLock()
	enabled := d.enabled
	d.mu.RUnlock()

	if !enabled {
		return nil
	}

	if !d.shouldLog(entry) {
		return nil
	}

	// Format the entry
	formatted, err := d.format.FormatResponse(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to format response: %w", err)
	}

	// Write to sink
	if err := d.sink.Write(ctx, formatted); err != nil {
		return fmt.Errorf("failed to write to sink: %w", err)
	}

	return nil
}

// LogTestRequest logs a test request to verify the device is working correctly
func (d *device) LogTestRequest(ctx context.Context) error {
	entry := &LogEntry{
		Type:      "test",
		Timestamp: time.Now().UTC(),
		Request: &Request{
			ID:        "test-request-id",
			Method:    "GET",
			Path:      "/sys/audit/test",
			ClientIP:  "127.0.0.1",
		},
	}

	// Format the entry
	formatted, err := d.format.FormatRequest(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to format test request: %w", err)
	}

	// Write to sink
	if err := d.sink.Write(ctx, formatted); err != nil {
		return fmt.Errorf("failed to write test request to sink: %w", err)
	}

	return nil
}

// Close closes the device
func (d *device) Close() error {
	return d.sink.Close()
}

// Name returns the device name
func (d *device) Name() string {
	return d.name
}

// Enabled returns whether the device is enabled
func (d *device) Enabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.enabled
}

// SetEnabled sets the enabled state
func (d *device) SetEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled = enabled
}

func (d *device) GetType() string {
	return d.config.Type
}

func (d *device) GetClass() string {
	return d.config.Class
}

func (d *device) GetDescription() string {
	return d.config.Description
}

func (d *device) GetAccessor() string {
	return d.config.Accessor
}

func (d *device) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (d *device) Cleanup() {
}