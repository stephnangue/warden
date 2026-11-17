package audit

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/stephnangue/warden/logical"
)

// device implements the Device interface.
//
// Every entry logged reads it and no lock guards it: all of it is set when
// the device is created and never written after, except enabled.
type device struct {
	name    string
	format  Format
	sink    Sink
	filters []FilterFunc
	config  *DeviceConfig

	// enabled is the one field that changes after creation.
	enabled atomic.Bool
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
		config:  config,
		filters: pathFilters(config),
	}
	d.enabled.Store(config.Enabled)

	return d
}

// pathFilters creates the filter functions of a device's path configuration.
func pathFilters(config *DeviceConfig) []FilterFunc {
	var filters []FilterFunc

	if len(config.ExcludePaths) > 0 {
		filters = append(filters, func(entry *LogEntry) bool {
			if entry.Request == nil {
				return true
			}

			for _, pattern := range config.ExcludePaths {
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

	if len(config.IncludePaths) > 0 {
		filters = append(filters, func(entry *LogEntry) bool {
			if entry.Request == nil {
				return false
			}

			for _, pattern := range config.IncludePaths {
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

	return filters
}

// shouldLog checks if an entry should be logged based on filters
func (d *device) shouldLog(entry *LogEntry) bool {
	for _, filter := range d.filters {
		if !filter(entry) {
			return false
		}
	}

	return true
}

// LogRequest logs a request
func (d *device) LogRequest(ctx context.Context, entry *LogEntry) error {
	if !d.enabled.Load() {
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
	if !d.enabled.Load() {
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
			ID:       "test-request-id",
			Method:   "GET",
			Path:     "/sys/audit/test",
			ClientIP: "127.0.0.1",
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

// Warnings implements WarningReporter.
func (d *device) Warnings() []string {
	return slices.Clone(d.config.Warnings)
}

var _ WarningReporter = (*device)(nil)

func (d *device) Setup(ctx context.Context, conf *logical.BackendConfig) error {
	return nil
}

func (d *device) Config() map[string]any {
	if d.config == nil {
		return map[string]any{}
	}

	return map[string]any{
		"name":          d.config.Name,
		"type":          d.config.Type,
		"class":         d.config.Class,
		"description":   d.config.Description,
		"accessor":      d.config.Accessor,
		"options":       d.config.Options,
		"enabled":       d.enabled.Load(),
		"format":        d.config.Format,
		"prefix":        d.config.Prefix,
		"hmac_key":      d.config.HMACKey,
		"exclude_paths": d.config.ExcludePaths,
		"include_paths": d.config.IncludePaths,
	}
}

// Enabled returns whether the device is enabled
func (d *device) Enabled() bool {
	return d.enabled.Load()
}

// SetEnabled sets the enabled state
func (d *device) SetEnabled(enabled bool) {
	d.enabled.Store(enabled)
}

func (d *device) GetType() string {
	return d.config.Type
}

func (d *device) Type() string {
	return d.config.Type
}

func (d *device) GetClass() string {
	return d.config.Class
}

func (d *device) Class() logical.BackendClass {
	return logical.ClassUnknown
}

func (d *device) GetDescription() string {
	return d.config.Description
}

func (d *device) GetAccessor() string {
	return d.config.Accessor
}

func (d *device) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	return nil, nil
}

func (d *device) Cleanup(ctx context.Context) {
}

func (d *device) Initialize(ctx context.Context) error {
	return nil
}

func (d *device) ExtractTokens(r *http.Request, userLeg bool) (agent, user string) {
	return "", ""
}

func (d *device) HandleExistenceCheck(ctx context.Context, req *logical.Request) (checkFound bool, exists bool, err error) {
	return false, false, nil
}

func (d *device) SpecialPaths() *logical.Paths {
	return nil
}
