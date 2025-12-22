package audit

import (
	"context"
	"fmt"
	"sync"

	"github.com/stephnangue/warden/logger"
)

// manager implements the Manager interface
type manager struct {
	mu       sync.RWMutex
	devices  map[string]Device
	log      *logger.GatedLogger
	parallel bool // Whether to log to devices in parallel
}

// AuditManagerConfig contains configuration for the audit manager
type AuditManagerConfig struct {
	// Parallel enables concurrent logging to multiple devices (default: true)
	// Set to false if you need strict ordering across all devices
	Parallel bool

	Logger *logger.GatedLogger
}

// NewAuditManager creates a new audit manager
func NewAuditManager(log *logger.GatedLogger) AuditManager {
	return &manager{
		devices:  make(map[string]Device),
		log:      log,
		parallel: true,
	}
}

// NewAuditManagerWithConfig creates a new audit manager with custom configuration
func NewAuditManagerWithConfig(config AuditManagerConfig) AuditManager {
	return &manager{
		devices:  make(map[string]Device),
		parallel: config.Parallel,
		log:      config.Logger,
	}
}

// RegisterDevice registers a new audit device
func (m *manager) RegisterDevice(name string, device Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.devices[name]; exists {
		return fmt.Errorf("device %q already registered", name)
	}

	m.devices[name] = device
	return nil
}

// UnregisterDevice unregisters an audit device
func (m *manager) UnregisterDevice(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	device, exists := m.devices[name]
	if !exists {
		return fmt.Errorf("device %q not found", name)
	}

	// Close the device
	if err := device.Close(); err != nil {
		return fmt.Errorf("failed to close device: %w", err)
	}

	delete(m.devices, name)
	return nil
}

// GetDevice returns a device by name
func (m *manager) GetDevice(name string) (Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	device, exists := m.devices[name]
	if !exists {
		return nil, fmt.Errorf("device %q not found", name)
	}

	return device, nil
}

// ListDevices returns all registered devices
func (m *manager) ListDevices() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.devices))
	for name := range m.devices {
		names = append(names, name)
	}

	return names
}

// LogRequest logs a request to all enabled devices
// Returns (continue, error) where continue is true if at least one device succeeded
func (m *manager) LogRequest(ctx context.Context, entry *LogEntry) (bool, error) {
	return m.logToDevices(ctx, entry, true)
}

// LogResponse logs a response to all enabled devices
// Returns (continue, error) where continue is true if at least one device succeeded
func (m *manager) LogResponse(ctx context.Context, entry *LogEntry) (bool, error) {
	return m.logToDevices(ctx, entry, false)
}

// logToDevices is a shared implementation for logging to all enabled devices
// Returns (continue, error) where continue is true if at least one device succeeded
func (m *manager) logToDevices(ctx context.Context, entry *LogEntry, isRequest bool) (bool, error) {
	// Get enabled devices with minimal lock time
	m.mu.RLock()
	if len(m.devices) == 0 {
		m.mu.RUnlock()
		return false, nil
	}

	devices := make([]Device, 0, len(m.devices))
	parallel := m.parallel
	for _, device := range m.devices {
		if device.Enabled() {
			devices = append(devices, device)
		}
	}
	m.mu.RUnlock()

	if len(devices) == 0 {
		return false, nil
	}

	// Single device optimization - no need for goroutines or channels
	if len(devices) == 1 {
		var err error
		if isRequest {
			err = devices[0].LogRequest(ctx, entry)
		} else {
			err = devices[0].LogResponse(ctx, entry)
		}
		if err != nil {
			return false, fmt.Errorf("device %q: %w", devices[0].Name(), err)
		}
		return true, nil
	}

	// Multiple devices - use parallel or sequential based on configuration
	if parallel {
		return m.logParallel(ctx, devices, entry, isRequest)
	}
	return m.logSequential(ctx, devices, entry, isRequest)
}

// logParallel logs to all devices concurrently
// Returns (continue, error) where continue is true if at least one device succeeded
func (m *manager) logParallel(ctx context.Context, devices []Device, entry *LogEntry, isRequest bool) (bool, error) {
	type result struct {
		name    string
		err     error
		success bool
	}

	results := make(chan result, len(devices))

	// Fan-out: log to all devices concurrently
	for _, device := range devices {
		go func(d Device) {
			var err error
			if isRequest {
				err = d.LogRequest(ctx, entry)
			} else {
				err = d.LogResponse(ctx, entry)
			}
			results <- result{name: d.Name(), err: err, success: err == nil}
		}(device)
	}

	// Fan-in: collect all results
	var errs []error
	atLeastOneSuccess := false
	for i := 0; i < len(devices); i++ {
		res := <-results
		if res.success {
			atLeastOneSuccess = true
		} else {
			errs = append(errs, fmt.Errorf("device %q: %w", res.name, res.err))
		}
	}

	return atLeastOneSuccess, m.formatErrors(errs)
}

// logSequential logs to all devices one by one
// Returns (continue, error) where continue is true if at least one device succeeded
func (m *manager) logSequential(ctx context.Context, devices []Device, entry *LogEntry, isRequest bool) (bool, error) {
	var errs []error
	atLeastOneSuccess := false

	for _, device := range devices {
		var err error
		if isRequest {
			err = device.LogRequest(ctx, entry)
		} else {
			err = device.LogResponse(ctx, entry)
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("device %q: %w", device.Name(), err))
		} else {
			atLeastOneSuccess = true
		}
	}

	return atLeastOneSuccess, m.formatErrors(errs)
}

// formatErrors formats a slice of errors into a single error
func (m *manager) formatErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}

	// Return single error directly for clarity
	if len(errs) == 1 {
		return errs[0]
	}

	// Multiple errors - return aggregated error
	return fmt.Errorf("failed to log to %d device(s): %v", len(errs), errs)
}

// Close closes all devices
func (m *manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for name, device := range m.devices {
		if err := device.Close(); err != nil {
			errs = append(errs, fmt.Errorf("device %q: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close %d device(s): %v", len(errs), errs)
	}

	return nil
}
