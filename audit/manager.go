package audit

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/stephnangue/warden/logger"
)

// manager implements the Manager interface
type manager struct {
	// mu guards devices and serialises the changes to it. Logging does not
	// take it: it reads published.
	mu      sync.RWMutex
	devices map[string]Device

	// health holds, for each device, how it has fared since it was
	// registered. A device keeps its own through every change to the others.
	health map[string]*deviceHealth

	// published is devices as a list, replaced whole at every change, so that
	// logging an entry takes no lock and allocates nothing to find its devices.
	published atomic.Pointer[deviceList]

	log *logger.GatedLogger
}

// deviceList is the devices to log to, in the order of their names. Once
// published it is never written again.
type deviceList struct {
	devices []listedDevice
}

// listedDevice is a device to log to, with its health.
type listedDevice struct {
	device Device
	health *deviceHealth
}

// deviceHealth is how many entries in a row a device has refused: zero for a
// device that took the last one. Logging reads and writes it with no lock.
type deviceHealth struct {
	refused atomic.Int64
}

// NewAuditManager creates a new audit manager
func NewAuditManager(log *logger.GatedLogger) AuditManager {
	return &manager{
		devices: make(map[string]Device),
		health:  make(map[string]*deviceHealth),
		log:     log,
	}
}

// publishLocked replaces the list logging reads with the devices registered
// now. The caller holds m.mu.
func (m *manager) publishLocked() {
	list := &deviceList{devices: make([]listedDevice, 0, len(m.devices))}
	for _, name := range slices.Sorted(maps.Keys(m.devices)) {
		list.devices = append(list.devices, listedDevice{device: m.devices[name], health: m.health[name]})
	}
	m.published.Store(list)
}

// RegisterDevice registers a new audit device
func (m *manager) RegisterDevice(name string, device Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.devices[name]; exists {
		return fmt.Errorf("device %q already registered", name)
	}

	m.devices[name] = device
	m.health[name] = &deviceHealth{}
	m.publishLocked()
	return nil
}

// UnregisterDevice unregisters an audit device and closes it.
//
// The device is out of the published list before it is closed, and closed
// outside the lock. Closing flushes it, which lasts as long as its file takes:
// requests do not wait for that, and those that come after are not handed a
// device that refuses their entries because it is closed. A request that had
// already read the list may still be: it is refused if no other device takes
// its entry. A device that fails to close is unregistered all the same, and
// the failure is returned.
func (m *manager) UnregisterDevice(name string) error {
	m.mu.Lock()
	device, exists := m.devices[name]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("device %q not found", name)
	}
	delete(m.devices, name)
	delete(m.health, name)
	m.publishLocked()
	m.mu.Unlock()

	if err := device.Close(); err != nil {
		return fmt.Errorf("failed to close device: %w", err)
	}
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

// Reset closes every device and unregisters it: the teardown before a seal.
// Closing a device writes the entries it still buffers and stops its flush
// goroutine; one dropped while open would lose those entries when the process
// exits, and would keep its file open beside the device the next unseal
// creates for the same path.
//
// A device that fails to close is unregistered all the same, so that the next
// unseal can register its successor. The failures are returned.
//
// The devices stay listed until they are closed. A request still on its way
// through a seal is then refused by a device that takes no more entries; with
// the list emptied first it would find no device at all, which is the state
// of a server that has none yet, and be served unaudited for as long as the
// devices take to close.
func (m *manager) Reset(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	err := closeDevices(m.devices)
	m.devices = make(map[string]Device)
	m.health = make(map[string]*deviceHealth)
	m.publishLocked()

	return err
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

// LogRequest logs a request to all enabled devices. See logToDevices for what
// it returns.
func (m *manager) LogRequest(ctx context.Context, entry *LogEntry) (bool, error) {
	return m.logToDevices(ctx, entry, true)
}

// LogResponse logs a response to all enabled devices. See logToDevices for
// what it returns.
func (m *manager) LogResponse(ctx context.Context, entry *LogEntry) (bool, error) {
	return m.logToDevices(ctx, entry, false)
}

// logToDevices is a shared implementation for logging to all enabled devices.
// Returns (continue, error) where continue is true if at least one device
// succeeded — OR if no devices are registered at all. The zero-devices
// case fails open so a freshly-installed cluster can serve sys/audit/{path}
// long enough for the operator to bootstrap one. Once any device is
// registered the broker becomes fail-closed (at least one device must
// succeed per request).
//
// The error is nil whenever continue is true. An entry one device took is
// audited: the devices that refused it are reported in the server log, not to
// the caller, who would refuse the request for it. A second device is there so
// that the failure of the first does not stop the service. With no device
// taking the entry, the error says why each refused.
//
// The devices are logged to in turn, in the order of their names. The caller
// waits for every device either way, and a device takes an entry in about the
// time it takes to start a goroutine for it, so handing each device its own
// cost more than twice what the turn does.
//
// It takes no lock and allocates nothing unless a device fails: the list it
// reads is replaced whole when a device is registered or unregistered.
func (m *manager) logToDevices(ctx context.Context, entry *LogEntry, isRequest bool) (bool, error) {
	list := m.published.Load()
	if list == nil || len(list.devices) == 0 {
		return true, nil
	}

	// With devices registered and all of them disabled, nothing succeeds and
	// nothing fails: fail-closed (the operator explicitly disabled them; we
	// should not pretend audit happened). Distinct from the zero-registered
	// case above, which fails open for bootstrap.
	var errs []error
	atLeastOneSuccess := false
	for _, listed := range list.devices {
		device := listed.device
		if !device.Enabled() {
			continue
		}
		var err error
		if isRequest {
			err = device.LogRequest(ctx, entry)
		} else {
			err = device.LogResponse(ctx, entry)
		}
		if err != nil {
			m.deviceRefused(device, listed.health, err)
			errs = append(errs, fmt.Errorf("device %q: %w", device.Name(), err))
			continue
		}
		if listed.health.refused.Load() != 0 {
			m.deviceRecovered(device, listed.health)
		}
		atLeastOneSuccess = true
	}

	if atLeastOneSuccess {
		return true, nil
	}
	return false, m.formatErrors(errs)
}

// deviceRefused counts an entry device refused, and reports the first of a
// run: a device whose file is full refuses every entry until it is not, and
// one line per entry would bury the log at the rate of the requests.
//
// A device that refuses because it was closed is not failing: it is being
// unregistered or the server is sealing, and nothing is to be reported.
func (m *manager) deviceRefused(device Device, health *deviceHealth, err error) {
	if health.refused.Add(1) != 1 || m.log == nil || errors.Is(err, errSinkClosed) {
		return
	}
	m.log.Error("audit device is failing: it refuses entries until it recovers",
		logger.String("device", device.Name()),
		logger.Err(err),
	)
}

// deviceRecovered reports that device takes entries again, and how many
// writes it refused meanwhile. A refused write is not always a lost entry: a
// device may keep it and write it once it recovers, and says itself what it
// dropped.
func (m *manager) deviceRecovered(device Device, health *deviceHealth) {
	refused := health.refused.Swap(0)
	if refused == 0 || m.log == nil {
		return
	}
	m.log.Info("audit device recovered",
		logger.String("device", device.Name()),
		logger.Int64("writes_refused", refused),
	)
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

	return closeDevices(m.devices)
}

// closeDevices closes every device and reports the ones that failed to. The
// devices are closed at the same time: a device gives up closing after its
// own timeout, and a seal waits for the slowest of them, not for their sum.
func closeDevices(devices map[string]Device) error {
	names := slices.Sorted(maps.Keys(devices))
	failures := make([]error, len(names))
	var closing sync.WaitGroup
	for i, name := range names {
		closing.Add(1)
		go func() {
			defer closing.Done()
			if err := devices[name].Close(); err != nil {
				failures[i] = fmt.Errorf("device %q: %w", name, err)
			}
		}()
	}
	closing.Wait()

	var errs []error
	for _, err := range failures {
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close %d device(s): %v", len(errs), errs)
	}

	return nil
}
