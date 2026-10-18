package credential

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
)

// DriverRegistry manages driver factories and instances
type DriverRegistry struct {
	mu        sync.RWMutex
	factories map[string]SourceDriverFactory // type -> factory
	instances map[string]SourceDriver        // {namespace}:{source_name} -> driver instance
	log       *logger.GatedLogger

	// generations counts how many times each source key has been invalidated.
	//
	// A driver is built outside this lock, from a source read outside it, so the
	// config it was built from can go stale before the instance is installed —
	// and because a registry hit is a plain map lookup, a stale instance
	// installed once is served until the next config change or a restart.
	//
	// Callers therefore read the generation before reading the source and hand it
	// back at install time; an install whose generation has moved is refused and
	// the caller re-reads. Checking at install rather than on lookup keeps the
	// hot path a single map read, and keeps driver teardown off the mint path.
	generations map[string]uint64

	// epoch invalidates every key at once, including keys with no generation
	// entry yet. CloseAll bumps it: a build that read its source before the
	// node stopped being active must be refused even for a source it had never
	// built a driver for. A key's effective generation is generations[key] +
	// epoch; both only grow, so any bump changes the sum.
	epoch uint64

	// building holds the driver builds in flight, one per key. A factory's Create
	// may log in or probe its upstream, so it runs outside mu: holding the lock
	// across it stalled every GetDriver, in every namespace, behind one slow
	// upstream. A second caller for the same key waits on the build in flight
	// rather than starting its own.
	building map[string]*driverBuild
}

// staleDriverCleanupTimeout bounds the cleanup of a driver built from config that
// changed while it was being built.
const staleDriverCleanupTimeout = 10 * time.Second

// driverBuild is one factory.Create in flight. done is closed once driver or err
// is set, and the entry is removed from building, both under mu.
type driverBuild struct {
	done   chan struct{}
	driver SourceDriver
	err    error
}

// NewDriverRegistry creates a new driver registry
func NewDriverRegistry(log *logger.GatedLogger) *DriverRegistry {
	return &DriverRegistry{
		factories:   make(map[string]SourceDriverFactory),
		instances:   make(map[string]SourceDriver),
		generations: make(map[string]uint64),
		building:    make(map[string]*driverBuild),
		log:         log,
	}
}

// RegisterFactory registers a driver factory
func (r *DriverRegistry) RegisterFactory(factory SourceDriverFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	driverType := factory.Type()

	// Check for duplicate registration
	if _, exists := r.factories[driverType]; exists {
		return fmt.Errorf("%w: %s", ErrDriverAlreadyRegistered, driverType)
	}

	r.factories[driverType] = factory
	return nil
}

// qualifiedKey builds a namespace-qualified key for driver instance lookup
// Format: {namespace_id}:{source_name}
func (r *DriverRegistry) qualifiedKey(ctx context.Context, sourceName string) (string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get namespace from context: %w", err)
	}
	return fmt.Sprintf("%s:%s", ns.ID, sourceName), nil
}

// Generation returns the current invalidation count for a source key. Read it
// before reading the source, and pass it to CreateDriver: that is what lets
// CreateDriver tell whether the config the driver was built from is still current.
func (r *DriverRegistry) Generation(ctx context.Context, sourceName string) (uint64, error) {
	qualifiedName, err := r.qualifiedKey(ctx, sourceName)
	if err != nil {
		return 0, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.generations[qualifiedName] + r.epoch, nil
}

// CreateDriver creates a driver instance for the given source
// The driver is stored with a namespace-qualified key to prevent collisions
// between sources with the same name in different namespaces.
// Returns the driver and a boolean indicating if a new driver was created (true)
// or an existing driver was returned (false).
//
// observedGeneration is the value Generation returned before the source was read.
// If the key has been invalidated since, the source this driver was built from is
// no longer current and the install is refused with ErrDriverConfigChanged rather
// than pinning stale config in the registry.
//
// The factory runs without the registry lock held, so a slow upstream delays only
// the callers waiting for this key. Concurrent callers for one key share a single
// build: they wait for it (or for their own ctx) and receive its driver or its
// error. A build whose key is invalidated while it runs is cleaned up and refused,
// so every caller that waited on it re-reads the source.
func (r *DriverRegistry) CreateDriver(ctx context.Context, sourceName string, source *CredSource, observedGeneration uint64) (SourceDriver, bool, error) {
	qualifiedName, err := r.qualifiedKey(ctx, sourceName)
	if err != nil {
		return nil, false, err
	}

	r.mu.Lock()

	// Check if instance already exists
	if driver, exists := r.instances[qualifiedName]; exists {
		r.mu.Unlock()
		return driver, false, nil
	}

	if r.generations[qualifiedName]+r.epoch != observedGeneration {
		r.mu.Unlock()
		return nil, false, ErrDriverConfigChanged
	}

	if inFlight, ok := r.building[qualifiedName]; ok {
		r.mu.Unlock()
		select {
		case <-inFlight.done:
			return inFlight.driver, false, inFlight.err
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}

	// Get factory for source type
	factory, exists := r.factories[source.Type]
	if !exists {
		r.mu.Unlock()
		return nil, false, fmt.Errorf("%w: %s", ErrDriverNotFound, source.Type)
	}

	build := &driverBuild{done: make(chan struct{})}
	r.building[qualifiedName] = build
	r.mu.Unlock()

	driver, err := r.runBuild(qualifiedName, build, factory, source, observedGeneration)
	if err != nil {
		return nil, false, err
	}
	return driver, true, nil
}

// runBuild runs factory.Create for an in-flight build and settles it: installs the
// driver if the key's generation is still observedGeneration, and otherwise
// refuses it and cleans it up. The build is removed from building and its waiters
// released on every path, a panicking factory included.
func (r *DriverRegistry) runBuild(key string, build *driverBuild, factory SourceDriverFactory, source *CredSource, observedGeneration uint64) (driver SourceDriver, err error) {
	var stale SourceDriver
	settled := false
	defer func() {
		if !settled {
			// The factory panicked: release the waiters before the panic unwinds.
			r.mu.Lock()
			delete(r.building, key)
			build.err = fmt.Errorf("%w: %s: the driver factory panicked", ErrDriverCreationFailed, source.Type)
			r.mu.Unlock()
			close(build.done)
		}
		if stale != nil {
			ctx, cancel := context.WithTimeout(context.Background(), staleDriverCleanupTimeout)
			defer cancel()
			if cerr := stale.Cleanup(ctx); cerr != nil {
				r.log.Warn("cleanup of a driver built from stale config failed",
					logger.String("qualified_key", key), logger.Err(cerr))
			}
		}
	}()

	driver, err = factory.Create(source.Config, r.log)
	if err != nil {
		// Both wrapped: a driver that calls its upstream while being created
		// (a login, a token fetch) can fail with that upstream's refusal,
		// which callers classify by the cause's type.
		err = fmt.Errorf("%w: %s: %w", ErrDriverCreationFailed, source.Type, err)
		driver = nil
	}

	r.mu.Lock()
	delete(r.building, key)
	switch {
	case err != nil:
	case r.generations[key]+r.epoch != observedGeneration:
		stale, driver, err = driver, nil, ErrDriverConfigChanged
	default:
		r.instances[key] = driver
	}
	build.driver, build.err = driver, err
	settled = true
	r.mu.Unlock()
	close(build.done)
	return driver, err
}

// GetDriver retrieves a driver instance by source name
// Uses namespace from context to build qualified key
func (r *DriverRegistry) GetDriver(ctx context.Context, sourceName string) (SourceDriver, bool) {
	qualifiedName, err := r.qualifiedKey(ctx, sourceName)
	if err != nil {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	driver, exists := r.instances[qualifiedName]
	return driver, exists
}

// ListFactories returns all registered driver factory types
func (r *DriverRegistry) ListFactories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.factories))
	for driverType := range r.factories {
		types = append(types, driverType)
	}
	return types
}

// HasFactory checks if a driver factory is registered for the given type
func (r *DriverRegistry) HasFactory(driverType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.factories[driverType]
	return exists
}

// GetFactory retrieves a driver factory by type
func (r *DriverRegistry) GetFactory(driverType string) (SourceDriverFactory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, exists := r.factories[driverType]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrDriverNotFound, driverType)
	}

	return factory, nil
}

// CloseDriver closes and removes a driver instance by source name.
// This should be called when a source is deleted or updated to prevent resource leaks.
// Returns an error if the driver's Cleanup() method fails.
func (r *DriverRegistry) CloseDriver(ctx context.Context, sourceName string) error {
	qualifiedName, err := r.qualifiedKey(ctx, sourceName)
	if err != nil {
		return err
	}

	r.mu.Lock()
	// Bump the generation whether or not an instance is present. An invalidation
	// with nothing cached still matters: a mint that has already read the old
	// source config and not yet installed its driver must be refused.
	r.generations[qualifiedName]++

	driver, exists := r.instances[qualifiedName]
	// Detached under the lock and cleaned up after it, so a slow Cleanup never
	// holds the registry.
	delete(r.instances, qualifiedName)
	r.mu.Unlock()

	if !exists {
		// Driver doesn't exist - nothing to clean up
		return nil
	}

	if err := driver.Cleanup(ctx); err != nil {
		r.log.Warn("driver cleanup failed",
			logger.String("source_name", sourceName),
			logger.Err(err))
	}

	r.log.Debug("driver closed and removed",
		logger.String("source_name", sourceName),
		logger.String("qualified_key", qualifiedName))

	return nil
}

// CloseAll closes and removes every driver instance, in every namespace, and
// invalidates each one's generation. It returns how many were closed.
//
// The registry outlives the node's active term: it is built once per process,
// while the config cache and the credential manager are rebuilt on each
// promotion. A source changed on another node while this one was standby only
// reaches this node's storage, never its registry, so an instance kept across a
// step-down would go on minting with the config it was built from — an old
// secret, after a rotation or a move to keyless — until the process restarted.
// Closing everything when the node stops being active makes the next promotion
// build each driver from what storage holds then.
//
// The epoch is bumped rather than each instance's generation, so a build that
// read its source before the close is refused for every key, including one
// that had no instance to close. Instances are detached under the lock and
// cleaned up after it is released, so a slow Cleanup never holds the registry.
func (r *DriverRegistry) CloseAll(ctx context.Context) int {
	r.mu.Lock()
	r.epoch++
	closing := r.instances
	r.instances = make(map[string]SourceDriver)
	r.mu.Unlock()

	for key, driver := range closing {
		if err := driver.Cleanup(ctx); err != nil {
			r.log.Warn("driver cleanup failed while closing all drivers",
				logger.String("qualified_key", key),
				logger.Err(err))
		}
		r.log.Debug("driver closed", logger.String("qualified_key", key))
	}
	return len(closing)
}

// CloseAllForNamespace closes and removes all driver instances for a given namespace.
// This should be called when a namespace is deleted to prevent resource leaks.
// Returns the number of drivers closed and any errors encountered.
func (r *DriverRegistry) CloseAllForNamespace(ctx context.Context) (int, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get namespace from context: %w", err)
	}

	// Detach this namespace's drivers under the lock and clean them up after it is
	// released, so a slow Cleanup never holds the registry.
	prefix := ns.ID + ":"
	toClose := make(map[string]SourceDriver)
	r.mu.Lock()
	for key, driver := range r.instances {
		if strings.HasPrefix(key, prefix) {
			r.generations[key]++
			toClose[key] = driver
			delete(r.instances, key)
		}
	}
	// A build in flight has no instance yet. Bump its generation too, or it would
	// install into the namespace being deleted when it settles.
	for key := range r.building {
		if strings.HasPrefix(key, prefix) {
			r.generations[key]++
		}
	}
	r.mu.Unlock()

	if len(toClose) == 0 {
		return 0, nil
	}

	var lastErr error
	for key, driver := range toClose {
		if err := driver.Cleanup(ctx); err != nil {
			r.log.Warn("driver cleanup failed during namespace cleanup",
				logger.String("qualified_key", key),
				logger.Err(err))
			lastErr = err
		}
	}
	closed := len(toClose)

	r.log.Debug("drivers closed for namespace",
		logger.String("namespace_id", ns.ID),
		logger.Int("count", closed))

	return closed, lastErr
}
