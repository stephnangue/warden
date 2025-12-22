package core

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/go-uuid"
	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider"
)

const (
	// coreMountConfigPath is used to store the mount configuration.
	// Mounts are protected within the Warden itself, which means they
	// can only be viewed or modified after an unseal.
	coreMountConfigPath = "core/mounts"

	mountPathSystem = "sys/"

	mountClassSystem   = "system"
	mountClassProvider = "provider"
	mountClassAuth     = "auth"
	mountClassAudit    = "audit"

	MountTableUpdateStorage   = true
	MountTableNoUpdateStorage = false
)

var (
	// protectedMounts cannot be remounted
	protectedMounts = []string{
		"audit/",
		"auth/",
		mountPathSystem,
	}

	// singletonMounts can only exist in one location and are
	// loaded by default. These are class, not paths.
	singletonMounts = []string{
		"system",
	}
)

func (c *Core) generateMountAccessor(entryType string) (string, error) {
	var accessor string
	for {
		randBytes, err := uuid.GenerateRandomBytes(4)
		if err != nil {
			return "", err
		}
		accessor = fmt.Sprintf("%s_%s", entryType, fmt.Sprintf("%08x", randBytes[0:4]))
		if entry := c.router.MatchingMountByAccessor(accessor); entry == nil {
			break
		}
	}

	return accessor, nil
}

// MountTable is used to represent the internal mount table
type MountTable struct {
	Entries []*MountEntry `json:"entries"`
}

func NewMountTable() *MountTable {
	return &MountTable{
		Entries: make([]*MountEntry, 0),
	}
}

// shallowClone returns a copy of the mount table that
// keeps the MountEntry locations, so as not to invalidate
// other locations holding pointers. Care needs to be taken
// if modifying entries rather than modifying the table itself
func (t *MountTable) shallowClone() *MountTable {
	return &MountTable{
		Entries: slices.Clone(t.Entries),
	}
}

// setTaint is used to set the taint on given entry
func (t *MountTable) setTaint(path string, tainted bool) (*MountEntry, error) {
	n := len(t.Entries)
	for i := 0; i < n; i++ {
		if entry := t.Entries[i]; entry.Path == path {
			t.Entries[i].Tainted = tainted
			return t.Entries[i], nil
		}
	}
	return nil, nil
}

// remove is used to remove a given path entry; returns the entry that was
// removed
func (t *MountTable) remove(ctx context.Context, path string) (*MountEntry, error) {
	var mountEntryToDelete *MountEntry
	t.Entries = slices.DeleteFunc(t.Entries, func(me *MountEntry) bool {
		if me.Path == path {
			mountEntryToDelete = me
			return true
		}
		return false
	})

	return mountEntryToDelete, nil
}

func (t *MountTable) findByPath(ctx context.Context, path string) (*MountEntry, error) {
	return t.find(ctx, func(me *MountEntry) bool { return me.Path == path })
}

func (t *MountTable) find(ctx context.Context, predicate func(*MountEntry) bool) (*MountEntry, error) {
	for _, entry := range t.Entries {
		if predicate(entry) {
			return entry, nil
		}
	}

	return nil, nil
}

// MountEntry is used to represent a mount table entry
type MountEntry struct {
	Class       string         `json:"class"`
	Type        string         `json:"type"`
	Path        string         `json:"path"`
	Description string         `json:"description"`
	Accessor    string         `json:"accessor"`
	Tainted     bool           `json:"tainted,omitempty"`
	Config      map[string]any `json:"config"`
	configMu    sync.RWMutex
}

// mount is used to mount a new backend to the mount table.
func (c *Core) mount(ctx context.Context, entry *MountEntry) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Prevent protected paths from being mounted
	for _, p := range protectedMounts {
		if strings.HasPrefix(entry.Path, p) {
			return fmt.Errorf("cannot mount %q", entry.Path)
		}
	}

	// Do not allow more than one instance of a singleton mount
	for _, p := range singletonMounts {
		if entry.Type == p {
			return fmt.Errorf("mount type of %q is not mountable", entry.Type)
		}
	}

	// Mount internally
	if err := c.mountInternal(ctx, entry, MountTableUpdateStorage); err != nil {
		return err
	}

	return nil
}

func (c *Core) mountInternal(ctx context.Context, entry *MountEntry, updateStorage bool) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	// Basic check for matching names
	for _, ent := range c.mounts.Entries {
		switch {
		// Existing is oauth/github/ new is oauth/ or
		// existing is oauth/ and new is oauth/github/
		case strings.HasPrefix(ent.Path, entry.Path):
			fallthrough
		case strings.HasPrefix(entry.Path, ent.Path):
			return fmt.Errorf("path is already in use at %s", ent.Path)
		}
	}

	// Verify there are no conflicting mounts in the router
	if match := c.router.MountConflict(ctx, entry.Path); match != "" {
		return fmt.Errorf("existing mount at %s", match)
	}

	if entry.Accessor == "" {
		accessor, err := c.generateMountAccessor(entry.Type)
		if err != nil {
			return err
		}
		entry.Accessor = accessor
	}

	var backend logical.Backend
	var err error
	backend, err = c.newLogicalBackend(ctx, entry)
	if err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("nil backend of type %s returned from creation function", entry.Type)
	}

	newTable := c.mounts.shallowClone()
	newTable.Entries = append(newTable.Entries, entry)
	if updateStorage {
		// if err := c.persistMounts(ctx, nil, newTable, &entry.Local, entry.UUID); err != nil {
		// 	if logical.ShouldForward(err) {
		// 		return err
		// 	}

		// 	c.logger.Error("failed to update mount table", "error", err)
		// 	return logical.CodedError(500, "failed to update mount table")
		// }
	}

	c.mounts = newTable

	if err := c.router.Mount(entry.Path, backend, entry); err != nil {
		return err
	}

	c.logger.Info("successfully mounted",
		logger.String("path", entry.Path),
		logger.String("type", entry.Type),
		logger.String("class", entry.Class),
	)

	return nil
}

// newLogicalBackend is used to create and configure a new logical backend by name.
func (c *Core) newLogicalBackend(ctx context.Context, entry *MountEntry) (logical.Backend, error) {
	var factory any
	var backend logical.Backend
	var err error
	switch entry.Class {
	case mountClassAuth:
		factory = c.authMethods[entry.Type]
		if factory == nil {
			return nil, fmt.Errorf("auth method type not supported: %s", entry.Type)
		}
		f := factory.(auth.Factory)
		backend, err = f.Create(
			ctx,
			entry.Path,
			entry.Description,
			entry.Accessor,
			entry.Config,
			c.logger.WithSystem("auth"),
			c.tokenStore,
			c.roles,
			c.accessControl,
			c.auditManager,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth method: %w", err)
		}
	case mountClassProvider:
		factory = c.providers[entry.Type]
		if factory == nil {
			return nil, fmt.Errorf("provider type not supported: %s", entry.Type)
		}
		f := factory.(provider.Factory)

		backend, err = f.Create(
			ctx,
			entry.Path,
			entry.Description,
			entry.Accessor,
			entry.Config,
			c.logger.WithSystem("provider"),
			c.tokenStore,
			c.roles,
			c.credSources,
			c.auditManager,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider: %w", err)
		}
	case mountClassSystem:
		backend = NewSystemBackend(c, c.logger.WithSystem("system"))
	}

	// Check if backend is nil (shouldn't happen in normal operation, but handle it for safety)
	if backend == nil {
		return nil, fmt.Errorf("nil backend returned for %s type %s", entry.Class, entry.Type)
	}

	entry.configMu.Lock()
	defer entry.configMu.Unlock()
	entry.Config = map[string]any{}
	maps.Copy(entry.Config, backend.Config())
	return backend, nil
}

// unmount is used to unmount a path.
func (c *Core) unmount(ctx context.Context, path string) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Prevent protected paths from being unmounted
	for _, p := range protectedMounts {
		if strings.HasPrefix(path, p) {
			return fmt.Errorf("cannot unmount %q", path)
		}
	}

	// Unmount mount internally
	if err := c.unmountInternal(ctx, path, MountTableUpdateStorage); err != nil {
		return err
	}

	return nil
}

// configureMount updates the configuration of an existing mount
func (c *Core) configureMount(ctx context.Context, path string, config map[string]any) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Prevent protected paths from being tuned
	for _, p := range protectedMounts {
		if strings.HasPrefix(path, p) {
			return fmt.Errorf("cannot tune %q", path)
		}
	}

	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	// Find the mount entry
	entry, err := c.mounts.findByPath(ctx, path)
	if err != nil {
		return err
	}
	if entry == nil {
		return errNoMatchingMount
	}

	// Merge existing config with new config
	mergedConfig := make(map[string]any)
	maps.Copy(mergedConfig, entry.Config)
	maps.Copy(mergedConfig, config)

	// Validate configuration for provider mounts
	var backend logical.Backend
	switch entry.Class {
	case mountClassProvider :
		factory := c.providers[entry.Type]
		if factory == nil {
			return fmt.Errorf("provider type %s not found", entry.Type)
		}
	case mountClassAuth :
		factory := c.authMethods[entry.Type]
		if factory == nil {
			return fmt.Errorf("auth method type %s not found", entry.Type)
		}

	default :
		return fmt.Errorf("unsupported mount class: %s", entry.Class)
	}

	backend = c.router.MatchingBackend(ctx, path)
	if backend == nil {
		return fmt.Errorf("backend not found for path %s", path)
	}

	if err := backend.Setup(mergedConfig); err != nil {
		return fmt.Errorf("failed to setup backend with new config: %w", err)
	}

	entry.configMu.Lock()
	entry.Config = backend.Config()
	entry.configMu.Unlock()

	// Persist the updated mount table (commented out for now, consistent with other methods)
	// if err := c.persistMounts(ctx, nil, c.mounts, &entry.Local, entry.UUID); err != nil {
	// 	c.logger.Error("failed to persist mount configuration", "error", err)
	// 	return fmt.Errorf("failed to persist mount configuration: %w", err)
	// }

	c.logger.Info("successfully configured mount",
		logger.String("path", path),
	)

	return nil
}

func (c *Core) unmountInternal(ctx context.Context, path string, updateStorage bool) error {
	// Verify exact match of the route
	match := c.router.MatchingMount(ctx, path)
	if match == "" {
		return errNoMatchingMount
	}

	// Mark the entry as tainted
	if err := c.taintMountEntry(ctx, path, updateStorage); err != nil {
		c.logger.Error("failed to taint mount entry for path being unmounted",
			logger.Err(err),
			logger.String("path", path),
		)
		return err
	}

	// Taint the router path to prevent routing. Note that in-flight requests
	// are uncertain, right now.
	if err := c.router.Taint(ctx, path); err != nil {
		return err
	}

	// Remove the mount table entry
	if err := c.removeMountEntry(ctx, path, updateStorage); err != nil {
		c.logger.Error("failed to remove mount entry for path being unmounted",
			logger.Err(err),
			logger.String("path", path),
		)
		return err
	}

	// Unmount the backend entirely
	if err := c.router.Unmount(path); err != nil {
		return err
	}

	c.logger.Info("successfully unmounted",
		logger.String("path", path),
	)

	return nil

}

// taintMountEntry is used to mark an entry in the mount table as tainted
func (c *Core) taintMountEntry(ctx context.Context, mountPath string, updateStorage bool) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	entry, err := c.mounts.setTaint(mountPath, true)
	if err != nil {
		return err
	}

	if entry == nil {
		c.logger.Error("nil entry found tainting entry in mounts table",
			logger.String("path", mountPath),
		)
		return fmt.Errorf("failed to taint entry in mounts table")
	}

	if updateStorage {
		// Update the mount table
		// if err := c.persistMounts(ctx, nil, c.mounts, &entry.Local, entry.UUID); err != nil {
		// 	c.logger.Error("failed to taint entry in mounts table", "error", err)
		// 	return logical.CodedError(500, "failed to taint entry in mounts table")
		// }
	}

	return nil
}

// removeMountEntry is used to remove an entry from the mount table
func (c *Core) removeMountEntry(ctx context.Context, path string, updateStorage bool) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	// Remove the entry from the mount table
	newTable := c.mounts.shallowClone()
	entry, err := newTable.remove(ctx, path)
	if err != nil {
		return err
	}
	if entry == nil {
		c.logger.Error("nil entry found tainting entry in mounts table",
			logger.String("path", path),
		)
		return fmt.Errorf("failed to remove entry in mounts table")
	}

	// When unmounting all entries the JSON code will load back up from storage
	// as a nil slice, which kills tests...just set it nil explicitly
	if len(newTable.Entries) == 0 {
		newTable.Entries = nil
	}

	if updateStorage {
		// Update the mount table
		// if err := c.persistMounts(ctx, nil, newTable, &entry.Local, entry.UUID); err != nil {
		// 	c.logger.Error("failed to remove entry from mounts table", "error", err)
		// 	return logical.CodedError(500, "failed to remove entry from mounts table")
		// }
	}

	c.mounts = newTable
	return nil
}

func (c *Core) LoadSystemBackend(ctx context.Context) error {
	return c.mountInternal(ctx, &MountEntry{
		Class:       mountClassSystem,
		Type:        "system",
		Path:        mountPathSystem, // "sys/"
		Description: "System backend for management operations",
		Accessor:    "system",
	}, MountTableNoUpdateStorage)
}

func (c *Core) LoadMounts(ctx context.Context) error {
	// err := c.mount(ctx, &MountEntry{
	// 	Class:       "auth",
	// 	Type:        "jwt",
	// 	Path:        "jwt",
	// 	Description: "test jwt auth method",
	// 	Config: map[string]any{
	// 		"type":     "jwt",
	// 		"jwks_url": "http://hydra:4444/.well-known/jwks.json",
	// 	}})
	// if err != nil {
	// 	return err
	// }

	// err = c.mount(ctx, &MountEntry{
	// 	Class:       "provider",
	// 	Type:        "aws",
	// 	Path:        "aws",
	// 	Description: "aws cloud provider",
	// 	Config: map[string]any{
	// 		"proxy_domains": []string{"localhost", "warden"},
	// 	}})
	// if err != nil {
	// 	return err
	// }

	return nil
}

// unloadMounts is called on seal to tear down all mounted backends
// This ensures a clean state when the core is sealed and prevents
// duplicate mount errors when unsealing again
func (c *Core) unloadMounts(ctx context.Context) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	// Get a snapshot of current mounts to iterate over
	// We need to copy the paths because we'll be modifying the mount table
	var mountPaths []string
	for _, entry := range c.mounts.Entries {
		mountPaths = append(mountPaths, entry.Path)
	}

	c.logger.Debug("unloading mounts", logger.Int("count", len(mountPaths)))

	// Unmount each backend from the router
	// We don't update storage here because we're sealing - the mount table
	// in storage should remain intact for the next unseal
	var unmountErrors []error
	for _, path := range mountPaths {
		c.logger.Debug("unmounting backend", logger.String("path", path))

		// Unmount from router (this calls backend.Cleanup())
		if err := c.router.Unmount(path); err != nil {
			c.logger.Warn("failed to unmount backend from router",
				logger.Err(err),
				logger.String("path", path))
			unmountErrors = append(unmountErrors, fmt.Errorf("failed to unmount %s: %w", path, err))
			continue
		}
	}

	// Clear the in-memory mount table
	// This will be reloaded from storage on next unseal
	c.mounts = NewMountTable()

	if len(unmountErrors) > 0 {
		c.logger.Warn("encountered errors while unloading mounts",
			logger.Int("error_count", len(unmountErrors)))
		// Return the first error for now
		return unmountErrors[0]
	}

	c.logger.Debug("successfully unloaded all mounts")
	return nil
}
