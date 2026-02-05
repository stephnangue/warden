package core

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/go-uuid"
	"github.com/mitchellh/copystructure"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

const (
	// coreMountConfigPath is used to store the mount configuration.
	// Mounts are protected within the Warden itself, which means they
	// can only be viewed or modified after an unseal.
	coreMountConfigPath = "core/mounts"

	mountPathSystem = "sys/"

	mountClassSystem   = "system"
	mountClassNSSystem = "ns_system"
	mountClassProvider = "provider"
	mountClassAuth     = "auth"
	mountClassAudit    = "audit"

	MountTableUpdateStorage   = true
	MountTableNoUpdateStorage = false

	mountStateUnmounting = "unmounting"

	// providerBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the provider backends.
	providerBarrierPrefix = "provider/"

	// authBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the auth backends.
	authBarrierPrefix = "auth/"

	// authRoutePrefix is the mount prefix used for the router
	authRoutePrefix = "auth/"

	// systemBarrierPrefix is the prefix used for the
	// system logical backend.
	systemBarrierPrefix = "sys/"
)

var (
	errLoadMountsFailed = errors.New("failed to setup mount table")

	// protectedMounts cannot be remounted
	protectedMounts = []string{
		"audit/",
		"auth/",
		mountPathSystem,
	}

	// singletonMounts can only exist in one location and are
	// loaded by default. These are class, not paths.
	singletonMounts = []string{
		mountClassSystem,
		mountClassNSSystem,
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
func (t *MountTable) setTaint(nsID, path string, tainted bool, mountState string) (*MountEntry, error) {
	n := len(t.Entries)
	for i := 0; i < n; i++ {
		if entry := t.Entries[i]; entry.Path == path && entry.Namespace().ID == nsID {
			t.Entries[i].Tainted = tainted
			t.Entries[i].MountState = mountState
			return t.Entries[i], nil
		}
	}
	return nil, nil
}

// remove is used to remove a given path entry; returns the entry that was
// removed
func (t *MountTable) remove(ctx context.Context, path string) (*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var mountEntryToDelete *MountEntry
	t.Entries = slices.DeleteFunc(t.Entries, func(me *MountEntry) bool {
		if me.Path == path && me.Namespace().ID == ns.ID {
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

func (t *MountTable) findByBackendUUID(ctx context.Context, backendUUID string) (*MountEntry, error) {
	return t.find(ctx, func(me *MountEntry) bool { return me.BackendAwareUUID == backendUUID })
}

func (t *MountTable) findAllNamespaceMounts(ctx context.Context) ([]*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var mounts []*MountEntry
	for _, entry := range t.Entries {
		if entry.Namespace().ID == ns.ID {
			mounts = append(mounts, entry)
		}
	}

	return mounts, nil
}

func (t *MountTable) find(ctx context.Context, predicate func(*MountEntry) bool) (*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, entry := range t.Entries {
		if predicate(entry) && entry.Namespace().ID == ns.ID {
			return entry, nil
		}
	}

	return nil, nil
}

// sortEntriesByPath sorts the entries in the table by path and returns the
// table; this is useful for tests
func (t *MountTable) sortEntriesByPath() *MountTable {
	sort.Slice(t.Entries, func(i, j int) bool {
		return t.Entries[i].Path < t.Entries[j].Path
	})
	return t
}

// sortEntriesByPath sorts the entries in the table by path and returns the
// table; this is useful for tests
func (t *MountTable) sortEntriesByPathDepth() *MountTable {
	sort.Slice(t.Entries, func(i, j int) bool {
		return len(strings.Split(t.Entries[i].Namespace().Path+t.Entries[i].Path, "/")) < len(strings.Split(t.Entries[j].Namespace().Path+t.Entries[j].Path, "/"))
	})
	return t
}

// MountEntry is used to represent a mount table entry
type MountEntry struct {
	Class                 string         `json:"class"`                             // The mount class
	Type                  string         `json:"type"`                              // The mount type
	Path                  string         `json:"path"`                              // The mounth path
	Description           string         `json:"description"`                       // User-provided description
	UUID                  string         `json:"uuid"`                              // Barrier view UUID
	BackendAwareUUID      string         `json:"backend_aware_uuid"`                // UUID that can be used by the backend as a helper when a consistent value is needed outside of storage.
	Accessor              string         `json:"accessor"`                          // Unique but more human-friendly ID. Does not change, not used for any sensitive things
	Tainted               bool           `json:"tainted,omitempty"`                 // Set as a Write-Ahead flag for unmount/remount
	MountState            string         `json:"mount_state,omitempty"`             // The current mount state.  The only non-empty mount state right now is "unmounting"
	ExternalEntropyAccess bool           `json:"external_entropy_access,omitempty"` // Whether to allow external entropy source access
	Config                map[string]any `json:"config"`                            // Config options for this mount
	SealWrap              bool           `json:"seal_wrap"`                         // Whether to wrap CSPs
	NamespaceID           string         `json:"namespace_id"`

	// namespace contains the populated namespace
	namespace *namespace.Namespace `json:"-"`

	configMu sync.RWMutex `json:"-"`
}

// Clone returns a deep copy of the mount entry
func (e *MountEntry) Clone() (*MountEntry, error) {
	cp, err := copystructure.Copy(e)
	if err != nil {
		return nil, err
	}
	return cp.(*MountEntry), nil
}

// Namespace returns the namespace for the mount entry
func (e *MountEntry) Namespace() *namespace.Namespace {
	return e.namespace
}

// APIPath returns the full API Path for the given mount entry
func (e *MountEntry) APIPath() string {
	path := e.Path
	if e.Class == mountClassAuth {
		path = authRoutePrefix + path
	}
	return e.namespace.Path + path
}

// APIPathNoNamespace returns the API Path without the namespace for the given mount entry
func (e *MountEntry) APIPathNoNamespace() string {
	path := e.Path
	if e.Class == mountClassAuth {
		path = authRoutePrefix + path
	}
	return path
}

func (entry *MountEntry) Deserialize() map[string]interface{} {
	return map[string]interface{}{
		"mount_path":      entry.Path,
		"mount_namespace": entry.Namespace().Path,
		"uuid":            entry.UUID,
		"accessor":        entry.Accessor,
		"mount_type":      entry.Type,
		"mount_class":     entry.Class,
	}
}

// mount is used to mount a new backend to the mount table.
func (c *Core) mount(ctx context.Context, entry *MountEntry) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Prevent protected paths from being mounted
	for _, p := range protectedMounts {
		if strings.HasPrefix(entry.Path, p) && entry.namespace == nil {
			return logical.ErrForbiddenf("cannot mount %q", entry.Path)
		}
	}

	// Do not allow more than one instance of a singleton mount
	for _, p := range singletonMounts {
		if entry.Type == p {
			return logical.ErrForbiddenf("mount type of %q is not mountable", entry.Type)
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

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	entry.NamespaceID = ns.ID
	entry.namespace = ns

	// Basic check for matching names
	for _, ent := range c.mounts.Entries {
		if ns.ID == ent.NamespaceID {
			switch {
			// Existing is oauth/github/ new is oauth/ or
			// existing is oauth/ and new is oauth/github/
			case strings.HasPrefix(ent.Path, entry.Path):
				fallthrough
			case strings.HasPrefix(entry.Path, ent.Path):
				return logical.ErrConflictf("path is already in use at %s", ent.Path)
			}
		}
	}

	mountPath := entry.Path
	if entry.Class == mountClassAuth {
		mountPath = authRoutePrefix + mountPath
	}
	// Verify there are no conflicting mounts in the router
	if match := c.router.MountConflict(ctx, mountPath); match != "" {
		return logical.ErrConflictf("existing mount at %s", match)
	}

	// Generate a new UUID and view
	if entry.UUID == "" {
		entryUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.UUID = entryUUID
	}
	if entry.BackendAwareUUID == "" {
		bUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.BackendAwareUUID = bUUID
	}
	if entry.Accessor == "" {
		accessor, err := c.generateMountAccessor(entry.Type)
		if err != nil {
			return err
		}
		entry.Accessor = accessor
	}

	view, err := c.mountEntryView(entry)
	if err != nil {
		return err
	}

	origReadOnlyErr := view.GetReadOnlyErr()

	// Mark the view as read-only until the mounting is complete and
	// ensure that it is reset after. This ensures that there will be no
	// writes during the construction of the backend.
	view.SetReadOnlyErr(sdklogical.ErrSetupReadOnly)
	// We defer this because we're already up and running so we don't need to
	// time it for after postUnseal
	defer view.SetReadOnlyErr(origReadOnlyErr)

	var backend logical.Backend

	backend, err = c.newLogicalBackend(ctx, entry, view)
	if err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("nil backend of type %s returned from creation function", entry.Type)
	}

	c.setCoreBackend(entry, backend, view)

	newTable := c.mounts.shallowClone()
	newTable.Entries = append(newTable.Entries, entry)
	if updateStorage {
		if err := c.persistMounts(ctx, nil, newTable, entry.UUID); err != nil {
			if sdklogical.ShouldForward(err) {
				return err
			}

			c.logger.Error("failed to update mount table", logger.Err(err))
			return logical.ErrInternal("failed to update mount table")
		}
	}

	c.mounts = newTable

	if err := c.router.Mount(mountPath, backend, entry, view); err != nil {
		return err
	}

	// restore the original readOnlyErr, so we can write to the view in
	// Initialize() if necessary
	view.SetReadOnlyErr(origReadOnlyErr)

	// initialize, using the core's active context.
	err = backend.Initialize(c.activeContext)
	if err != nil {
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
func (c *Core) newLogicalBackend(ctx context.Context, entry *MountEntry, view sdklogical.Storage) (logical.Backend, error) {
	var backend logical.Backend
	var err error

	ctx = namespace.ContextWithNamespace(ctx, entry.namespace)

	switch entry.Class {
	case mountClassAuth:
		factory := c.authMethods[entry.Type]
		if factory == nil {
			return nil, fmt.Errorf("auth method type not supported: %s", entry.Type)
		}
		conf := &logical.BackendConfig{
			StorageView:          view,
			Logger:               c.logger.WithSystem("auth"),
			Config:               entry.Config,
			BackendUUID:          entry.BackendAwareUUID,
			ValidTokenTypes:      c.tokenStore.ListTokenTypes(),
			RegisterShutdownHook: c.RegisterShutdownHook,
		}
		backend, err = factory(ctx, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth method: %w", err)
		}
	case mountClassProvider:
		factory := c.providers[entry.Type]
		if factory == nil {
			return nil, fmt.Errorf("provider type not supported: %s", entry.Type)
		}
		conf := &logical.BackendConfig{
			StorageView:          view,
			Logger:               c.logger.WithSystem("provider"),
			Config:               entry.Config,
			BackendUUID:          entry.BackendAwareUUID,
			RegisterShutdownHook: c.RegisterShutdownHook,
		}
		backend, err = factory(ctx, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider: %w", err)
		}
	case mountClassSystem:
		backend = NewSystemBackend(c, c.logger.WithSystem("system"))
	case mountClassNSSystem:
		backend = NewSystemBackend(c, c.logger.WithSystem("ns_system"))
	}

	// Check if backend is nil (shouldn't happen in normal operation, but handle it for safety)
	if backend == nil {
		return nil, fmt.Errorf("nil backend returned for %s type %s", entry.Class, entry.Type)
	}

	// Only update entry.Config if it's currently empty (i.e., when first creating the mount)
	// When loading from storage, entry.Config already contains the persisted configuration
	// and should not be overwritten with the backend's initial empty config
	entry.configMu.Lock()
	defer entry.configMu.Unlock()
	if len(entry.Config) == 0 {
		entry.Config = map[string]any{}
		maps.Copy(entry.Config, backend.Config())
	}
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

func (c *Core) unmountInternal(ctx context.Context, path string, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Verify exact match of the route
	checkMatch := func(p string) bool {
		match := c.router.MatchingMount(ctx, p)
		return match != "" && ns.Path+p == match
	}

	// first check provider match
	if !checkMatch(path) {
		// try auth match instead
		path = authRoutePrefix + path
		if !checkMatch(path) {
			return logical.ErrNotFoundf("no mount found at path %q", strings.TrimPrefix(path, authRoutePrefix))
		}
	}

	// Get the view for this backend
	view := c.router.MatchingStorageByAPIPath(ctx, path)
	if view == nil {
		return fmt.Errorf("no matching storage %q", path)
	}

	// Get the backend/mount entry for this path, used to remove ignored
	// replication prefixes
	backend := c.router.MatchingBackend(ctx, path)

	// Mark the entry as tainted
	if err := c.taintMountEntry(ctx, ns.ID, strings.TrimPrefix(path, authRoutePrefix), updateStorage, true); err != nil {
		c.logger.Error("failed to taint mount entry for path being unmounted",
			logger.Err(err),
			logger.String("namespace", ns.Path),
			logger.String("path", path),
		)
		return err
	}

	// Taint the router path to prevent routing. Note that in-flight requests
	// are uncertain, right now.
	if err := c.router.Taint(ctx, path); err != nil {
		return err
	}

	revokeCtx := namespace.ContextWithNamespace(c.activeContext, ns)

	if backend != nil {
		// Call cleanup function if it exists
		backend.Cleanup(revokeCtx)
	}

	// Remove the mount table entry
	if err := c.removeMountEntry(ctx, strings.TrimPrefix(path, authRoutePrefix), updateStorage); err != nil {
		c.logger.Error("failed to remove mount entry for path being unmounted",
			logger.Err(err),
			logger.String("path", path),
		)
		return err
	}

	// Unmount the backend entirely
	if err := c.router.Unmount(revokeCtx, path); err != nil {
		return err
	}

	c.logger.Info("successfully unmounted",
		logger.String("path", path),
	)

	return nil

}

// taintMountEntry is used to mark an entry in the mount table as tainted
func (c *Core) taintMountEntry(ctx context.Context, nsID, mountPath string, updateStorage bool, unmounting bool) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	mountState := ""
	if unmounting {
		mountState = mountStateUnmounting
	}

	// As modifying the taint of an entry affects shallow clones,
	// we simply use the original
	entry, err := c.mounts.setTaint(nsID, mountPath, true, mountState)
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
		if err := c.persistMounts(ctx, nil, c.mounts, entry.UUID); err != nil {
			c.logger.Error("failed to taint entry in mounts table", logger.Err(err))
			return logical.ErrInternal("failed to taint entry in mounts table")
		}
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
		if err := c.persistMounts(ctx, nil, newTable, entry.UUID); err != nil {
			c.logger.Error("failed to remove entry from mounts table", logger.Err(err))
			return logical.ErrInternal("failed to remove entry from mounts table")
		}
	}

	c.mounts = newTable
	return nil
}

// From an input path that has a relative namespace hierarchy followed by a mount point, return the full
// namespace of the mount point, along with the mount point without the namespace related prefix.
// For example, in a hierarchy ns1/ns2/ns3/secret-mount, when currNs is ns1 and path is ns2/ns3/secret-mount,
// this returns the namespace object for ns1/ns2/ns3/, and the string "secret-mount"
func (c *Core) splitNamespaceAndMountFromPath(currNs, path string) namespace.MountPathDetails {
	fullPath := currNs + path
	ns, mountPath := c.namespaceStore.GetNamespaceByLongestPrefix(namespace.RootContext(context.TODO()), fullPath)

	return namespace.MountPathDetails{
		Namespace: ns,
		MountPath: sanitizePath(mountPath),
	}
}

func sanitizePath(path string) string {
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	path = strings.TrimPrefix(path, "/")

	return path
}

// loadMounts is invoked as part of postUnseal to load the mount table
func (c *Core) loadMounts(ctx context.Context) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	// Start with an empty mount table.
	c.mounts = nil

	if txnableBarrier, ok := c.barrier.(sdklogical.TransactionalStorage); ok {
		txn, err := txnableBarrier.BeginTx(ctx)
		if err != nil {
			return err
		}
		defer txn.Rollback(ctx)

		c.logger.Info("reading mount table")
		if err := c.loadTransactionalMounts(ctx, txn); err != nil {
			return fmt.Errorf("failed to load mount table: %w", err)
		}

		// Finally, persist our changes.
		if err := txn.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit mount table changes: %w", err)
		}

		return nil
	}

	return fmt.Errorf("failed to create a read transation on the barrier")
}

// this function reads the mount table.
func (c *Core) loadTransactionalMounts(ctx context.Context, barrier sdklogical.Storage) error {
	allNamespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	var needPersist bool
	mountEntries := make(map[string][]string, len(allNamespaces))
	for index, ns := range allNamespaces {
		if ns.Tainted {
			c.logger.Info("skipping loading mounts for tainted namespace", logger.String("ns", ns.ID))
			continue
		}

		view := NamespaceView(barrier, ns)
		mountsListed, err := listTransactionalMountsForNamespace(ctx, view)
		if err != nil {
			c.logger.Error("failed to list mounts for namespace", logger.Err(err), logger.Int("ns_index", index), logger.String("namespace", ns.ID))
			return err
		}

		if len(mountsListed) > 0 {
			mountEntries[ns.ID] = mountsListed
		}
	}

	if len(mountEntries) == 0 {
		c.logger.Info("no mounts in mount table; adding default mount table")
		c.mounts = c.defaultMountTable(ctx)
		needPersist = true
	} else {
		c.mounts = &MountTable{}

		for nsIndex, ns := range allNamespaces {
			view := NamespaceView(barrier, ns)
			for index, uuid := range mountEntries[ns.ID] {
				entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreMountConfigPath, uuid)
				if err != nil {
					return fmt.Errorf("error loading mount table entry (%v (%v)/%v/%v): %w", ns.ID, nsIndex, index, uuid, err)
				}

				if entry != nil {
					c.mounts.Entries = append(c.mounts.Entries, entry)
				}
			}
		}
	}

	err = c.runMountUpdates(ctx, barrier, needPersist)
	if err != nil {
		c.logger.Error("failed to run legacy mount table upgrades", logger.Err(err))
		return err
	}

	return nil
}

// Note that this is only designed to work with singletons, as it checks by
// type only.
func (c *Core) runMountUpdates(ctx context.Context, barrier sdklogical.Storage, needPersist bool) error {

	requiredMounts, err := c.requiredMountTable(ctx)
	if err != nil {
		panic(err.Error())
	}
	for _, requiredMount := range requiredMounts.Entries {
		foundRequired := false
		for _, coreMount := range c.mounts.Entries {
			if coreMount.Type == requiredMount.Type {
				foundRequired = true
				coreMount.Config = requiredMount.Config

				break
			}
		}

		// In a replication scenario we will let sync invalidation take
		// care of creating a new required mount that doesn't exist yet.
		// This should only happen in the upgrade case where a new one is
		// introduced on the primary; otherwise initial bootstrapping will
		// ensure this comes over. If we upgrade first, we simply don't
		// create the mount, so we won't conflict when we sync. If this is
		// local (e.g. cubbyhole) we do still add it.
		if !foundRequired {
			c.mounts.Entries = append(c.mounts.Entries, requiredMount)
			needPersist = true
		}
	}

	// Upgrade to table-scoped entries
	for _, entry := range c.mounts.Entries {
		if entry.Accessor == "" {
			accessor, err := c.generateMountAccessor(entry.Type)
			if err != nil {
				return err
			}
			entry.Accessor = accessor
			needPersist = true
		}
		if entry.BackendAwareUUID == "" {
			bUUID, err := uuid.GenerateUUID()
			if err != nil {
				return err
			}
			entry.BackendAwareUUID = bUUID
			needPersist = true
		}

		if entry.NamespaceID == "" {
			entry.NamespaceID = namespace.RootNamespaceID
			needPersist = true
		}

		ns, err := c.NamespaceByID(ctx, entry.NamespaceID)
		if err != nil {
			return err
		}
		if ns == nil {
			return namespace.ErrNoNamespace
		}
		entry.namespace = ns
	}
	// Done if we have restored the mount table and we don't need
	// to persist
	if !needPersist {
		return nil
	}

	if err := c.persistMounts(ctx, barrier, c.mounts, ""); err != nil {
		c.logger.Error("failed to persist mount table", logger.Err(err))
		return errLoadMountsFailed
	}
	return nil
}

func listTransactionalMountsForNamespace(ctx context.Context, barrier sdklogical.Storage) ([]string, error) {
	globalEntries, err := barrier.List(ctx, coreMountConfigPath+"/")
	if err != nil {
		return nil, fmt.Errorf("failed listing core mounts: %w", err)
	}

	return globalEntries, nil
}

// defaultMountTable creates a default mount table
func (c *Core) defaultMountTable(ctx context.Context) *MountTable {
	table := &MountTable{}

	requiredMounts, err := c.requiredMountTable(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to create required mounts: %v", err))
	}
	table.Entries = append(table.Entries, requiredMounts.Entries...)

	return table
}

// requiredMountTable() creates a mount table with entries required
// to be available
func (c *Core) requiredMountTable(ctx context.Context) (*MountTable, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil && !errors.Is(err, namespace.ErrNoNamespace) {
		return nil, err
	}
	if ns == nil {
		ns = namespace.RootNamespace
	}

	table := &MountTable{}

	sysUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create sys UUID: %w", err)
	}
	sysAccessor, err := c.generateMountAccessor("system")
	if err != nil {
		return nil, fmt.Errorf("could not generate sys accessor: %w", err)
	}
	sysBackendUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create sys backend UUID: %w", err)
	}
	sysMount := &MountEntry{
		Class:            mountClassSystem,
		Path:             "sys/",
		Type:             mountClassSystem,
		Description:      "system endpoints used for control, policy and debugging",
		UUID:             sysUUID,
		Accessor:         sysAccessor,
		BackendAwareUUID: sysBackendUUID,
		SealWrap:         true, // Enable SealWrap since SystemBackend utilizes SealWrapStorage
		NamespaceID:      ns.ID,
		namespace:        ns,
	}

	if ns.ID != namespace.RootNamespaceID {
		sysMount.Class = mountClassNSSystem
		sysMount.Type = mountClassNSSystem
	}

	table.Entries = append(table.Entries, sysMount)

	return table, nil
}

func (c *Core) fetchAndDecodeMountTableEntry(ctx context.Context, barrier sdklogical.Storage, prefix string, uuid string) (*MountEntry, error) {
	path := path.Join(prefix, uuid)
	sEntry, err := barrier.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if sEntry == nil {
		return nil, errors.New("unexpected empty storage entry for mount")
	}

	entry := new(MountEntry)
	if err := jsonutil.DecodeJSON(sEntry.Value, entry); err != nil {
		return nil, err
	}

	if entry.UUID == "" {
		entry.UUID = uuid
	} else if entry.UUID != uuid {
		return nil, fmt.Errorf("mismatch between mount entry uuid in path (%v) and value (%v)", uuid, entry.UUID)
	}

	if entry.NamespaceID == "" {
		entry.NamespaceID = namespace.RootNamespaceID
	}
	ns, err := c.NamespaceByID(ctx, entry.NamespaceID)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		c.logger.Error("namespace on mount entry not found",
			logger.String("table", prefix),
			logger.String("uuid", uuid),
			logger.String("namespace_id", entry.NamespaceID),
			logger.String("mount_path", entry.Path),
			logger.String("mount_description", entry.Description))
		return nil, nil
	}

	entry.namespace = ns

	return entry, nil
}

// setupMounts is invoked after we've loaded the mount table to
// initialize the logical backends and setup the router
func (c *Core) setupMounts(ctx context.Context) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	for _, entry := range c.mounts.sortEntriesByPathDepth().Entries {
		// Initialize the backend, special casing for system
		view, err := c.mountEntryView(entry)
		if err != nil {
			return err
		}

		origReadOnlyErr := view.GetReadOnlyErr()

		// Mark the view as read-only until the mounting is complete and
		// ensure that it is reset after. This ensures that there will be no
		// writes during the construction of the backend.
		view.SetReadOnlyErr(sdklogical.ErrSetupReadOnly)
		if slices.Contains(singletonMounts, entry.Type) {
			defer view.SetReadOnlyErr(origReadOnlyErr)
		}

		// Create the new backend
		var backend logical.Backend
		backend, err = c.newLogicalBackend(ctx, entry, view)
		if err != nil {
			c.logger.Error("failed to create mount entry", logger.String("path", entry.Path), logger.Err(err))
			return errLoadMountsFailed
		}
		if backend == nil {
			return fmt.Errorf("created mount entry of type %q is nil", entry.Type)
		}

		c.setCoreBackend(entry, backend, view)

		mountPath := entry.Path
		if entry.Class == mountClassAuth {
			mountPath = authRoutePrefix + mountPath
		}

		// Mount the backend
		err = c.router.Mount(mountPath, backend, entry, view)
		if err != nil {
			c.logger.Error("failed to mount entry", logger.String("path", mountPath), logger.Err(err))
			return errLoadMountsFailed
		}

		// Bind locally
		localEntry := entry
		c.postUnsealFuncs = append(c.postUnsealFuncs, func() {
			postUnsealLogger := c.logger.WithFields(logger.String("type", localEntry.Type)).WithFields(logger.String("path", mountPath))
			if backend == nil {
				postUnsealLogger.Error("skipping initialization for nil backend", logger.String("path", mountPath))
				return
			}
			if !slices.Contains(singletonMounts, localEntry.Type) {
				view.SetReadOnlyErr(origReadOnlyErr)
			}

			nsCtx := namespace.ContextWithNamespace(ctx, localEntry.namespace)
			err := backend.Initialize(nsCtx)
			if err != nil {
				postUnsealLogger.Error("failed to initialize mount backend", logger.Err(err))
			}
		})

		c.logger.Info("successfully mounted", logger.String("type", entry.Type), logger.String("path", entry.Path), logger.String("namespace", entry.Namespace().Path))

		// Ensure the path is tainted if set in the mount table
		if entry.Tainted {
			// Calculate any namespace prefixes here, because when Taint() is called, there won't be
			// a namespace to pull from the context. This is similar to what we do above in c.router.Mount().
			path := entry.Namespace().Path + mountPath
			c.logger.Debug("tainting a mount due to it being marked as tainted in mount table", logger.String("entry.path", mountPath), logger.String("entry.namespace.path", entry.Namespace().Path), logger.String("full_path", path))
			c.router.Taint(ctx, path)
		}
	}
	return nil
}

// unloadMounts is used before we seal the vault to reset the mounts to
// their unloaded state, calling Cleanup if defined. This is reversed by load and setup mounts.
func (c *Core) unloadMounts(ctx context.Context) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	if c.mounts != nil {
		mountTable := c.mounts.shallowClone()
		for _, e := range mountTable.Entries {
			mountPath := e.Path
			if e.Class == mountClassAuth {
				mountPath = authRoutePrefix + mountPath
			}
			backend := c.router.MatchingBackend(namespace.ContextWithNamespace(ctx, e.namespace), mountPath)
			if backend != nil {
				backend.Cleanup(ctx)
			}
		}
	}

	c.mounts = nil
	c.router.reset()
	c.systemBarrierView = nil
	return nil
}

func (c *Core) setCoreBackend(entry *MountEntry, backend logical.Backend, view BarrierView) {
	switch entry.Class {
	case mountClassSystem:
		c.systemBackend = backend.(*SystemBackend)
		c.systemBarrierView = view
	}
}

// mountEntryView returns the barrier view object with prefix depending on the mount entry class and namespace
func (c *Core) mountEntryView(me *MountEntry) (BarrierView, error) {
	if me.Namespace() != nil && me.Namespace().ID != me.NamespaceID {
		return nil, errors.New("invalid namespace")
	}

	switch me.Class {
	case mountClassSystem, mountClassNSSystem:
		if me.Namespace() != nil && me.NamespaceID != namespace.RootNamespaceID {
			return c.namespaceMountEntryView(me.Namespace(), systemBarrierPrefix), nil
		}
		return NewBarrierView(c.barrier, systemBarrierPrefix), nil
	case mountClassProvider:
		if me.Namespace() != nil && me.NamespaceID != namespace.RootNamespaceID {
			return c.namespaceMountEntryView(me.Namespace(), providerBarrierPrefix+me.UUID+"/"), nil
		}
		return NewBarrierView(c.barrier, providerBarrierPrefix+me.UUID+"/"), nil
	case mountClassAuth:
		if me.Namespace() != nil && me.NamespaceID != namespace.RootNamespaceID {
			return c.namespaceMountEntryView(me.Namespace(), authBarrierPrefix+me.UUID+"/"), nil
		}
		return NewBarrierView(c.barrier, authBarrierPrefix+me.UUID+"/"), nil
	case mountClassAudit:
		return NewBarrierView(c.barrier, auditBarrierPrefix+me.UUID+"/"), nil
	}

	return nil, errors.New("invalid mount entry")
}

func (c *Core) namespaceMountEntryView(namespace *namespace.Namespace, prefix string) BarrierView {
	return NamespaceView(c.barrier, namespace).SubView(prefix)
}

// persistMounts is used to persist the mount table after modification.
func (c *Core) persistMounts(ctx context.Context, barrier sdklogical.Storage, table *MountTable, mount string) error {
	// Sometimes we may not want to explicitly pass barrier; fetch it if
	// necessary.
	if barrier == nil {
		barrier = c.barrier
	}

	// Gracefully handle a transaction-aware backend, if a transaction
	// wasn't created for us. This is safe as we do not support nested
	// transactions.
	needTxnCommit := false
	if txnBarrier, ok := barrier.(sdklogical.TransactionalStorage); ok {
		var err error
		barrier, err = txnBarrier.BeginTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction to persist mounts: %w", err)
		}

		needTxnCommit = true

		// In the event of an unexpected error, rollback this transaction.
		// A rollback of a committed transaction does not impact the commit.
		defer barrier.(sdklogical.Transaction).Rollback(ctx) //nolint:errcheck
	}

	mounts := &MountTable{}

	for _, entry := range table.Entries {
		mounts.Entries = append(mounts.Entries, entry)
	}

	var writeTable func(mt *MountTable, path string) (int, error)

	if _, ok := barrier.(sdklogical.Transaction); ok {
		writeTable = func(mt *MountTable, prefix string) (int, error) {
			var size int
			var found bool
			currentEntries := make(map[string]struct{}, len(mt.Entries))
			for index, mtEntry := range mt.Entries {
				if mount != "" && mtEntry.UUID != mount {
					continue
				}

				view := NamespaceView(barrier, mtEntry.Namespace())

				found = true
				currentEntries[mtEntry.UUID] = struct{}{}

				// Encode the mount table entry into JSON. There is little value in
				// compressing short entries.
				path := path.Join(prefix, mtEntry.UUID)
				encoded, err := jsonutil.EncodeJSON(mtEntry)
				if err != nil {
					c.logger.Error(
						"failed to encode mount table entry",
						logger.Int("index", index),
						logger.String("uuid", mtEntry.UUID),
						logger.Err(err),
					)
					return -1, err
				}

				// Create a storage entry.
				sEntry := &sdklogical.StorageEntry{
					Key:   path,
					Value: encoded,
				}

				// Write to the backend.
				if err := view.Put(ctx, sEntry); err != nil {
					c.logger.Error(
						"failed to persist mount table entry",
						logger.Int("index", index),
						logger.String("uuid", mtEntry.UUID),
						logger.Err(err),
					)
					return -1, err
				}

				size += len(encoded)
			}

			if mount != "" && !found {
				// Delete this component if it exists. This signifies that
				// we're removing this mount. We don't know which namespace
				// this entry could belong to, so remove it from all.
				allNamespaces, err := c.ListNamespaces(ctx)
				if err != nil {
					return -1, fmt.Errorf("failed to list namespaces: %w", err)
				}

				for nsIndex, ns := range allNamespaces {
					view := NamespaceView(barrier, ns)
					path := path.Join(prefix, mount)
					if err := view.Delete(ctx, path); err != nil {
						return -1, fmt.Errorf("requested removal of a mount from namespace %v (%v) but failed: %w", ns.ID, nsIndex, err)
					}
				}
			}

			if mount == "" {
				allNamespaces, err := c.ListNamespaces(ctx)
				if err != nil {
					return -1, fmt.Errorf("failed to list namespaces: %w", err)
				}

				for nsIndex, ns := range allNamespaces {
					view := NamespaceView(barrier, ns)

					// List all entries and remove any deleted ones.
					presentEntries, err := view.List(ctx, prefix+"/")
					if err != nil {
						return -1, fmt.Errorf("failed to list mount entries in namespace %v (%v) for removal: %w", ns.ID, nsIndex, err)
					}

					for index, presentEntry := range presentEntries {
						if _, present := currentEntries[presentEntry]; present {
							continue
						}

						if err := view.Delete(ctx, prefix+"/"+presentEntry); err != nil {
							return -1, fmt.Errorf("failed to remove deleted mount %v (%v) in namespace %v (%v): %w", presentEntry, index, ns.ID, nsIndex, err)
						}
					}
				}
			}

			// Finally, delete the legacy entries, if any.
			if err := barrier.Delete(ctx, prefix); err != nil {
				return -1, err
			}

			return size, nil
		}
	} else {
		return fmt.Errorf("failed to create storage transation")
	}

	_, err := writeTable(mounts, coreMountConfigPath)
	if err != nil {
		return err
	}

	if needTxnCommit {
		if err := barrier.(sdklogical.Transaction).Commit(ctx); err != nil {
			return fmt.Errorf("failed to persist mounts inside transaction: %w", err)
		}
	}

	return nil
}
