package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

const (
	// coreAuditConfigPath is used to store the audit configuration.
	// Audit configuration is protected within the Vault itself, which means it
	// can only be viewed or modified after an unseal.
	coreAuditConfigPath = "core/audit"

	// auditBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the audit backends.
	auditBarrierPrefix = "audit/"
)

// generateAuditHMACSalt generates a cryptographically secure random salt for HMAC operations.
// Returns a 32-byte hex-encoded string.
func generateAuditHMACSalt() (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate HMAC salt: %w", err)
	}
	return hex.EncodeToString(salt), nil
}

// normalizeAuditPath returns the path with a trailing slash, matching the
// router convention used elsewhere for audit mount paths.
func normalizeAuditPath(p string) string {
	if !strings.HasSuffix(p, "/") {
		return p + "/"
	}
	return p
}

// loadAudits is invoked as part of postUnseal. It loads any persisted audit
// table from storage, then reconciles it against the HCL-declared audit
// devices (c.auditConfigDeclarations):
//
//   - HCL-declared (Declarative=true) and API-enabled (Declarative=false)
//     entries coexist at different paths.
//   - HCL adds: register, persist with Declarative=true.
//   - HCL updates an existing Declarative entry: refresh Description/Config,
//     re-register, persist. Accessor, UUID and HMAC salt are preserved.
//   - HCL drops a previously-declared Declarative entry: disable, remove
//     from storage.
//   - HCL declares a path that collides with an API-enabled entry: refuse
//     to start.
func (c *Core) loadAudits(ctx context.Context) error {
	c.auditLock.Lock()
	defer c.auditLock.Unlock()

	// Try to load audit table from storage
	raw, err := c.barrier.Get(ctx, coreAuditConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read audit table: %w", err)
	}

	c.audit = NewMountTable()
	if raw != nil {
		if err := jsonutil.DecodeJSON(raw.Value, c.audit); err != nil {
			c.logger.Error("failed to decode audit table", logger.Err(err))
			return fmt.Errorf("failed to decode audit table: %w", err)
		}
		c.logger.Info("loaded audit table from storage", logger.Int("count", len(c.audit.Entries)))
	}

	// Index stored entries by path so the reconcile can do O(1) lookups.
	stored := make(map[string]*MountEntry, len(c.audit.Entries))
	for _, entry := range c.audit.Entries {
		entry.NamespaceID = namespace.RootNamespaceID
		entry.namespace = namespace.RootNamespace
		stored[entry.Path] = entry
	}

	// Reconcile HCL declarations against stored entries.
	declaredPaths := make(map[string]struct{}, len(c.auditConfigDeclarations))
	tableMutated := false
	for _, decl := range c.auditConfigDeclarations {
		path := normalizeAuditPath(decl.Path)
		declaredPaths[path] = struct{}{}

		existing, ok := stored[path]
		switch {
		case !ok:
			// New HCL device: assign accessor + HMAC salt, persist.
			entry, err := c.buildConfigAuditEntry(decl, path)
			if err != nil {
				return fmt.Errorf("audit %q: %w", path, err)
			}
			c.audit.Entries = append(c.audit.Entries, entry)
			stored[path] = entry
			tableMutated = true
			c.logger.Info("registering new HCL-declared audit device",
				logger.String("path", path),
				logger.String("type", entry.Type),
			)

		case !existing.Declarative:
			// API-created device already lives here. Refuse to come up
			// rather than silently overwrite operator state.
			return fmt.Errorf("audit %q: HCL declaration collides with an API-enabled device at the same path; rename one or remove the other", path)

		default:
			// Existing HCL device: refresh mutable fields, keep accessor/salt/UUID stable.
			if existing.Type != decl.Type {
				return fmt.Errorf("audit %q: HCL type changed (%q → %q); rename the path to migrate", path, existing.Type, decl.Type)
			}
			newConfig := mergeAuditConfig(decl.Config, existing.Config)
			if existing.Description != decl.Description || !auditConfigEqual(existing.Config, newConfig) {
				existing.Description = decl.Description
				existing.Config = newConfig
				tableMutated = true
				c.logger.Info("refreshing HCL-declared audit device",
					logger.String("path", path),
				)
			}
		}
	}

	// Drop Declarative entries no longer present in the HCL.
	if len(c.audit.Entries) > 0 {
		kept := c.audit.Entries[:0]
		for _, entry := range c.audit.Entries {
			if entry.Declarative {
				if _, stillDeclared := declaredPaths[entry.Path]; !stillDeclared {
					c.logger.Info("removing HCL-declared audit device no longer in config",
						logger.String("path", entry.Path),
					)
					tableMutated = true
					continue
				}
			}
			kept = append(kept, entry)
		}
		c.audit.Entries = kept
	}

	// Register every surviving entry with the audit manager. Backend
	// creation failure is fatal — for HCL devices the operator opted in
	// and silent skips would hide breakage; for API devices the entry was
	// persisted while it worked, so a reload failure indicates real drift.
	for _, entry := range c.audit.Entries {
		backend, err := c.newAuditBackend(ctx, entry)
		if err != nil {
			c.logger.Error("failed to create audit backend during load",
				logger.String("path", entry.Path),
				logger.String("type", entry.Type),
				logger.Err(err),
			)
			return fmt.Errorf("failed to create audit backend %s: %w", entry.Path, err)
		}
		if backend == nil {
			return fmt.Errorf("nil backend returned for audit device %q", entry.Path)
		}

		// Run a probe so a misconfigured sink fails startup rather than
		// the next request. Honour skip_test for tests that don't set up
		// a real fs.
		if entry.Config["skip_test"] != "true" {
			if err := backend.LogTestRequest(ctx); err != nil {
				return fmt.Errorf("audit device %q failed test message: %w", entry.Path, err)
			}
		}

		c.auditManager.RegisterDevice(entry.Path, backend)
		c.logger.Info("registered audit device",
			logger.String("path", entry.Path),
			logger.String("type", entry.Type),
			logger.String("origin", auditOriginLabel(entry)),
		)
	}

	if tableMutated {
		if err := c.persistAuditsLocked(ctx); err != nil {
			return fmt.Errorf("failed to persist audit table: %w", err)
		}
	}

	return nil
}

// buildConfigAuditEntry promotes a CoreConfig declaration into a full
// MountEntry — assigns a stable accessor and generates an HMAC salt if the
// operator didn't supply one. Called only the first time an HCL device
// appears (subsequent reconciles keep the existing entry's accessor/salt).
func (c *Core) buildConfigAuditEntry(decl *MountEntry, normalizedPath string) (*MountEntry, error) {
	cfg := make(map[string]any, len(decl.Config)+1)
	for k, v := range decl.Config {
		cfg[k] = v
	}
	if _, ok := cfg["hmac_key"]; !ok {
		salt, err := generateAuditHMACSalt()
		if err != nil {
			return nil, fmt.Errorf("generate HMAC salt: %w", err)
		}
		cfg["hmac_key"] = salt
	}
	accessor, err := c.generateMountAccessor("audit_" + decl.Type)
	if err != nil {
		return nil, fmt.Errorf("generate accessor: %w", err)
	}
	return &MountEntry{
		Class:       mountClassAudit,
		Type:        decl.Type,
		Path:        normalizedPath,
		Description: decl.Description,
		Accessor:    accessor,
		Config:      cfg,
		Declarative:  true,
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}, nil
}

// mergeAuditConfig takes the new HCL-declared options and the previously-
// stored config, returning a fresh map that preserves the generated
// hmac_key from the stored config (so audit-log HMACs stay stable across
// restarts) but otherwise reflects the HCL values.
func mergeAuditConfig(declared, stored map[string]any) map[string]any {
	out := make(map[string]any, len(declared)+1)
	for k, v := range declared {
		out[k] = v
	}
	if _, ok := out["hmac_key"]; !ok {
		if salt, hadSalt := stored["hmac_key"]; hadSalt {
			out["hmac_key"] = salt
		}
	}
	return out
}

// auditConfigEqual compares two audit Config maps for equality. Used by
// the reconcile to decide whether persisted state has drifted from HCL.
// Safe because AuditBlock.Options is map[string]string, so HCL-sourced
// values arrive as strings on both sides of the compare; if a future
// code path stores typed values (int rotate_size, bool rotate_daily),
// this needs a proper deep-equal that respects types.
func auditConfigEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if fmt.Sprint(va) != fmt.Sprint(vb) {
			return false
		}
	}
	return true
}

func auditOriginLabel(entry *MountEntry) string {
	if entry.Declarative {
		return "config"
	}
	return "api"
}

// persistAudits saves the audit table to storage
func (c *Core) persistAudits(ctx context.Context) error {
	c.auditLock.Lock()
	defer c.auditLock.Unlock()
	return c.persistAuditsLocked(ctx)
}

// persistAuditsLocked saves the audit table to storage (caller must hold auditLock)
func (c *Core) persistAuditsLocked(ctx context.Context) error {
	// Encode the audit table
	encoded, err := jsonutil.EncodeJSON(c.audit)
	if err != nil {
		return fmt.Errorf("failed to encode audit table: %w", err)
	}

	// Create storage entry
	entry := &sdklogical.StorageEntry{
		Key:   coreAuditConfigPath,
		Value: encoded,
	}

	// Write to storage
	if err := c.barrier.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to persist audit table: %w", err)
	}

	c.logger.Debug("persisted audit table", logger.Int("count", len(c.audit.Entries)))
	return nil
}

func (c *Core) teardownAudits(ctx context.Context) error {
	// Reset the audit mount table to empty instead of nil to avoid
	// nil pointer dereference when loadAudits is called during next unseal
	c.audit = NewMountTable()
	return c.auditManager.Reset(ctx)
}

// EnableAudit is used to enable a new audit backend
func (c *Core) EnableAudit(ctx context.Context, entry *MountEntry, updateStorage bool) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Ensure there is a name
	if entry.Path == "/" {
		return logical.ErrBadRequest("backend path must be specified")
	}

	// Audit devices are only supported in the root namespace
	entry.NamespaceID = namespace.RootNamespaceID
	entry.namespace = namespace.RootNamespace

	// Update the audit table
	c.auditLock.Lock()
	defer c.auditLock.Unlock()

	// Look for matching name
	for _, ent := range c.audit.Entries {
		switch {
		// Existing is sql/mysql/ new is sql/ or
		// existing is sql/ and new is sql/mysql/
		case strings.HasPrefix(ent.Path, entry.Path):
			fallthrough
		case strings.HasPrefix(entry.Path, ent.Path):
			if ent.Declarative {
				return logical.ErrBadRequest(fmt.Sprintf("path %q is owned by an HCL audit declaration; edit the server config and restart instead", ent.Path))
			}
			return logical.ErrBadRequest("path already in use")
		}
	}

	if entry.Accessor == "" {
		accessor, err := c.generateMountAccessor("audit_" + entry.Type)
		if err != nil {
			return err
		}
		entry.Accessor = accessor
	}

	var backend audit.Device
	var err error
	backend, err = c.newAuditBackend(ctx, entry)
	if err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("nil backend of type %s returned from creation function", entry.Type)
	}

	if entry.Config["skip_test"] != "true" {
		// Test the new audit device and report failure if it doesn't work.
		err = backend.LogTestRequest(ctx)
		if err != nil {
			c.logger.Error("new audit backend failed test",
				logger.String("path", entry.Path),
				logger.String("type", entry.Type),
				logger.Err(err),
			)
			return fmt.Errorf("audit device failed test message: %w", err)

		}
	}

	newTable := c.audit.shallowClone()
	newTable.Entries = append(newTable.Entries, entry)
	c.audit = newTable

	if updateStorage {
		if err := c.persistAuditsLocked(ctx); err != nil {
			c.logger.Error("failed to persist audit table after enable", logger.Err(err))
			return fmt.Errorf("failed to persist audit table: %w", err)
		}
	}

	// Register the backend
	c.auditManager.RegisterDevice(entry.Path, backend)

	c.logger.Info("audit backend successfully enabled",
		logger.String("path", entry.Path),
		logger.String("type", entry.Type),
		logger.String("class", entry.Class),
	)

	return nil
}

// newAuditBackend is used to create and configure a new audit device by name.
func (c *Core) newAuditBackend(ctx context.Context, entry *MountEntry) (audit.Device, error) {
	var backend audit.Device
	var err error
	switch entry.Class {
	case mountClassAudit:
		factory := c.auditDevices[entry.Type]
		if factory == nil {
			return nil, logical.ErrBadRequest(fmt.Sprintf("audit device type not supported: %s", entry.Type))
		}
		backend, err = factory.Create(
			ctx,
			entry.Path,
			entry.Description,
			entry.Accessor,
			entry.Config,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create audit device: %w", err)
		}
	}
	return backend, nil
}

// DisableAudit is used to disable an existing audit backend
func (c *Core) DisableAudit(ctx context.Context, path string, updateStorage bool) (bool, error) {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Ensure there is a name
	if path == "/" {
		return false, logical.ErrBadRequest("backend path must be specified")
	}

	// Remove the entry from the mount table
	c.auditLock.Lock()
	defer c.auditLock.Unlock()

	// Reject API disable for HCL-declared devices.
	for _, ent := range c.audit.Entries {
		if ent.Path == path && ent.Declarative {
			return false, logical.ErrBadRequest(fmt.Sprintf("path %q is owned by an HCL audit declaration; remove the block from the server config and restart instead", path))
		}
	}

	newTable := c.audit.shallowClone()
	entry, err := newTable.remove(ctx, path)
	if err != nil {
		return false, err
	}

	// Ensure there was a match
	if entry == nil {
		return false, logical.ErrNotFound("no matching backend")
	}

	// When unmounting all entries the JSON code will load back up from storage
	// as a nil slice, which kills tests...just set it nil explicitly
	if len(newTable.Entries) == 0 {
		newTable.Entries = nil
	}

	c.audit = newTable

	if updateStorage {
		if err := c.persistAuditsLocked(ctx); err != nil {
			c.logger.Error("failed to persist audit table after disable", logger.Err(err))
			return true, fmt.Errorf("failed to persist audit table: %w", err)
		}
	}

	// Unmount the backend
	c.auditManager.UnregisterDevice(path)

	c.logger.Info("audit device successfully disabled",
		logger.String("path", path),
	)

	return true, nil
}
