package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/audit"
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

// loadAudits is invoked as part of postUnseal to load the audit table from storage
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
		// Decode the stored audit table
		if err := jsonutil.DecodeJSON(raw.Value, c.audit); err != nil {
			c.logger.Error("failed to decode audit table", logger.Err(err))
			return fmt.Errorf("failed to decode audit table: %w", err)
		}

		c.logger.Info("loaded audit table from storage", logger.Int("count", len(c.audit.Entries)))

		// Re-create and register all audit backends
		for _, entry := range c.audit.Entries {
			// Audit devices are only supported in the root namespace
			entry.NamespaceID = namespace.RootNamespaceID
			entry.namespace = namespace.RootNamespace

			backend, err := c.newAuditBackend(ctx, entry)
			if err != nil {
				c.logger.Error("failed to create audit backend during load",
					logger.String("path", entry.Path),
					logger.String("type", entry.Type),
					logger.Err(err),
				)
				return fmt.Errorf("failed to create audit backend %s: %w", entry.Path, err)
			}

			if backend != nil {
				c.auditManager.RegisterDevice(entry.Path, backend)
				c.logger.Info("registered audit device",
					logger.String("path", entry.Path),
					logger.String("type", entry.Type),
				)
			}
		}

		return nil
	}

	// No stored audit table - create default file audit device
	c.logger.Info("no audit table in storage; creating default audit device")

	// Generate a secure HMAC salt for the default device
	salt, err := generateAuditHMACSalt()
	if err != nil {
		return fmt.Errorf("failed to generate HMAC salt for default audit device: %w", err)
	}

	defaultEntry := &MountEntry{
		Class:       mountClassAudit,
		Type:        "file",
		Path:        "file/",
		Description: "default file audit device",
		Config: map[string]any{
			"file_path": "warden-audit.log",
			"hmac_key":  salt,
		},
	}

	// Audit devices are only supported in the root namespace
	defaultEntry.NamespaceID = namespace.RootNamespaceID
	defaultEntry.namespace = namespace.RootNamespace

	// Generate accessor
	accessor, err := c.generateMountAccessor("audit_file")
	if err != nil {
		return fmt.Errorf("failed to generate accessor for default audit device: %w", err)
	}
	defaultEntry.Accessor = accessor

	// Create the backend
	backend, err := c.newAuditBackend(ctx, defaultEntry)
	if err != nil {
		return fmt.Errorf("failed to create default audit backend: %w", err)
	}
	if backend == nil {
		return errors.New("nil backend returned for default audit device")
	}

	// Test the device
	if err := backend.LogTestRequest(ctx); err != nil {
		c.logger.Error("default audit backend failed test", logger.Err(err))
		return fmt.Errorf("default audit device failed test: %w", err)
	}

	// Add to table and register
	c.audit.Entries = append(c.audit.Entries, defaultEntry)
	c.auditManager.RegisterDevice(defaultEntry.Path, backend)

	// Persist the new table
	if err := c.persistAuditsLocked(ctx); err != nil {
		return fmt.Errorf("failed to persist default audit table: %w", err)
	}

	c.logger.Info("created and persisted default audit device",
		logger.String("path", defaultEntry.Path),
		logger.String("type", defaultEntry.Type),
	)

	return nil
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
