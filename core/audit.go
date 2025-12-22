package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/logger"
)

// isAuditExempt checks if a request should be allowed even when no audit devices are configured.
// Only bootstrap operations that must work before audit devices are set up are exempted.
func isAuditExempt(req *http.Request) bool {
	// Normalize path to handle both /sys/... and /v1/sys/... formats
	normalizedPath := strings.TrimPrefix(req.URL.Path, "/v1")

	// Only POST /sys/init is exempt - this is the bootstrap operation that happens
	// before audit devices are loaded during post-unseal
	if normalizedPath == "/sys/init" && req.Method == http.MethodPost {
		return true
	}

	// Future: Add other bootstrap operations here as needed
	// Examples:
	// - GET /sys/health (health check before init)
	// - GET /sys/seal-status (check status before init)

	return false
}

func (c *Core) auditRequest(req *http.Request) bool {
	// Read body for logging
	bodyBytes, _ := io.ReadAll(req.Body)

	// Restore body for next handlers
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var data map[string]interface{}
	if len(bodyBytes) > 0 {
		data = map[string]interface{}{
			"body": string(bodyBytes),
		}
	}

	headersCopy := make(http.Header, len(req.Header))
	maps.Copy(headersCopy, req.Header)
	clientIP := req.RemoteAddr
	// Remove port if present
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	entry := audit.LogEntry{
		Type:      string(audit.EntryTypeRequest),
		Timestamp: time.Now(),
		Request: &audit.Request{
			ID:       middleware.GetReqID(req.Context()),
			Method:   req.Method,
			ClientIP: clientIP,
			Path:     req.URL.Path,
			Headers:  headersCopy,
			Data:     data,
		},
	}

	ok, err := c.auditManager.LogRequest(req.Context(), &entry)
	if err != nil {
		c.logger.Error("failed to audit request", logger.Err(err), logger.String("request_id", middleware.GetReqID(req.Context())))
		return false
	}

	// If no audit devices are configured, only allow audit-exempt bootstrap operations
	if !ok {
		if isAuditExempt(req) {
			c.logger.Debug("audit-exempt bootstrap operation, proceeding without audit",
				logger.String("path", req.URL.Path),
				logger.String("method", req.Method),
			)
			return true
		}

		// Non-exempt requests require audit logging
		c.logger.Warn("request blocked: no audit devices configured for non-exempt operation",
			logger.String("path", req.URL.Path),
			logger.String("method", req.Method),
		)
		return false
	}

	return true
}

func (c *Core) LoadAudits(ctx context.Context) error {
	// err := c.EnableAudit(ctx, &MountEntry{
	// 	Class:       "audit",
	// 	Type:        "file",
	// 	Path:        "file-device",
	// 	Description: "file audit device",
	// 	Config: map[string]any{
	// 		"file_path": "/logs/warden-audit.log",
	// 		"hmac_key":  "your-secret-key-here",
	// 	}}, false)
	// if err != nil {
	// 	return err
	// }

	return nil
}

// EnableAudit is used to enable a new audit backend
func (c *Core) EnableAudit(ctx context.Context, entry *MountEntry, updateStorage bool) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Ensure there is a name
	if entry.Path == "/" {
		return errors.New("backend path must be specified")
	}

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
			return errors.New("path already in use")
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
	if updateStorage {

	}

	c.audit = newTable

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
			return nil, fmt.Errorf("audit device type not supported: %s", entry.Type)
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
		return false, errors.New("backend path must be specified")
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
		return false, errors.New("no matching backend")
	}

	// When unmounting all entries the JSON code will load back up from storage
	// as a nil slice, which kills tests...just set it nil explicitly
	if len(newTable.Entries) == 0 {
		newTable.Entries = nil
	}

	if updateStorage {
		// Update the audit table
		// if err := c.persistAudit(ctx, newTable, entry.Local); err != nil {
		// 	return true, errors.New("failed to update audit table")
		// }
	}

	c.audit = newTable

	// Unmount the backend
	c.auditManager.UnregisterDevice(path)

	c.logger.Info("audit device successfully disabled",
		logger.String("path", path),
	)

	return true, nil
}
