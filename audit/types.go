package audit

import (
	"context"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// LogEntry represents a single audit log entry
type LogEntry struct {
	Type      string    `json:"type"`      // "request" or "response"
	Timestamp time.Time `json:"timestamp"`

	// Request information (always present)
	Request *Request `json:"request"`

	// Response information (only for response entries)
	Response *Response `json:"response,omitempty"`

	// Authentication context
	Auth *Auth `json:"auth,omitempty"`

	// Error from the operation (if any)
	Error string `json:"error,omitempty"`
}

// Request contains audit information about the request
type Request struct {
	// Identifiers
	ID        string `json:"id"`        // Request ID
	Operation string `json:"operation"` // create, read, update, delete, list, stream

	// Path information
	Path       string `json:"path"`                   // Full request path
	MountPoint string `json:"mount_point,omitempty"`  // Mount point prefix
	MountType  string `json:"mount_type,omitempty"`   // Backend type (vault, aws, jwt)
	MountClass string `json:"mount_class,omitempty"`  // provider, auth, system, audit

	// HTTP details
	Method   string              `json:"method"`           // GET, POST, PUT, DELETE
	ClientIP string              `json:"client_ip"`
	Headers  map[string][]string `json:"headers,omitempty"`
	Data     map[string]any      `json:"data,omitempty"`

	// Namespace context
	NamespaceID   string `json:"namespace_id,omitempty"`
	NamespacePath string `json:"namespace_path,omitempty"`

	// Flags
	Unauthenticated bool `json:"unauthenticated,omitempty"`
	Streamed        bool `json:"streamed,omitempty"`
	Transparent     bool `json:"transparent,omitempty"`
}

// Response contains audit information about the response
type Response struct {
	// HTTP response
	StatusCode    int                 `json:"status_code"`
	StatusMessage string              `json:"status_message,omitempty"`
	Headers       map[string][]string `json:"headers,omitempty"`
	Data          map[string]any      `json:"data,omitempty"`

	// Mount context (from response)
	MountClass string `json:"mount_class,omitempty"`

	// Flags
	Streamed bool `json:"streamed,omitempty"`

	// Warnings
	Warnings []string `json:"warnings,omitempty"`

	// Credential issued (if any) - for provider requests
	Credential *Credential `json:"credential,omitempty"`

	// Auth result (for login responses)
	AuthResult *AuthResult `json:"auth_result,omitempty"`

	// UpstreamURL is the target URL for proxied streaming requests
	UpstreamURL string `json:"upstream_url,omitempty"`
}

// Auth contains authentication context for the request
type Auth struct {
	// Token information (hash-based ID, safe to log)
	TokenID       string `json:"token_id,omitempty"`
	TokenAccessor string `json:"token_accessor,omitempty"`
	TokenType     string `json:"token_type,omitempty"`

	// Principal/Identity
	PrincipalID string `json:"principal_id,omitempty"`
	RoleName    string `json:"role_name,omitempty"`

	// Policies
	Policies      []string       `json:"policies,omitempty"`
	PolicyResults *PolicyResults `json:"policy_results,omitempty"`

	// Token lifecycle
	TokenTTL  int64 `json:"token_ttl,omitempty"`  // Seconds remaining
	ExpiresAt int64 `json:"expires_at,omitempty"` // Unix timestamp

	// Namespace binding
	NamespaceID   string `json:"namespace_id,omitempty"`
	NamespacePath string `json:"namespace_path,omitempty"`

	// Creation context
	CreatedByIP string `json:"created_by_ip,omitempty"`
}

// PolicyResults captures which policies granted access
type PolicyResults struct {
	Allowed          bool     `json:"allowed"`
	GrantingPolicies []string `json:"granting_policies,omitempty"`
}

// AuthResult contains authentication result from login operations
type AuthResult struct {
	TokenType      string   `json:"token_type"`
	PrincipalID    string   `json:"principal_id"`
	RoleName       string   `json:"role_name"`
	Policies       []string `json:"policies"`
	TokenTTL       int64    `json:"token_ttl"` // Seconds
	CredentialSpec string   `json:"credential_spec,omitempty"`
}

// Credential contains audit information about a credential that was issued
type Credential struct {
	// Identity
	CredentialID string `json:"credential_id"` // UUID

	// Type information
	Type     string `json:"type"`               // aws_access_keys, vault_token, github_token
	Category string `json:"category,omitempty"` // database, cloud_iam, oauth, etc.

	// Lifecycle
	LeaseTTL int64  `json:"lease_ttl,omitempty"` // Seconds (0 for static)
	LeaseID  string `json:"lease_id,omitempty"`  // For revocation tracking
	TokenID  string `json:"token_id"`            // Session token this is bound to

	// Source information
	SourceName string `json:"source_name,omitempty"`
	SourceType string `json:"source_type,omitempty"` // local, hvault, aws
	SpecName   string `json:"spec_name,omitempty"`   // Which spec created this

	// Flags
	Revocable bool `json:"revocable"`

	// Credential data (sensitive - will be HMAC salted by the format layer)
	// Contains the actual credential values like access_key, secret_key, password, etc.
	Data map[string]string `json:"data,omitempty"`
}

// EntryType defines the type of audit entry
type EntryType string

const (
	EntryTypeRequest  EntryType = "request"
	EntryTypeResponse EntryType = "response"
)

// Clone creates a deep copy of the LogEntry to avoid data races
func (e *LogEntry) Clone() *LogEntry {
	if e == nil {
		return nil
	}

	clone := &LogEntry{
		Type:      e.Type,
		Timestamp: e.Timestamp,
		Error:     e.Error,
	}

	// Clone Request
	if e.Request != nil {
		clone.Request = &Request{
			ID:              e.Request.ID,
			Operation:       e.Request.Operation,
			Path:            e.Request.Path,
			MountPoint:      e.Request.MountPoint,
			MountType:       e.Request.MountType,
			MountClass:      e.Request.MountClass,
			Method:          e.Request.Method,
			ClientIP:        e.Request.ClientIP,
			NamespaceID:     e.Request.NamespaceID,
			NamespacePath:   e.Request.NamespacePath,
			Unauthenticated: e.Request.Unauthenticated,
			Streamed:        e.Request.Streamed,
			Transparent:     e.Request.Transparent,
		}
		if e.Request.Headers != nil {
			clone.Request.Headers = cloneHeaders(e.Request.Headers)
		}
		if e.Request.Data != nil {
			clone.Request.Data = cloneMapAny(e.Request.Data)
		}
	}

	// Clone Response
	if e.Response != nil {
		clone.Response = &Response{
			StatusCode:    e.Response.StatusCode,
			StatusMessage: e.Response.StatusMessage,
			MountClass:    e.Response.MountClass,
			Streamed:      e.Response.Streamed,
			UpstreamURL:   e.Response.UpstreamURL,
		}
		if e.Response.Headers != nil {
			clone.Response.Headers = cloneHeaders(e.Response.Headers)
		}
		if e.Response.Data != nil {
			clone.Response.Data = cloneMapAny(e.Response.Data)
		}
		if e.Response.Warnings != nil {
			clone.Response.Warnings = make([]string, len(e.Response.Warnings))
			copy(clone.Response.Warnings, e.Response.Warnings)
		}
		if e.Response.Credential != nil {
			clone.Response.Credential = &Credential{
				CredentialID: e.Response.Credential.CredentialID,
				Type:         e.Response.Credential.Type,
				Category:     e.Response.Credential.Category,
				LeaseTTL:     e.Response.Credential.LeaseTTL,
				LeaseID:      e.Response.Credential.LeaseID,
				TokenID:      e.Response.Credential.TokenID,
				SourceName:   e.Response.Credential.SourceName,
				SourceType:   e.Response.Credential.SourceType,
				SpecName:     e.Response.Credential.SpecName,
				Revocable:    e.Response.Credential.Revocable,
			}
			if e.Response.Credential.Data != nil {
				clone.Response.Credential.Data = make(map[string]string, len(e.Response.Credential.Data))
				for k, v := range e.Response.Credential.Data {
					clone.Response.Credential.Data[k] = v
				}
			}
		}
		if e.Response.AuthResult != nil {
			clone.Response.AuthResult = &AuthResult{
				TokenType:      e.Response.AuthResult.TokenType,
				PrincipalID:    e.Response.AuthResult.PrincipalID,
				RoleName:       e.Response.AuthResult.RoleName,
				TokenTTL:       e.Response.AuthResult.TokenTTL,
				CredentialSpec: e.Response.AuthResult.CredentialSpec,
			}
			if e.Response.AuthResult.Policies != nil {
				clone.Response.AuthResult.Policies = make([]string, len(e.Response.AuthResult.Policies))
				copy(clone.Response.AuthResult.Policies, e.Response.AuthResult.Policies)
			}
		}
	}

	// Clone Auth
	if e.Auth != nil {
		clone.Auth = &Auth{
			TokenID:       e.Auth.TokenID,
			TokenAccessor: e.Auth.TokenAccessor,
			TokenType:     e.Auth.TokenType,
			PrincipalID:   e.Auth.PrincipalID,
			RoleName:      e.Auth.RoleName,
			TokenTTL:      e.Auth.TokenTTL,
			ExpiresAt:     e.Auth.ExpiresAt,
			NamespaceID:   e.Auth.NamespaceID,
			NamespacePath: e.Auth.NamespacePath,
			CreatedByIP:   e.Auth.CreatedByIP,
		}
		if e.Auth.Policies != nil {
			clone.Auth.Policies = make([]string, len(e.Auth.Policies))
			copy(clone.Auth.Policies, e.Auth.Policies)
		}
		if e.Auth.PolicyResults != nil {
			clone.Auth.PolicyResults = &PolicyResults{
				Allowed: e.Auth.PolicyResults.Allowed,
			}
			if e.Auth.PolicyResults.GrantingPolicies != nil {
				clone.Auth.PolicyResults.GrantingPolicies = make([]string, len(e.Auth.PolicyResults.GrantingPolicies))
				copy(clone.Auth.PolicyResults.GrantingPolicies, e.Auth.PolicyResults.GrantingPolicies)
			}
		}
	}

	return clone
}

// cloneMapAny creates a deep copy of a map[string]any, recursively cloning
// nested maps and slices to prevent data races when logging to multiple devices.
func cloneMapAny(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	clone := make(map[string]any, len(m))
	for k, v := range m {
		clone[k] = cloneValue(v)
	}
	return clone
}

// cloneValue recursively clones a value, handling maps, slices, and primitives.
func cloneValue(v any) any {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]any:
		return cloneMapAny(val)
	case map[string]string:
		clone := make(map[string]string, len(val))
		for k, v := range val {
			clone[k] = v
		}
		return clone
	case []any:
		clone := make([]any, len(val))
		for i, item := range val {
			clone[i] = cloneValue(item)
		}
		return clone
	case []string:
		clone := make([]string, len(val))
		copy(clone, val)
		return clone
	default:
		// Primitives (string, int, bool, etc.) are safe to share
		return v
	}
}

// cloneHeaders creates a copy of HTTP headers
func cloneHeaders(h map[string][]string) map[string][]string {
	if h == nil {
		return nil
	}
	clone := make(map[string][]string, len(h))
	for k, v := range h {
		if v != nil {
			clone[k] = make([]string, len(v))
			copy(clone[k], v)
		}
	}
	return clone
}

// Format defines the serialization format for audit logs
type Format interface {
	// FormatRequest formats a request entry
	FormatRequest(ctx context.Context, entry *LogEntry) ([]byte, error)

	// FormatResponse formats a response entry
	FormatResponse(ctx context.Context, entry *LogEntry) ([]byte, error)

	// Name returns the format name
	Name() string
}

// Sink is the interface for audit log destinations
type Sink interface {
	// Write writes the formatted entry to the sink
	Write(ctx context.Context, entry []byte) error

	// Close closes the sink and releases resources
	Close() error

	// Name returns the sink name
	Name() string

	// Type returns the sink type (file, syslog, socket, etc.)
	Type() string
}

// Device represents an audit device that combines a format and sink
type Device interface {
	// LogRequest logs a request
	LogRequest(ctx context.Context, entry *LogEntry) error

	// LogResponse logs a response
	LogResponse(ctx context.Context, entry *LogEntry) error

	// LogTestRequest logs a test request to verify the device is working correctly
	LogTestRequest(ctx context.Context) error

	// Close closes the device
	Close() error

	// Name returns the device name
	Name() string

	// Enabled returns whether the device is enabled
	Enabled() bool

	// SetEnabled sets the enabled state
	SetEnabled(enabled bool)

	logical.Backend
}

// FilterFunc is a function that filters audit entries
type FilterFunc func(entry *LogEntry) bool

// SaltFunc is a function that salts sensitive data
type SaltFunc func(ctx context.Context, data string) (string, error)

// DeviceConfig contains configuration for an audit device
type DeviceConfig struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Class       string                 `json:"class,omitempty"`
	Description string                 `json:"description,omitempty"`
	Accessor    string                 `json:"accessor,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
	Enabled     bool                   `json:"enabled"`
	Format      string                 `json:"format"`
	Prefix      string                 `json:"prefix,omitempty"`
	HMACKey     string                 `json:"hmac_key,omitempty"`

	// Filtering options
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	IncludePaths []string `json:"include_paths,omitempty"`

	// Performance options
	BufferSize  int           `json:"buffer_size,omitempty"`
	FlushPeriod time.Duration `json:"flush_period,omitempty"`
}

// AuditManager manages audit devices
type AuditManager interface {
	// RegisterDevice registers a new audit device
	RegisterDevice(name string, device Device) error

	// UnregisterDevice unregisters an audit device
	UnregisterDevice(name string) error

	// GetDevice returns a device by name
	GetDevice(name string) (Device, error)

	// ListDevices returns all registered devices
	ListDevices() []string

	// LogRequest logs a request to all enabled devices
	// Returns (continue, error) where continue is true if at least one device succeeded
	LogRequest(ctx context.Context, entry *LogEntry) (bool, error)

	// LogResponse logs a response to all enabled devices
	// Returns (continue, error) where continue is true if at least one device succeeded
	LogResponse(ctx context.Context, entry *LogEntry) (bool, error)

	// Unregister all registered audit devices
	Reset(ctx context.Context) error

	// Close closes all devices
	Close() error
}

type AuditAccess interface {
	// LogRequest logs a request to all enabled devices
	// Returns (continue, error) where continue is true if at least one device succeeded
	LogRequest(ctx context.Context, entry *LogEntry) (bool, error)

	// LogResponse logs a response to all enabled devices
	// Returns (continue, error) where continue is true if at least one device succeeded
	LogResponse(ctx context.Context, entry *LogEntry) (bool, error)
}

type Factory interface {
	Type() string
	Class() string
	Create(ctx context.Context,
		mountPath string,
		description string,
		accessor string,
		config map[string]any) (Device, error)
	Initialize(logger *logger.GatedLogger) error
}
