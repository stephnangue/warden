package audit

import (
	"context"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// LogEntry represents a single audit log entry
type LogEntry struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Auth      *Auth                  `json:"auth,omitempty"`
	Request   *Request               `json:"request,omitempty"`
	Response  *Response              `json:"response,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Auth contains authentication information
type Auth struct {
	ClientToken     *Token            `json:"client_token,omitempty"`
	RoleName        string            `json:"role_name,omitempty"`
	PrincipalID     string            `json:"principal_id,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// Request contains request information
type Request struct {
	ID                  string                 `json:"id"`
	Method              string                 `json:"method"`
	Operation           string                 `json:"operation"`
	ClientIP            string                 `json:"client_ip"`
	Path                string                 `json:"path"`
	Data                map[string]interface{} `json:"data,omitempty"`
	TargetUrl           string                 `json:"target_url,omitempty"`
	Headers             map[string][]string    `json:"headers,omitempty"`
	MountType           string                 `json:"mount_type,omitempty"`
	MountAccessor       string                 `json:"mount_accessor,omitempty"`
	MountPath           string                 `json:"mount_path,omitempty"`
	MountClass          string                 `json:"mount_class,omitempty"`
}

// Response contains response information
type Response struct {
	Data                map[string]interface{} `json:"data,omitempty"`
	Cred                *Cred                  `json:"cred,omitempty"`
	StatusCode          int                    `json:"status_code,omitempty"`
	Message             string                 `json:"message,omitempty"`
	MountType           string                 `json:"mount_type,omitempty"`
	MountAccessor       string                 `json:"mount_accessor,omitempty"`
	MountPath           string                 `json:"mount_path,omitempty"`
	MountClass          string                 `json:"mount_class,omitempty"`
	Headers             map[string][]string    `json:"headers,omitempty"`
}

// Cred contains credential information used by warden to send a request to a provider
type Cred struct {
	Type               string 				   `json:"type"`
	LeaseTTL           int64				   `json:"lease_ttl,omitempty"`
	LeaseID            string 				   `json:"lease_id,omitempty"`
	TokenID            string 				   `json:"token_id,omitempty"`
	Origin             string                  `json:"origin,omitempty"`
	Data               map[string]string       `json:"data,omitempty"`
}

// Token contains token information used by a principal to send a request to warden
type Token struct {
	Type               string 				   `json:"type"`
	TokenID            string 				   `json:"token_id,omitempty"`
	TokenTTL           int64				   `json:"token_ttl,omitempty"`
	TokenIssuer        string                  `json:"token_issuer,omitempty"`
	Data               map[string]string       `json:"data,omitempty"`
}

// EntryType defines the type of audit entry
type EntryType string

const (
	EntryTypeRequest  EntryType = "request"
	EntryTypeResponse EntryType = "response"
)

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
	Initialize(logger logger.Logger) error
}