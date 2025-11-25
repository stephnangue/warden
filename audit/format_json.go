package audit

import (
	"context"
	"encoding/json"
	"strings"
)

// JSONFormat implements the Format interface for JSON output
type JSONFormat struct {
	prefix     string
	saltFn     SaltFunc
	omitFields []string
	saltFields []string
}

// NewJSONFormat creates a new JSON format
func NewJSONFormat(opts ...JSONFormatOption) *JSONFormat {
	f := &JSONFormat{
		omitFields: []string{},
	}
	
	for _, opt := range opts {
		opt(f)
	}
	
	return f
}

// JSONFormatOption is a functional option for JSONFormat
type JSONFormatOption func(*JSONFormat)

// WithPrefix sets a prefix for each log line
func WithPrefix(prefix string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.prefix = prefix
	}
}

// WithSaltFunc sets a salt function for sensitive data
func WithSaltFunc(fn SaltFunc) JSONFormatOption {
	return func(f *JSONFormat) {
		f.saltFn = fn
	}
}

// WithOmitFields sets fields to omit from output
func WithOmitFields(fields []string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.omitFields = fields
	}
}

// WithSaltFields sets fields to salt in the output
func WithSaltFields(fields []string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.saltFields = fields
	}
}

// FormatRequest formats a request entry as JSON
func (f *JSONFormat) FormatRequest(ctx context.Context, entry *LogEntry) ([]byte, error) {
	entry.Type = string(EntryTypeRequest)
	
	// Salt sensitive data if function is provided
	if f.saltFn != nil {
		if err := f.saltEntry(ctx, entry); err != nil {
			return nil, err
		}
	}
	
	// Remove omitted fields
	f.omitFieldsFromEntry(entry)
	
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	
	if f.prefix != "" {
		return append([]byte(f.prefix), data...), nil
	}
	
	return data, nil
}

// FormatResponse formats a response entry as JSON
func (f *JSONFormat) FormatResponse(ctx context.Context, entry *LogEntry) ([]byte, error) {
	entry.Type = string(EntryTypeResponse)
	
	// Salt sensitive data if function is provided
	if f.saltFn != nil {
		if err := f.saltEntry(ctx, entry); err != nil {
			return nil, err
		}
	}
	
	// Remove omitted fields
	f.omitFieldsFromEntry(entry)
	
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	
	if f.prefix != "" {
		return append([]byte(f.prefix), data...), nil
	}
	
	return data, nil
}

// Name returns the format name
func (f *JSONFormat) Name() string {
	return "json"
}

// saltEntry salts sensitive fields in the entry
func (f *JSONFormat) saltEntry(ctx context.Context, entry *LogEntry) error {
	// If no salt fields are configured, do nothing
	if len(f.saltFields) == 0 {
		return nil
	}

	// Salt each configured field path
	for _, fieldPath := range f.saltFields {
		if err := f.saltFieldByPath(ctx, entry, fieldPath); err != nil {
			// Continue on error to salt as many fields as possible
			continue
		}
	}

	return nil
}

// saltFieldByPath salts a field identified by a dot-separated path
// Examples: "auth.client_token.token_id", "request.data.password", "response.auth.client_token.token_id"
func (f *JSONFormat) saltFieldByPath(ctx context.Context, entry *LogEntry, fieldPath string) error {
	parts := strings.Split(fieldPath, ".")
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "auth":
		return f.saltAuthField(ctx, entry.Auth, parts[1:])
	case "request":
		return f.saltRequestField(ctx, entry.Request, parts[1:])
	case "response":
		return f.saltResponseField(ctx, entry.Response, parts[1:])
	}

	return nil
}

// saltAuthField salts a field within the Auth structure
func (f *JSONFormat) saltAuthField(ctx context.Context, auth *Auth, parts []string) error {
	if auth == nil || len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "client_token":
		if auth.ClientToken == nil {
			return nil
		}
		if len(parts) == 1 {
			return nil
		}
		return f.saltTokenField(ctx, auth.ClientToken, parts[1:])
	case "principal_id":
		if auth.PrincipalID != "" {
			salted, err := f.saltFn(ctx, auth.PrincipalID)
			if err != nil {
				return err
			}
			auth.PrincipalID = salted
		}
	case "metadata":
		if auth.Metadata == nil {
			return nil
		}
		// If parts length is 1, salt all values in the metadata map
		if len(parts) == 1 {
			for key, value := range auth.Metadata {
				if value != "" {
					salted, err := f.saltFn(ctx, value)
					if err != nil {
						return err
					}
					auth.Metadata[key] = salted
				}
			}
		} else if len(parts) >= 2 {
			// Salt specific key
			key := parts[1]
			if value, ok := auth.Metadata[key]; ok && value != "" {
				salted, err := f.saltFn(ctx, value)
				if err != nil {
					return err
				}
				auth.Metadata[key] = salted
			}
		}
	}

	return nil
}

// saltTokenField salts a field within the Token structure
func (f *JSONFormat) saltTokenField(ctx context.Context, token *Token, parts []string) error {
	if token == nil || len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "token_id":
		if token.TokenID != "" {
			salted, err := f.saltFn(ctx, token.TokenID)
			if err != nil {
				return err
			}
			token.TokenID = salted
		}
	case "data":
		if token.Data == nil {
			return nil
		}
		// If parts length is 1, salt all values in the data map
		if len(parts) == 1 {
			for key, value := range token.Data {
				if value != "" {
					salted, err := f.saltFn(ctx, value)
					if err != nil {
						return err
					}
					token.Data[key] = salted
				}
			}
		} else if len(parts) >= 2 {
			// Salt specific key
			key := parts[1]
			if value, ok := token.Data[key]; ok && value != "" {
				salted, err := f.saltFn(ctx, value)
				if err != nil {
					return err
				}
				token.Data[key] = salted
			}
		}
	}

	return nil
}

// saltRequestField salts a field within the Request structure
func (f *JSONFormat) saltRequestField(ctx context.Context, request *Request, parts []string) error {
	if request == nil || len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "data":
		if request.Data == nil {
			return nil
		}
		// If parts length is 1, salt all string values in the data map
		if len(parts) == 1 {
			for key, value := range request.Data {
				if strValue, ok := value.(string); ok && strValue != "" {
					salted, err := f.saltFn(ctx, strValue)
					if err != nil {
						return err
					}
					request.Data[key] = salted
				}
			}
		} else if len(parts) >= 2 {
			// Salt specific key
			key := parts[1]
			if value, ok := request.Data[key]; ok {
				if strValue, ok := value.(string); ok && strValue != "" {
					salted, err := f.saltFn(ctx, strValue)
					if err != nil {
						return err
					}
					request.Data[key] = salted
				}
			}
		}
	case "client_ip":
		if request.ClientIP != "" {
			salted, err := f.saltFn(ctx, request.ClientIP)
			if err != nil {
				return err
			}
			request.ClientIP = salted
		}
	}

	return nil
}

// saltResponseField salts a field within the Response structure
func (f *JSONFormat) saltResponseField(ctx context.Context, response *Response, parts []string) error {
	if response == nil || len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "cred":
		return f.saltCredField(ctx, response.Cred, parts[1:])
	case "data":
		if response.Data == nil {
			return nil
		}
		// If parts length is 1, salt all string values in the data map
		if len(parts) == 1 {
			for key, value := range response.Data {
				if strValue, ok := value.(string); ok && strValue != "" {
					salted, err := f.saltFn(ctx, strValue)
					if err != nil {
						return err
					}
					response.Data[key] = salted
				}
			}
		} else if len(parts) >= 2 {
			// Salt specific key
			key := parts[1]
			if value, ok := response.Data[key]; ok {
				if strValue, ok := value.(string); ok && strValue != "" {
					salted, err := f.saltFn(ctx, strValue)
					if err != nil {
						return err
					}
					response.Data[key] = salted
				}
			}
		}
	}

	return nil
}

// saltCredField salts a field within the Cred structure
func (f *JSONFormat) saltCredField(ctx context.Context, cred *Cred, parts []string) error {
	if cred == nil || len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "token_id":
		if cred.TokenID != "" {
			salted, err := f.saltFn(ctx, cred.TokenID)
			if err != nil {
				return err
			}
			cred.TokenID = salted
		}
	case "lease_id":
		if cred.LeaseID != "" {
			salted, err := f.saltFn(ctx, cred.LeaseID)
			if err != nil {
				return err
			}
			cred.LeaseID = salted
		}
	case "data":
		if cred.Data == nil {
			return nil
		}
		// If parts length is 1, salt all values in the data map
		if len(parts) == 1 {
			for key, value := range cred.Data {
				if value != "" {
					salted, err := f.saltFn(ctx, value)
					if err != nil {
						return err
					}
					cred.Data[key] = salted
				}
			}
		} else if len(parts) >= 2 {
			// Salt specific key
			key := parts[1]
			if value, ok := cred.Data[key]; ok && value != "" {
				salted, err := f.saltFn(ctx, value)
				if err != nil {
					return err
				}
				cred.Data[key] = salted
			}
		}
	}

	return nil
}

// omitFieldsFromEntry removes fields from entry based on configuration
func (f *JSONFormat) omitFieldsFromEntry(entry *LogEntry) {
	for _, fieldPath := range f.omitFields {
		f.omitFieldByPath(entry, fieldPath)
	}
}

// omitFieldByPath omits a field identified by a dot-separated path
// Examples: "auth", "request.data", "response.auth.client_token", "metadata"
func (f *JSONFormat) omitFieldByPath(entry *LogEntry, fieldPath string) {
	parts := strings.Split(fieldPath, ".")
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "auth":
		if len(parts) == 1 {
			entry.Auth = nil
		} else {
			f.omitAuthField(entry.Auth, parts[1:])
		}
	case "request":
		if len(parts) == 1 {
			entry.Request = nil
		} else if entry.Request != nil {
			f.omitRequestField(entry.Request, parts[1:])
		}
	case "response":
		if len(parts) == 1 {
			entry.Response = nil
		} else if entry.Response != nil {
			f.omitResponseField(entry.Response, parts[1:])
		}
	case "metadata":
		if len(parts) == 1 {
			entry.Metadata = nil
		} else if len(parts) >= 2 && entry.Metadata != nil {
			// Omit specific key in metadata
			delete(entry.Metadata, parts[1])
		}
	case "error":
		entry.Error = ""
	}
}

// omitAuthField omits a field within the Auth structure
func (f *JSONFormat) omitAuthField(auth *Auth, parts []string) {
	if auth == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "client_token":
		if len(parts) == 1 {
			auth.ClientToken = nil
		} else if auth.ClientToken != nil {
			f.omitTokenField(auth.ClientToken, parts[1:])
		}
	case "principal_id":
		auth.PrincipalID = ""
	case "role_name":
		auth.RoleName = ""
	case "metadata":
		if len(parts) == 1 {
			auth.Metadata = nil
		} else if len(parts) >= 2 && auth.Metadata != nil {
			delete(auth.Metadata, parts[1])
		}
	}
}

// omitTokenField omits a field within the Token structure
func (f *JSONFormat) omitTokenField(token *Token, parts []string) {
	if token == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "token_id":
		token.TokenID = ""
	case "type":
		token.Type = ""
	case "token_ttl":
		token.TokenTTL = 0
	case "token_issuer":
		token.TokenIssuer = ""
	case "data":
		if len(parts) == 1 {
			token.Data = nil
		} else if len(parts) >= 2 && token.Data != nil {
			delete(token.Data, parts[1])
		}
	}
}

// omitRequestField omits a field within the Request structure
func (f *JSONFormat) omitRequestField(request *Request, parts []string) {
	if request == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "id":
		request.ID = ""
	case "method":
		request.Method = ""
	case "operation":
		request.Operation = ""
	case "client_ip":
		request.ClientIP = ""
	case "path":
		request.Path = ""
	case "target_url":
		request.TargetUrl = ""
	case "data":
		if len(parts) == 1 {
			request.Data = nil
		} else if len(parts) >= 2 && request.Data != nil {
			delete(request.Data, parts[1])
		}
	case "headers":
		if len(parts) == 1 {
			request.Headers = nil
		} else if len(parts) >= 2 && request.Headers != nil {
			delete(request.Headers, parts[1])
		}
	case "mount_type":
		request.MountType = ""
	case "mount_accessor":
		request.MountAccessor = ""
	case "mount_path":
		request.MountPath = ""
	case "mount_class":
		request.MountClass = ""
	}
}

// omitResponseField omits a field within the Response structure
func (f *JSONFormat) omitResponseField(response *Response, parts []string) {
	if response == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "cred":
		if len(parts) == 1 {
			response.Cred = nil
		} else {
			f.omitCredField(response.Cred, parts[1:])
		}
	case "status_code":
		response.StatusCode = 0
	case "message":
		response.Message = ""
	case "data":
		if len(parts) == 1 {
			response.Data = nil
		} else if len(parts) >= 2 && response.Data != nil {
			delete(response.Data, parts[1])
		}
	case "headers":
		if len(parts) == 1 {
			response.Headers = nil
		} else if len(parts) >= 2 && response.Headers != nil {
			delete(response.Headers, parts[1])
		}
	case "mount_type":
		response.MountType = ""
	case "mount_accessor":
		response.MountAccessor = ""
	case "mount_path":
		response.MountPath = ""
	case "mount_class":
		response.MountClass = ""
	}
}

// omitCredField omits a field within the Cred structure
func (f *JSONFormat) omitCredField(cred *Cred, parts []string) {
	if cred == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "type":
		cred.Type = ""
	case "lease_ttl":
		cred.LeaseTTL = 0
	case "lease_id":
		cred.LeaseID = ""
	case "token_id":
		cred.TokenID = ""
	case "origin":
		cred.Origin = ""
	case "data":
		if len(parts) == 1 {
			cred.Data = nil
		} else if len(parts) >= 2 && cred.Data != nil {
			delete(cred.Data, parts[1])
		}
	}
}