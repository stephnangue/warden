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
	// Clone the entry to avoid data races when logging to multiple devices in parallel
	entry = entry.Clone()
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
	// Clone the entry to avoid data races when logging to multiple devices in parallel
	entry = entry.Clone()
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
// Examples: "auth.token_id", "request.data.password", "response.credential.data"
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
	case "token_id":
		if auth.TokenID != "" {
			salted, err := f.saltFn(ctx, auth.TokenID)
			if err != nil {
				return err
			}
			auth.TokenID = salted
		}
	case "token_accessor":
		if auth.TokenAccessor != "" {
			salted, err := f.saltFn(ctx, auth.TokenAccessor)
			if err != nil {
				return err
			}
			auth.TokenAccessor = salted
		}
	case "principal_id":
		if auth.PrincipalID != "" {
			salted, err := f.saltFn(ctx, auth.PrincipalID)
			if err != nil {
				return err
			}
			auth.PrincipalID = salted
		}
	case "created_by_ip":
		if auth.CreatedByIP != "" {
			salted, err := f.saltFn(ctx, auth.CreatedByIP)
			if err != nil {
				return err
			}
			auth.CreatedByIP = salted
		}
	case "policy_results":
		if auth.PolicyResults != nil && len(parts) > 1 {
			return f.saltPolicyResultsField(ctx, auth.PolicyResults, parts[1:])
		}
	}

	return nil
}

// saltPolicyResultsField salts a field within the PolicyResults structure
func (f *JSONFormat) saltPolicyResultsField(ctx context.Context, pr *PolicyResults, parts []string) error {
	if pr == nil || len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "granting_policies":
		// Salt all policy names
		for i, policy := range pr.GrantingPolicies {
			if policy != "" {
				salted, err := f.saltFn(ctx, policy)
				if err != nil {
					return err
				}
				pr.GrantingPolicies[i] = salted
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
	case "headers":
		if request.Headers == nil {
			return nil
		}
		// If parts length is 1, salt all header values
		if len(parts) == 1 {
			for key, values := range request.Headers {
				for i, value := range values {
					if value != "" {
						salted, err := f.saltFn(ctx, value)
						if err != nil {
							return err
						}
						request.Headers[key][i] = salted
					}
				}
			}
		} else if len(parts) >= 2 {
			// Salt specific header
			key := parts[1]
			if values, ok := request.Headers[key]; ok {
				for i, value := range values {
					if value != "" {
						salted, err := f.saltFn(ctx, value)
						if err != nil {
							return err
						}
						request.Headers[key][i] = salted
					}
				}
			}
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
	case "credential":
		return f.saltCredentialField(ctx, response.Credential, parts[1:])
	case "auth_result":
		return f.saltAuthResultField(ctx, response.AuthResult, parts[1:])
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
	case "headers":
		if response.Headers == nil {
			return nil
		}
		// If parts length is 1, salt all header values
		if len(parts) == 1 {
			for key, values := range response.Headers {
				for i, value := range values {
					if value != "" {
						salted, err := f.saltFn(ctx, value)
						if err != nil {
							return err
						}
						response.Headers[key][i] = salted
					}
				}
			}
		} else if len(parts) >= 2 {
			// Salt specific header
			key := parts[1]
			if values, ok := response.Headers[key]; ok {
				for i, value := range values {
					if value != "" {
						salted, err := f.saltFn(ctx, value)
						if err != nil {
							return err
						}
						response.Headers[key][i] = salted
					}
				}
			}
		}
	}

	return nil
}

// saltCredentialField salts a field within the Credential structure
func (f *JSONFormat) saltCredentialField(ctx context.Context, cred *Credential, parts []string) error {
	if cred == nil || len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "credential_id":
		if cred.CredentialID != "" {
			salted, err := f.saltFn(ctx, cred.CredentialID)
			if err != nil {
				return err
			}
			cred.CredentialID = salted
		}
	case "lease_id":
		if cred.LeaseID != "" {
			salted, err := f.saltFn(ctx, cred.LeaseID)
			if err != nil {
				return err
			}
			cred.LeaseID = salted
		}
	case "token_id":
		if cred.TokenID != "" {
			salted, err := f.saltFn(ctx, cred.TokenID)
			if err != nil {
				return err
			}
			cred.TokenID = salted
		}
	case "data":
		if cred.Data == nil {
			return nil
		}
		// If parts length is 1, salt all values in the data map (contains sensitive credential values)
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

// saltAuthResultField salts a field within the AuthResult structure
func (f *JSONFormat) saltAuthResultField(ctx context.Context, authResult *AuthResult, parts []string) error {
	if authResult == nil || len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "principal_id":
		if authResult.PrincipalID != "" {
			salted, err := f.saltFn(ctx, authResult.PrincipalID)
			if err != nil {
				return err
			}
			authResult.PrincipalID = salted
		}
	case "credential_spec":
		if authResult.CredentialSpec != "" {
			salted, err := f.saltFn(ctx, authResult.CredentialSpec)
			if err != nil {
				return err
			}
			authResult.CredentialSpec = salted
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
// Examples: "auth", "request.data", "response.credential"
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
	case "token_id":
		auth.TokenID = ""
	case "token_accessor":
		auth.TokenAccessor = ""
	case "token_type":
		auth.TokenType = ""
	case "principal_id":
		auth.PrincipalID = ""
	case "role_name":
		auth.RoleName = ""
	case "policies":
		auth.Policies = nil
	case "policy_results":
		if len(parts) == 1 {
			auth.PolicyResults = nil
		} else if auth.PolicyResults != nil {
			f.omitPolicyResultsField(auth.PolicyResults, parts[1:])
		}
	case "token_ttl":
		auth.TokenTTL = 0
	case "expires_at":
		auth.ExpiresAt = 0
	case "namespace_id":
		auth.NamespaceID = ""
	case "namespace_path":
		auth.NamespacePath = ""
	case "created_by_ip":
		auth.CreatedByIP = ""
	}
}

// omitPolicyResultsField omits a field within the PolicyResults structure
func (f *JSONFormat) omitPolicyResultsField(pr *PolicyResults, parts []string) {
	if pr == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "granting_policies":
		pr.GrantingPolicies = nil
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
	case "operation":
		request.Operation = ""
	case "path":
		request.Path = ""
	case "mount_point":
		request.MountPoint = ""
	case "mount_type":
		request.MountType = ""
	case "mount_class":
		request.MountClass = ""
	case "method":
		request.Method = ""
	case "client_ip":
		request.ClientIP = ""
	case "headers":
		if len(parts) == 1 {
			request.Headers = nil
		} else if len(parts) >= 2 && request.Headers != nil {
			delete(request.Headers, parts[1])
		}
	case "data":
		if len(parts) == 1 {
			request.Data = nil
		} else if len(parts) >= 2 && request.Data != nil {
			delete(request.Data, parts[1])
		}
	case "namespace_id":
		request.NamespaceID = ""
	case "namespace_path":
		request.NamespacePath = ""
	case "unauthenticated":
		request.Unauthenticated = false
	case "streamed":
		request.Streamed = false
	case "transparent":
		request.Transparent = false
	}
}

// omitResponseField omits a field within the Response structure
func (f *JSONFormat) omitResponseField(response *Response, parts []string) {
	if response == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "status_code":
		response.StatusCode = 0
	case "headers":
		if len(parts) == 1 {
			response.Headers = nil
		} else if len(parts) >= 2 && response.Headers != nil {
			delete(response.Headers, parts[1])
		}
	case "data":
		if len(parts) == 1 {
			response.Data = nil
		} else if len(parts) >= 2 && response.Data != nil {
			delete(response.Data, parts[1])
		}
	case "mount_class":
		response.MountClass = ""
	case "streamed":
		response.Streamed = false
	case "warnings":
		response.Warnings = nil
	case "credential":
		if len(parts) == 1 {
			response.Credential = nil
		} else {
			f.omitCredentialField(response.Credential, parts[1:])
		}
	case "auth_result":
		if len(parts) == 1 {
			response.AuthResult = nil
		} else {
			f.omitAuthResultField(response.AuthResult, parts[1:])
		}
	}
}

// omitCredentialField omits a field within the Credential structure
func (f *JSONFormat) omitCredentialField(cred *Credential, parts []string) {
	if cred == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "credential_id":
		cred.CredentialID = ""
	case "type":
		cred.Type = ""
	case "category":
		cred.Category = ""
	case "lease_ttl":
		cred.LeaseTTL = 0
	case "lease_id":
		cred.LeaseID = ""
	case "token_id":
		cred.TokenID = ""
	case "source_name":
		cred.SourceName = ""
	case "source_type":
		cred.SourceType = ""
	case "spec_name":
		cred.SpecName = ""
	case "revocable":
		cred.Revocable = false
	case "data":
		if len(parts) == 1 {
			cred.Data = nil
		} else if len(parts) >= 2 && cred.Data != nil {
			delete(cred.Data, parts[1])
		}
	}
}

// omitAuthResultField omits a field within the AuthResult structure
func (f *JSONFormat) omitAuthResultField(authResult *AuthResult, parts []string) {
	if authResult == nil || len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "token_type":
		authResult.TokenType = ""
	case "principal_id":
		authResult.PrincipalID = ""
	case "role_name":
		authResult.RoleName = ""
	case "policies":
		authResult.Policies = nil
	case "token_ttl":
		authResult.TokenTTL = 0
	case "credential_spec":
		authResult.CredentialSpec = ""
	}
}
