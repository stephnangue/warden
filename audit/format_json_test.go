package audit

import (
	"context"
	"testing"
	"time"
)

func TestJSONFormat(t *testing.T) {
	format := NewJSONFormat()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:        "req-123",
			Operation: "read",
			Path:      "/v1/secret/data/test",
			ClientIP:  "192.168.1.100",
		},
	}

	data, err := format.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatalf("Failed to format request: %v", err)
	}

	if len(data) == 0 {
		t.Error("Formatted data is empty")
	}

	// Check that it contains expected fields
	if !contains(data, "request") {
		t.Error("Missing 'request' in formatted output")
	}
}

func TestJSONFormatWithConfigurableSalting(t *testing.T) {
	testCases := []struct {
		name       string
		saltFields []string
		entry      *LogEntry
		checkFunc  func(*testing.T, *LogEntry)
	}{
		{
			name:       "salt auth token",
			saltFields: []string{"auth.client_token.token_id"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					ClientToken: &Token{
						TokenID: "secret-token-123",
						Type:    "service",
					},
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Auth == nil || entry.Auth.ClientToken == nil {
					t.Fatal("Auth or ClientToken is nil")
				}
				if entry.Auth.ClientToken.TokenID == "secret-token-123" {
					t.Error("Token ID was not salted")
				}
				if !contains([]byte(entry.Auth.ClientToken.TokenID), "hmac-sha256:") {
					t.Error("Token ID doesn't have HMAC prefix")
				}
			},
		},
		{
			name:       "salt request data password",
			saltFields: []string{"request.data.password"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:   "req-123",
					Path: "/v1/auth/login",
					Data: map[string]interface{}{
						"username": "user1",
						"password": "secret-password",
					},
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Request == nil || entry.Request.Data == nil {
					t.Fatal("Request or Data is nil")
				}
				password, ok := entry.Request.Data["password"].(string)
				if !ok {
					t.Fatal("Password is not a string")
				}
				if password == "secret-password" {
					t.Error("Password was not salted")
				}
				if !contains([]byte(password), "hmac-sha256:") {
					t.Error("Password doesn't have HMAC prefix")
				}
				// Username should not be salted
				if username, ok := entry.Request.Data["username"].(string); ok {
					if username != "user1" {
						t.Error("Username was modified when it shouldn't be")
					}
				}
			},
		},
		{
			name:       "salt multiple fields",
			saltFields: []string{"auth.client_token.token_id", "request.data.password", "request.data.secret"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					ClientToken: &Token{
						TokenID: "token-abc",
						Type:    "service",
					},
				},
				Request: &Request{
					ID:   "req-456",
					Path: "/v1/secret/update",
					Data: map[string]interface{}{
						"password": "pass123",
						"secret":   "secret456",
						"public":   "public-info",
					},
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				// Check token is salted
				if entry.Auth == nil || entry.Auth.ClientToken == nil {
					t.Fatal("Auth or ClientToken is nil")
				}
				if entry.Auth.ClientToken.TokenID == "token-abc" {
					t.Error("Token was not salted")
				}

				// Check password is salted
				if entry.Request == nil || entry.Request.Data == nil {
					t.Fatal("Request or Data is nil")
				}
				if password, ok := entry.Request.Data["password"].(string); ok {
					if password == "pass123" {
						t.Error("Password was not salted")
					}
				}

				// Check secret is salted
				if secret, ok := entry.Request.Data["secret"].(string); ok {
					if secret == "secret456" {
						t.Error("Secret was not salted")
					}
				}

				// Check public is not salted
				if public, ok := entry.Request.Data["public"].(string); ok {
					if public != "public-info" {
						t.Error("Public field was modified")
					}
				}
			},
		},
		{
			name:       "salt response cred token",
			saltFields: []string{"response.cred.token_id", "response.cred.lease_id"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					Cred: &Cred{
						TokenID:  "cred-token-123",
						LeaseID:  "lease-456",
						Type:     "aws",
					},
					StatusCode: 200,
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Response == nil || entry.Response.Cred == nil {
					t.Fatal("Response or Cred is nil")
				}
				if entry.Response.Cred.TokenID == "cred-token-123" {
					t.Error("Cred token was not salted")
				}
				if entry.Response.Cred.LeaseID == "lease-456" {
					t.Error("Lease ID was not salted")
				}
			},
		},
		{
			name:       "salt principal ID",
			saltFields: []string{"auth.principal_id"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					PrincipalID: "user@example.com",
					RoleName:    "admin",
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Auth == nil {
					t.Fatal("Auth is nil")
				}
				if entry.Auth.PrincipalID == "user@example.com" {
					t.Error("Principal ID was not salted")
				}
				// Role name should not be salted
				if entry.Auth.RoleName != "admin" {
					t.Error("Role name was modified")
				}
			},
		},
		{
			name:       "salt client IP",
			saltFields: []string{"request.client_ip"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:       "req-789",
					ClientIP: "192.168.1.100",
					Path:     "/v1/secret/read",
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Request == nil {
					t.Fatal("Request is nil")
				}
				if entry.Request.ClientIP == "192.168.1.100" {
					t.Error("Client IP was not salted")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock salt function
			mockSaltFunc := func(ctx context.Context, data string) (string, error) {
				return "hmac-sha256:" + data + "-salted", nil
			}

			format := NewJSONFormat(
				WithSaltFunc(mockSaltFunc),
				WithSaltFields(tc.saltFields),
			)

			// Format the entry (this triggers salting)
			_, err := format.FormatRequest(context.Background(), tc.entry)
			if err != nil {
				t.Fatalf("Failed to format request: %v", err)
			}

			// Run the check function
			tc.checkFunc(t, tc.entry)
		})
	}
}

func TestJSONFormatSaltAllDataFields(t *testing.T) {
	// Test that specifying just "request.data" salts all fields in the data map
	mockSaltFunc := func(ctx context.Context, data string) (string, error) {
		return "hmac-sha256:" + data + "-salted", nil
	}

	format := NewJSONFormat(
		WithSaltFunc(mockSaltFunc),
		WithSaltFields([]string{"request.data"}),
	)

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request: &Request{
			ID:   "req-123",
			Path: "/v1/auth/login",
			Data: map[string]interface{}{
				"username": "user1",
				"password": "secret-password",
				"token":    "secret-token",
				"number":   123, // non-string should be ignored
			},
		},
	}

	_, err := format.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatalf("Failed to format request: %v", err)
	}

	// Check that all string fields were salted
	if username, ok := entry.Request.Data["username"].(string); ok {
		if username == "user1" {
			t.Error("Username was not salted")
		}
		if !contains([]byte(username), "hmac-sha256:") {
			t.Error("Username doesn't have HMAC prefix")
		}
	}

	if password, ok := entry.Request.Data["password"].(string); ok {
		if password == "secret-password" {
			t.Error("Password was not salted")
		}
		if !contains([]byte(password), "hmac-sha256:") {
			t.Error("Password doesn't have HMAC prefix")
		}
	}

	if token, ok := entry.Request.Data["token"].(string); ok {
		if token == "secret-token" {
			t.Error("Token was not salted")
		}
		if !contains([]byte(token), "hmac-sha256:") {
			t.Error("Token doesn't have HMAC prefix")
		}
	}

	// Number should remain unchanged
	if number, ok := entry.Request.Data["number"].(int); ok {
		if number != 123 {
			t.Error("Number field was modified")
		}
	}
}

func TestJSONFormatOmitFields(t *testing.T) {
	testCases := []struct {
		name       string
		omitFields []string
		entry      *LogEntry
		checkFunc  func(*testing.T, []byte, *LogEntry)
	}{
		{
			name:       "omit entire auth",
			omitFields: []string{"auth"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					ClientToken: &Token{
						TokenID: "token-123",
						Type:    "service",
					},
					PrincipalID: "user@example.com",
				},
				Request: &Request{
					ID:   "req-123",
					Path: "/v1/test",
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				if entry.Auth != nil {
					t.Error("Auth was not omitted")
				}
				if !contains(data, "request") {
					t.Error("Request should still be present")
				}
				if contains(data, "auth") {
					t.Error("Auth should not be in JSON output")
				}
			},
		},
		{
			name:       "omit request.data",
			omitFields: []string{"request.data"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:   "req-123",
					Path: "/v1/test",
					Data: map[string]interface{}{
						"username": "user1",
						"password": "secret",
					},
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				if entry.Request == nil {
					t.Fatal("Request should not be nil")
				}
				if entry.Request.Data != nil {
					t.Error("Request.Data was not omitted")
				}
				if entry.Request.Path != "/v1/test" {
					t.Error("Request.Path should still be present")
				}
			},
		},
		{
			name:       "omit specific request.data field",
			omitFields: []string{"request.data.password"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:   "req-123",
					Path: "/v1/test",
					Data: map[string]interface{}{
						"username": "user1",
						"password": "secret",
					},
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				if entry.Request == nil || entry.Request.Data == nil {
					t.Fatal("Request or Data should not be nil")
				}
				if _, exists := entry.Request.Data["password"]; exists {
					t.Error("password field was not omitted")
				}
				if username, exists := entry.Request.Data["username"]; !exists || username != "user1" {
					t.Error("username field should still be present")
				}
			},
		},
		{
			name:       "omit response.cred",
			omitFields: []string{"response.cred"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					StatusCode: 200,
					Cred: &Cred{
						TokenID: "token-456",
						Type:    "aws",
					},
					Data: map[string]interface{}{
						"result": "success",
					},
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				if entry.Response == nil {
					t.Fatal("Response should not be nil")
				}
				if entry.Response.Cred != nil {
					t.Error("Response.Cred was not omitted")
				}
				if entry.Response.StatusCode != 200 {
					t.Error("Response.StatusCode should still be present")
				}
			},
		},
		{
			name:       "omit multiple fields",
			omitFields: []string{"request.data", "response.cred", "metadata"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:   "req-789",
					Data: map[string]interface{}{"key": "value"},
				},
				Response: &Response{
					StatusCode: 200,
					Cred:       &Cred{Type: "aws", TokenID: "token-123"},
				},
				Metadata: map[string]interface{}{"meta": "data"},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				if entry.Request.Data != nil {
					t.Error("Request.Data was not omitted")
				}
				if entry.Response.Cred != nil {
					t.Error("Response.Cred was not omitted")
				}
				if entry.Metadata != nil {
					t.Error("Metadata was not omitted")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			format := NewJSONFormat(
				WithOmitFields(tc.omitFields),
			)

			data, err := format.FormatRequest(context.Background(), tc.entry)
			if err != nil {
				t.Fatalf("Failed to format request: %v", err)
			}

			tc.checkFunc(t, data, tc.entry)
		})
	}
}

func TestJSONFormatNoSaltingWhenFieldsNotConfigured(t *testing.T) {
	// Test that when no saltFields are specified, no salting occurs
	mockSaltFunc := func(ctx context.Context, data string) (string, error) {
		return "hmac-sha256:" + data + "-salted", nil
	}

	format := NewJSONFormat(
		WithSaltFunc(mockSaltFunc),
		// No WithSaltFields() - should not salt anything
	)

	entry := &LogEntry{
		Timestamp: time.Now(),
		Auth: &Auth{
			ClientToken: &Token{
				TokenID: "token-123",
				Type:    "service",
			},
		},
		Request: &Request{
			ID:   "req-123",
			Path: "/v1/auth/login",
			Data: map[string]interface{}{
				"password": "secret-password",
				"token":    "secret-token",
				"other":    "not-salted",
			},
		},
	}

	_, err := format.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatalf("Failed to format request: %v", err)
	}

	// Check that nothing was salted when no salt fields are configured
	if entry.Auth.ClientToken.TokenID != "token-123" {
		t.Error("Token was modified when it should not be")
	}
	if password, ok := entry.Request.Data["password"].(string); ok {
		if password != "secret-password" {
			t.Error("Password was modified when it should not be")
		}
	}
	if token, ok := entry.Request.Data["token"].(string); ok {
		if token != "secret-token" {
			t.Error("Token was modified when it should not be")
		}
	}
	if other, ok := entry.Request.Data["other"].(string); ok {
		if other != "not-salted" {
			t.Error("Other field was modified when it should not be")
		}
	}
}


