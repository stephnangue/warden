package audit

import (
	"context"
	"encoding/json"
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
	if !containsBytes(data, "request") {
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
			name:       "salt auth token_id",
			saltFields: []string{"auth.token_id"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					TokenID:   "secret-token-123",
					TokenType: "service",
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Auth == nil {
					t.Fatal("Auth is nil")
				}
				if entry.Auth.TokenID == "secret-token-123" {
					t.Error("Token ID was not salted")
				}
				if !containsBytes([]byte(entry.Auth.TokenID), "hmac-sha256:") {
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
				if !containsBytes([]byte(password), "hmac-sha256:") {
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
			saltFields: []string{"auth.token_id", "request.data.password", "request.data.secret"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					TokenID:   "token-abc",
					TokenType: "service",
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
				if entry.Auth == nil {
					t.Fatal("Auth is nil")
				}
				if entry.Auth.TokenID == "token-abc" {
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
			name:       "salt response credential fields",
			saltFields: []string{"response.credential.token_id", "response.credential.lease_id"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					Credential: &Credential{
						TokenID:      "cred-token-123",
						LeaseID:      "lease-456",
						CredentialID: "cred-id-789",
						Type:         "aws_access_keys",
					},
					StatusCode: 200,
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Response == nil || entry.Response.Credential == nil {
					t.Fatal("Response or Credential is nil")
				}
				if entry.Response.Credential.TokenID == "cred-token-123" {
					t.Error("Credential token was not salted")
				}
				if entry.Response.Credential.LeaseID == "lease-456" {
					t.Error("Lease ID was not salted")
				}
			},
		},
		{
			name:       "salt credential data",
			saltFields: []string{"response.credential.data"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					Credential: &Credential{
						CredentialID: "cred-id-123",
						Type:         "aws_access_keys",
						Data: map[string]string{
							"access_key": "AKIAEXAMPLE123",
							"secret_key": "secret-key-value",
						},
					},
					StatusCode: 200,
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Response == nil || entry.Response.Credential == nil || entry.Response.Credential.Data == nil {
					t.Fatal("Response, Credential, or Data is nil")
				}
				if entry.Response.Credential.Data["access_key"] == "AKIAEXAMPLE123" {
					t.Error("Access key was not salted")
				}
				if entry.Response.Credential.Data["secret_key"] == "secret-key-value" {
					t.Error("Secret key was not salted")
				}
				// Both should have HMAC prefix
				if !containsBytes([]byte(entry.Response.Credential.Data["access_key"]), "hmac-sha256:") {
					t.Error("Access key doesn't have HMAC prefix")
				}
				if !containsBytes([]byte(entry.Response.Credential.Data["secret_key"]), "hmac-sha256:") {
					t.Error("Secret key doesn't have HMAC prefix")
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
			jsonData, err := format.FormatRequest(context.Background(), tc.entry)
			if err != nil {
				t.Fatalf("Failed to format request: %v", err)
			}

			// Parse the JSON to get the modified entry
			var formattedEntry LogEntry
			if err := json.Unmarshal(jsonData, &formattedEntry); err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			// Run the check function on the formatted entry
			tc.checkFunc(t, &formattedEntry)
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

	jsonData, err := format.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatalf("Failed to format request: %v", err)
	}

	// Parse the JSON to get the formatted entry
	var formattedEntry LogEntry
	if err := json.Unmarshal(jsonData, &formattedEntry); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Check that all string fields were salted in the formatted output
	if username, ok := formattedEntry.Request.Data["username"].(string); ok {
		if username == "user1" {
			t.Error("Username was not salted")
		}
		if !containsBytes([]byte(username), "hmac-sha256:") {
			t.Error("Username doesn't have HMAC prefix")
		}
	}

	if password, ok := formattedEntry.Request.Data["password"].(string); ok {
		if password == "secret-password" {
			t.Error("Password was not salted")
		}
		if !containsBytes([]byte(password), "hmac-sha256:") {
			t.Error("Password doesn't have HMAC prefix")
		}
	}

	if token, ok := formattedEntry.Request.Data["token"].(string); ok {
		if token == "secret-token" {
			t.Error("Token was not salted")
		}
		if !containsBytes([]byte(token), "hmac-sha256:") {
			t.Error("Token doesn't have HMAC prefix")
		}
	}

	// Number should remain unchanged
	if number, ok := formattedEntry.Request.Data["number"].(float64); ok { // JSON unmarshals numbers as float64
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
					TokenID:     "token-123",
					TokenType:   "service",
					PrincipalID: "user@example.com",
				},
				Request: &Request{
					ID:   "req-123",
					Path: "/v1/test",
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				// Check JSON output, not the original entry (which is not modified due to cloning)
				if !containsBytes(data, "request") {
					t.Error("Request should still be present")
				}
				if containsBytes(data, "auth") {
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
				// Check JSON output, not the original entry (which is not modified due to cloning)
				if !containsBytes(data, "request") {
					t.Error("Request should still be present")
				}
				if !containsBytes(data, "/v1/test") {
					t.Error("Request.Path should still be present")
				}
				if containsBytes(data, "username") || containsBytes(data, "password") {
					t.Error("Request.Data should not be in JSON output")
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
				// Check JSON output, not the original entry (which is not modified due to cloning)
				if !containsBytes(data, "username") {
					t.Error("username field should still be present in JSON")
				}
				if !containsBytes(data, "user1") {
					t.Error("username value should still be present in JSON")
				}
				if containsBytes(data, "password") || containsBytes(data, "secret") {
					t.Error("password field should not be in JSON output")
				}
			},
		},
		{
			name:       "omit response.credential",
			omitFields: []string{"response.credential"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					StatusCode: 200,
					Credential: &Credential{
						TokenID:      "token-456",
						CredentialID: "cred-id-123",
						Type:         "aws_access_keys",
					},
					Data: map[string]interface{}{
						"result": "success",
					},
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				// Check JSON output, not the original entry (which is not modified due to cloning)
				if !containsBytes(data, "response") {
					t.Error("Response should still be present in JSON")
				}
				if !containsBytes(data, "200") {
					t.Error("Response.StatusCode should still be present in JSON")
				}
				if containsBytes(data, "token-456") || containsBytes(data, "\"credential\"") {
					t.Error("Response.Credential should not be in JSON output")
				}
			},
		},
		{
			name:       "omit multiple fields",
			omitFields: []string{"request.data", "response.credential"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:   "req-789",
					Data: map[string]interface{}{"key": "value"},
				},
				Response: &Response{
					StatusCode: 200,
					Credential: &Credential{Type: "aws_access_keys", TokenID: "token-123"},
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				// Check JSON output, not the original entry (which is not modified due to cloning)
				if containsBytes(data, "\"key\"") || containsBytes(data, "\"value\"") {
					t.Error("Request.Data should not be in JSON output")
				}
				if containsBytes(data, "token-123") || containsBytes(data, "\"credential\"") {
					t.Error("Response.Credential should not be in JSON output")
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
			TokenID:   "token-123",
			TokenType: "service",
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
	if entry.Auth.TokenID != "token-123" {
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

func containsBytes(data []byte, substr string) bool {
	return len(data) > 0 && len(substr) > 0 && (string(data) == substr || len(data) >= len(substr) && containsSubstring(string(data), substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestJSONFormatName(t *testing.T) {
	f := NewJSONFormat()
	if f.Name() != "json" {
		t.Errorf("expected json, got %s", f.Name())
	}
}

func TestJSONFormatWithPrefix(t *testing.T) {
	f := NewJSONFormat(WithPrefix("AUDIT: "))

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request:   &Request{ID: "req-1", Path: "/test"},
	}

	data, err := f.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatalf("FormatRequest failed: %v", err)
	}
	if string(data[:7]) != "AUDIT: " {
		t.Errorf("expected prefix 'AUDIT: ', got %s", string(data[:7]))
	}

	// FormatResponse with prefix
	entry.Response = &Response{StatusCode: 200}
	data, err = f.FormatResponse(context.Background(), entry)
	if err != nil {
		t.Fatalf("FormatResponse failed: %v", err)
	}
	if string(data[:7]) != "AUDIT: " {
		t.Errorf("expected prefix 'AUDIT: ', got %s", string(data[:7]))
	}
}

func TestFormatResponse(t *testing.T) {
	f := NewJSONFormat()

	entry := &LogEntry{
		Timestamp: time.Now(),
		Request:   &Request{ID: "req-1", Path: "/test"},
		Response: &Response{
			StatusCode: 200,
			Data:       map[string]any{"key": "value"},
		},
	}

	data, err := f.FormatResponse(context.Background(), entry)
	if err != nil {
		t.Fatalf("FormatResponse failed: %v", err)
	}

	var result LogEntry
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result.Type != "response" {
		t.Errorf("expected type 'response', got %s", result.Type)
	}
}

func TestFormatResponseWithSalting(t *testing.T) {
	mockSalt := func(ctx context.Context, data string) (string, error) {
		return "hmac-sha256:" + data + "-salted", nil
	}

	t.Run("salt response data", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"response.data"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				StatusCode: 200,
				Data:       map[string]any{"secret": "value123"},
			},
		}

		data, err := f.FormatResponse(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatResponse failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if v, ok := result.Response.Data["secret"].(string); ok {
			if v == "value123" {
				t.Error("response data was not salted")
			}
		}
	})

	t.Run("salt response data specific key", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"response.data.secret"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				StatusCode: 200,
				Data:       map[string]any{"secret": "value123", "public": "safe"},
			},
		}

		data, err := f.FormatResponse(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatResponse failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if v, ok := result.Response.Data["public"].(string); ok {
			if v != "safe" {
				t.Error("public field should not be salted")
			}
		}
	})

	t.Run("salt response headers all", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"response.headers"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				StatusCode: 200,
				Headers:    map[string][]string{"Authorization": {"Bearer token123"}},
			},
		}

		data, err := f.FormatResponse(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatResponse failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Response.Headers["Authorization"][0] == "Bearer token123" {
			t.Error("response header was not salted")
		}
	})

	t.Run("salt response headers specific", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"response.headers.Authorization"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				StatusCode: 200,
				Headers: map[string][]string{
					"Authorization": {"Bearer token123"},
					"Content-Type":  {"application/json"},
				},
			},
		}

		data, err := f.FormatResponse(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatResponse failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Response.Headers["Content-Type"][0] != "application/json" {
			t.Error("Content-Type should not be salted")
		}
	})

	t.Run("salt auth result", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{
			"response.auth_result.principal_id",
			"response.auth_result.credential_spec",
		}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				StatusCode: 200,
				AuthResult: &AuthResult{
					PrincipalID:    "user@example.com",
					CredentialSpec: "spec-123",
					RoleName:       "admin",
				},
			},
		}

		data, err := f.FormatResponse(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatResponse failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Response.AuthResult.PrincipalID == "user@example.com" {
			t.Error("principal_id should be salted")
		}
		if result.Response.AuthResult.CredentialSpec == "spec-123" {
			t.Error("credential_spec should be salted")
		}
		if result.Response.AuthResult.RoleName != "admin" {
			t.Error("role_name should not be salted")
		}
	})

	t.Run("salt auth token accessor", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"auth.token_accessor"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Auth:      &Auth{TokenAccessor: "acc-123"},
		}

		data, err := f.FormatRequest(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatRequest failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Auth.TokenAccessor == "acc-123" {
			t.Error("token_accessor should be salted")
		}
	})

	t.Run("salt auth created_by_ip", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"auth.created_by_ip"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Auth:      &Auth{CreatedByIP: "10.0.0.1"},
		}

		data, err := f.FormatRequest(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatRequest failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Auth.CreatedByIP == "10.0.0.1" {
			t.Error("created_by_ip should be salted")
		}
	})

	t.Run("salt policy results granting policies", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"auth.policy_results.granting_policies"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Auth: &Auth{
				PolicyResults: &PolicyResults{
					Allowed:          true,
					GrantingPolicies: []string{"policy1", "policy2"},
				},
			},
		}

		data, err := f.FormatRequest(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatRequest failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Auth.PolicyResults.GrantingPolicies[0] == "policy1" {
			t.Error("granting policy should be salted")
		}
	})

	t.Run("salt request headers all", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"request.headers"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Request: &Request{
				ID:      "req-1",
				Headers: map[string][]string{"X-Token": {"secret"}},
			},
		}

		data, err := f.FormatRequest(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatRequest failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Request.Headers["X-Token"][0] == "secret" {
			t.Error("request header should be salted")
		}
	})

	t.Run("salt request headers specific", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"request.headers.X-Token"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Request: &Request{
				ID: "req-1",
				Headers: map[string][]string{
					"X-Token":      {"secret"},
					"Content-Type": {"text/plain"},
				},
			},
		}

		data, err := f.FormatRequest(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatRequest failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Request.Headers["Content-Type"][0] != "text/plain" {
			t.Error("Content-Type should not be salted")
		}
	})

	t.Run("salt credential id", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"response.credential.credential_id"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				Credential: &Credential{CredentialID: "cred-123", Type: "aws"},
			},
		}

		data, err := f.FormatResponse(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatResponse failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Response.Credential.CredentialID == "cred-123" {
			t.Error("credential_id should be salted")
		}
	})

	t.Run("salt credential data specific key", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"response.credential.data.secret_key"}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				Credential: &Credential{
					CredentialID: "cred-1",
					Data: map[string]string{
						"access_key": "AKIA123",
						"secret_key": "secret",
					},
				},
			},
		}

		data, err := f.FormatResponse(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatResponse failed: %v", err)
		}

		var result LogEntry
		json.Unmarshal(data, &result)
		if result.Response.Credential.Data["access_key"] != "AKIA123" {
			t.Error("access_key should not be salted")
		}
		if result.Response.Credential.Data["secret_key"] == "secret" {
			t.Error("secret_key should be salted")
		}
	})

	t.Run("salt nil response", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"response.data"}))
		entry := &LogEntry{Timestamp: time.Now()}

		_, err := f.FormatRequest(context.Background(), entry)
		if err != nil {
			t.Fatalf("should handle nil response: %v", err)
		}
	})

	t.Run("salt nil auth", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"auth.token_id"}))
		entry := &LogEntry{Timestamp: time.Now()}

		_, err := f.FormatRequest(context.Background(), entry)
		if err != nil {
			t.Fatalf("should handle nil auth: %v", err)
		}
	})
}

func TestOmitResponseFields(t *testing.T) {
	tests := []struct {
		name       string
		omitFields []string
		entry      *LogEntry
		check      func(*testing.T, []byte)
	}{
		{
			name:       "omit response.auth_result",
			omitFields: []string{"response.auth_result"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					StatusCode: 200,
					AuthResult: &AuthResult{PrincipalID: "user1", RoleName: "admin"},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "auth_result") {
					t.Error("auth_result should be omitted")
				}
			},
		},
		{
			name:       "omit response.auth_result sub-fields",
			omitFields: []string{"response.auth_result.principal_id"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					StatusCode: 200,
					AuthResult: &AuthResult{PrincipalID: "user1", RoleName: "admin"},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "user1") {
					t.Error("principal_id value should be omitted")
				}
				if !containsBytes(data, "admin") {
					t.Error("role_name should still be present")
				}
			},
		},
		{
			name:       "omit response.status_code",
			omitFields: []string{"response.status_code"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response:  &Response{StatusCode: 404, MountClass: "provider"},
			},
			check: func(t *testing.T, data []byte) {
				// status_code should be 0 (zero value)
				if containsBytes(data, "404") {
					t.Error("status_code 404 should be omitted")
				}
			},
		},
		{
			name:       "omit response.mount_class",
			omitFields: []string{"response.mount_class"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response:  &Response{StatusCode: 200, MountClass: "provider"},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "provider") {
					t.Error("mount_class should be omitted")
				}
			},
		},
		{
			name:       "omit response.warnings",
			omitFields: []string{"response.warnings"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response:  &Response{StatusCode: 200, Warnings: []string{"warn1"}},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "warn1") {
					t.Error("warnings should be omitted")
				}
			},
		},
		{
			name:       "omit response.streamed",
			omitFields: []string{"response.streamed"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response:  &Response{StatusCode: 200, Streamed: true},
			},
			check: func(t *testing.T, data []byte) {
				// just ensure no error
			},
		},
		{
			name:       "omit response headers specific",
			omitFields: []string{"response.headers.X-Secret"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					StatusCode: 200,
					Headers:    map[string][]string{"X-Secret": {"val"}, "X-Public": {"pub"}},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "X-Secret") {
					t.Error("X-Secret header should be omitted")
				}
				if !containsBytes(data, "X-Public") {
					t.Error("X-Public should remain")
				}
			},
		},
		{
			name:       "omit response data specific key",
			omitFields: []string{"response.data.secret"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					StatusCode: 200,
					Data:       map[string]any{"secret": "val", "public": "pub"},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "\"secret\"") {
					t.Error("secret key should be omitted")
				}
			},
		},
		{
			name:       "omit error",
			omitFields: []string{"error"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Error:     "something went wrong",
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "something went wrong") {
					t.Error("error should be omitted")
				}
			},
		},
		{
			name:       "omit entire request",
			omitFields: []string{"request"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request:   &Request{ID: "req-1", Path: "/test"},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "req-1") {
					t.Error("request should be omitted")
				}
			},
		},
		{
			name:       "omit entire response",
			omitFields: []string{"response"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response:  &Response{StatusCode: 999},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "999") {
					t.Error("response should be omitted")
				}
			},
		},
		{
			name:       "omit auth sub-fields",
			omitFields: []string{"auth.token_id", "auth.token_accessor", "auth.token_type", "auth.principal_id", "auth.role_name", "auth.policies", "auth.token_ttl", "auth.expires_at", "auth.namespace_id", "auth.namespace_path", "auth.created_by_ip"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					TokenID:       "t1",
					TokenAccessor: "ta1",
					TokenType:     "service",
					PrincipalID:   "p1",
					RoleName:      "r1",
					Policies:      []string{"pol1"},
					TokenTTL:      3600,
					ExpiresAt:     1234567890,
					NamespaceID:   "ns1",
					NamespacePath: "nsp1",
					CreatedByIP:   "10.0.0.1",
				},
			},
			check: func(t *testing.T, data []byte) {
				// Just ensure it doesn't error
			},
		},
		{
			name:       "omit auth policy_results",
			omitFields: []string{"auth.policy_results"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					PolicyResults: &PolicyResults{
						Allowed:          true,
						GrantingPolicies: []string{"p1"},
					},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "policy_results") {
					t.Error("policy_results should be omitted")
				}
			},
		},
		{
			name:       "omit auth policy_results sub-field",
			omitFields: []string{"auth.policy_results.granting_policies"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					PolicyResults: &PolicyResults{
						Allowed:          true,
						GrantingPolicies: []string{"p1"},
					},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "p1") {
					t.Error("granting_policies should be omitted")
				}
			},
		},
		{
			name:       "omit request sub-fields",
			omitFields: []string{"request.id", "request.operation", "request.path", "request.mount_point", "request.mount_type", "request.mount_class", "request.method", "request.client_ip", "request.namespace_id", "request.namespace_path", "request.unauthenticated", "request.streamed", "request.transparent"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:              "r1",
					Operation:       "read",
					Path:            "/test",
					MountPoint:      "mp",
					MountType:       "mt",
					MountClass:      "mc",
					Method:          "GET",
					ClientIP:        "1.2.3.4",
					NamespaceID:     "ns",
					NamespacePath:   "nsp",
					Unauthenticated: true,
					Streamed:        true,
					Transparent:     true,
				},
			},
			check: func(t *testing.T, data []byte) {
				// Just ensure no error
			},
		},
		{
			name:       "omit request headers specific",
			omitFields: []string{"request.headers.Authorization"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:      "r1",
					Headers: map[string][]string{"Authorization": {"Bearer x"}, "Accept": {"*/*"}},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "Authorization") {
					t.Error("Authorization header should be omitted")
				}
			},
		},
		{
			name:       "omit credential sub-fields",
			omitFields: []string{"response.credential.credential_id", "response.credential.type", "response.credential.category", "response.credential.lease_ttl", "response.credential.lease_id", "response.credential.token_id", "response.credential.source_name", "response.credential.source_type", "response.credential.spec_name", "response.credential.revocable"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					Credential: &Credential{
						CredentialID: "c1",
						Type:         "aws",
						Category:     "cloud",
						LeaseTTL:     3600,
						LeaseID:      "l1",
						TokenID:      "t1",
						SourceName:   "s1",
						SourceType:   "local",
						SpecName:     "sp1",
						Revocable:    true,
					},
				},
			},
			check: func(t *testing.T, data []byte) {
				// Just ensure no error
			},
		},
		{
			name:       "omit credential data specific key",
			omitFields: []string{"response.credential.data.secret_key"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					Credential: &Credential{
						CredentialID: "c1",
						Data:         map[string]string{"access_key": "AK", "secret_key": "SK"},
					},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "secret_key") {
					t.Error("secret_key should be omitted")
				}
				if !containsBytes(data, "access_key") {
					t.Error("access_key should remain")
				}
			},
		},
		{
			name:       "omit auth result sub-fields",
			omitFields: []string{"response.auth_result.token_type", "response.auth_result.policies", "response.auth_result.token_ttl", "response.auth_result.credential_spec", "response.auth_result.role_name"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Response: &Response{
					AuthResult: &AuthResult{
						TokenType:      "service",
						PrincipalID:    "user1",
						RoleName:       "admin",
						Policies:       []string{"p1"},
						TokenTTL:       3600,
						CredentialSpec: "spec",
					},
				},
			},
			check: func(t *testing.T, data []byte) {
				// Just ensure no error
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := NewJSONFormat(WithOmitFields(tc.omitFields))
			data, err := f.FormatRequest(context.Background(), tc.entry)
			if err != nil {
				t.Fatalf("FormatRequest failed: %v", err)
			}
			tc.check(t, data)
		})
	}
}
