package audit

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stephnangue/warden/logical"
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
					TokenType: "service_token",
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
			name:       "salt multiple fields",
			saltFields: []string{"auth.token_id", "request.client_ip"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Auth: &Auth{
					TokenID:   "token-abc",
					TokenType: "service_token",
				},
				Request: &Request{
					ID:       "req-456",
					Path:     "/v1/secret/update",
					ClientIP: "10.0.0.7",
				},
			},
			checkFunc: func(t *testing.T, entry *LogEntry) {
				if entry.Auth == nil || entry.Request == nil {
					t.Fatal("Auth or Request is nil")
				}
				if entry.Auth.TokenID == "token-abc" {
					t.Error("Token was not salted")
				}
				if entry.Request.ClientIP == "10.0.0.7" {
					t.Error("Client IP was not salted")
				}
				// Fields not listed are left as they are
				if entry.Auth.TokenType != "service_token" || entry.Request.Path != "/v1/secret/update" {
					t.Error("An unlisted field was modified")
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
					TokenType:   "service_token",
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
			name:       "omit request.client_ip",
			omitFields: []string{"request.client_ip"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:       "req-123",
					Path:     "/v1/test",
					ClientIP: "10.0.0.7",
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				// Check JSON output, not the original entry (which is not modified due to cloning)
				if !containsBytes(data, "/v1/test") {
					t.Error("Request.Path should still be present")
				}
				if containsBytes(data, "10.0.0.7") {
					t.Error("Request.ClientIP should not be in JSON output")
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
			omitFields: []string{"request.client_ip", "response.credential"},
			entry: &LogEntry{
				Timestamp: time.Now(),
				Request: &Request{
					ID:       "req-789",
					ClientIP: "10.0.0.8",
				},
				Response: &Response{
					StatusCode: 200,
					Credential: &Credential{Type: "aws_access_keys", TokenID: "token-123"},
				},
			},
			checkFunc: func(t *testing.T, data []byte, entry *LogEntry) {
				// Check JSON output, not the original entry (which is not modified due to cloning)
				if containsBytes(data, "10.0.0.8") {
					t.Error("Request.ClientIP should not be in JSON output")
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
			TokenType: "service_token",
		},
		Request: &Request{
			ID:       "req-123",
			Path:     "/v1/auth/login",
			ClientIP: "10.0.0.9",
		},
	}

	data, err := format.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatalf("Failed to format request: %v", err)
	}

	// Check that nothing was salted when no salt fields are configured
	if containsBytes(data, "hmac-sha256:") {
		t.Errorf("A field was salted with no salt fields configured: %s", data)
	}
	if !containsBytes(data, "token-123") || !containsBytes(data, "10.0.0.9") {
		t.Errorf("A field was modified when it should not be: %s", data)
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

// TestFormatConditionInputsSalting exercises salt_fields for the CEL condition
// inputs map, whose keys are themselves dotted (agent.metadata.env).
func TestFormatConditionInputsSalting(t *testing.T) {
	mockSalt := func(ctx context.Context, data string) (string, error) {
		return "hmac-sha256:" + data + "-salted", nil
	}
	newEntry := func() *LogEntry {
		return &LogEntry{
			Timestamp: time.Now(),
			Auth: &Auth{
				PolicyResults: &PolicyResults{
					Allowed: false,
					Condition: &logical.ConditionResult{
						Decision:   "deny",
						Expression: "agent.metadata.env == 'prod'",
						Inputs: map[string]string{
							"agent.metadata.env": "staging",
							"agent.token_type":   "identity_token",
							"request.data.model": "opus",
						},
					},
				},
			},
		}
	}
	format := func(t *testing.T, saltFields []string) map[string]string {
		t.Helper()
		opts := []JSONFormatOption{WithSaltFunc(mockSalt)}
		if saltFields != nil {
			opts = append(opts, WithSaltFields(saltFields))
		}
		f := NewJSONFormat(opts...)
		data, err := f.FormatRequest(context.Background(), newEntry())
		if err != nil {
			t.Fatalf("FormatRequest failed: %v", err)
		}
		var got LogEntry
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		return got.Auth.PolicyResults.Condition.Inputs
	}
	salted := func(s string) bool { return containsBytes([]byte(s), "hmac-sha256:") }

	t.Run("clear by default", func(t *testing.T) {
		in := format(t, nil)
		if in["agent.metadata.env"] != "staging" || in["request.data.model"] != "opus" {
			t.Errorf("inputs should be clear, got %v", in)
		}
	})

	t.Run("salt all inputs", func(t *testing.T) {
		in := format(t, []string{"auth.policy_results.condition.inputs"})
		if !salted(in["agent.metadata.env"]) || !salted(in["request.data.model"]) {
			t.Errorf("all inputs should be salted, got %v", in)
		}
	})

	t.Run("salt one dotted key", func(t *testing.T) {
		in := format(t, []string{"auth.policy_results.condition.inputs.request.data.model"})
		if in["agent.metadata.env"] != "staging" {
			t.Errorf("other input must stay clear, got %q", in["agent.metadata.env"])
		}
		if !salted(in["request.data.model"]) {
			t.Errorf("request.data.model should be salted, got %q", in["request.data.model"])
		}
	})

	// The `token` -> `agent` rename moved every condition-input key, and
	// salt_fields matches those keys verbatim. A stale selector therefore does
	// not error or warn — it simply stops matching, and the value it used to
	// protect starts logging in clear. These two cases pin that fail-open so it
	// is visible in the suite rather than in an audit log.
	t.Run("pre-rename selector no longer matches", func(t *testing.T) {
		in := format(t, []string{"auth.policy_results.condition.inputs.token.metadata.env"})
		if salted(in["agent.metadata.env"]) {
			t.Errorf("stale token.* selector must not salt the renamed key, got %q", in["agent.metadata.env"])
		}
		if in["agent.metadata.env"] != "staging" {
			t.Errorf("value should be untouched and in clear, got %q", in["agent.metadata.env"])
		}
	})

	// The three token_-prefixed fields are the sharp edge: substituting
	// `token.` -> `agent.` across an audit config fixes agent.metadata.* but
	// turns token.type into agent.type, which names nothing.
	t.Run("token_-prefixed field needs the full new name", func(t *testing.T) {
		naive := format(t, []string{"auth.policy_results.condition.inputs.agent.type"})
		if salted(naive["agent.token_type"]) {
			t.Errorf("agent.type must not match agent.token_type, got %q", naive["agent.token_type"])
		}
		correct := format(t, []string{"auth.policy_results.condition.inputs.agent.token_type"})
		if !salted(correct["agent.token_type"]) {
			t.Errorf("agent.token_type selector should salt, got %q", correct["agent.token_type"])
		}
	})
}

// TestFormatDenyingPolicySaltAndOmit: denying_policy holds a policy name, like
// granting_policies, so it can be salted or omitted.
func TestFormatDenyingPolicySaltAndOmit(t *testing.T) {
	mockSalt := func(ctx context.Context, data string) (string, error) {
		return "hmac-sha256:" + data + "-salted", nil
	}
	format := func(t *testing.T, opts ...JSONFormatOption) *PolicyResults {
		t.Helper()
		entry := &LogEntry{
			Timestamp: time.Now(),
			Auth: &Auth{PolicyResults: &PolicyResults{
				DenyingPolicy: "guard",
				Condition: &logical.ConditionResult{
					Decision:   "deny",
					Expression: "agent.metadata.env != 'prod'",
				},
			}},
		}
		data, err := NewJSONFormat(append(opts, WithSaltFunc(mockSalt))...).FormatRequest(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatRequest failed: %v", err)
		}
		var got LogEntry
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		return got.Auth.PolicyResults
	}
	const salted = "hmac-sha256:guard-salted"

	t.Run("clear by default", func(t *testing.T) {
		got := format(t)
		if got.DenyingPolicy != "guard" {
			t.Errorf("the name should be clear, got %q", got.DenyingPolicy)
		}
	})
	t.Run("salted", func(t *testing.T) {
		got := format(t, WithSaltFields([]string{"auth.policy_results.denying_policy"}))
		if got.DenyingPolicy != salted {
			t.Errorf("the name should be salted, got %q", got.DenyingPolicy)
		}
	})
	t.Run("omitted", func(t *testing.T) {
		got := format(t, WithOmitFields([]string{"auth.policy_results.denying_policy"}))
		if got.DenyingPolicy != "" {
			t.Errorf("the name should be omitted, got %q", got.DenyingPolicy)
		}
		if got.Condition == nil || got.Condition.Expression == "" {
			t.Error("omitting the name should leave the condition")
		}
	})
}

func TestFormatResponseWithSalting(t *testing.T) {
	mockSalt := func(ctx context.Context, data string) (string, error) {
		return "hmac-sha256:" + data + "-salted", nil
	}

	t.Run("salt auth result", func(t *testing.T) {
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{
			"response.auth_result.principal_id",
		}))
		entry := &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				StatusCode: 200,
				AuthResult: &AuthResult{
					PrincipalID: "user@example.com",
					TokenType:   "identity_token",
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
		if result.Response.AuthResult.TokenType != "identity_token" {
			t.Error("token_type should not be salted")
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
		f := NewJSONFormat(WithSaltFunc(mockSalt), WithSaltFields([]string{"response.credential.data"}))
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
	// Pin the timestamp so its marshalled string never collides with the
	// 3-digit sentinel values (e.g. StatusCode 999, 404) the substring
	// checks below scan for. time.Now() makes the nanosecond fraction
	// non-deterministic and occasionally produces e.g. ".999Z", which
	// would match `containsBytes(data, "999")` and fail the test for the
	// wrong reason.
	fixedTS := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

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
				Timestamp: fixedTS,
				Response: &Response{
					StatusCode: 200,
					AuthResult: &AuthResult{PrincipalID: "user1", TokenType: "admin_type"},
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
				Timestamp: fixedTS,
				Response: &Response{
					StatusCode: 200,
					AuthResult: &AuthResult{PrincipalID: "user1", TokenType: "admin_type"},
				},
			},
			check: func(t *testing.T, data []byte) {
				if containsBytes(data, "user1") {
					t.Error("principal_id value should be omitted")
				}
				if !containsBytes(data, "admin_type") {
					t.Error("token_type should still be present")
				}
			},
		},
		{
			name:       "omit response.status_code",
			omitFields: []string{"response.status_code"},
			entry: &LogEntry{
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
				Response:  &Response{StatusCode: 200, Streamed: true},
			},
			check: func(t *testing.T, data []byte) {
				// just ensure no error
			},
		},
		{
			name:       "omit error",
			omitFields: []string{"error"},
			entry: &LogEntry{
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
				Auth: &Auth{
					TokenID:       "t1",
					TokenAccessor: "ta1",
					TokenType:     "service_token",
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
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
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
			name:       "omit credential sub-fields",
			omitFields: []string{"response.credential.credential_id", "response.credential.type", "response.credential.category", "response.credential.lease_ttl", "response.credential.lease_id", "response.credential.token_id", "response.credential.source_name", "response.credential.source_type", "response.credential.spec_name", "response.credential.revocable"},
			entry: &LogEntry{
				Timestamp: fixedTS,
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
				Timestamp: fixedTS,
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
			omitFields: []string{"response.auth_result.token_type", "response.auth_result.policies", "response.auth_result.token_ttl"},
			entry: &LogEntry{
				Timestamp: fixedTS,
				Response: &Response{
					AuthResult: &AuthResult{
						TokenType:   "service_token",
						PrincipalID: "user1",
						Policies:    []string{"p1"},
						TokenTTL:    3600,
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

func TestJSONFormatCredentialMetadata(t *testing.T) {
	mockSaltFunc := func(ctx context.Context, data string) (string, error) {
		return "hmac-sha256:" + data, nil
	}

	newEntry := func() *LogEntry {
		return &LogEntry{
			Timestamp: time.Now(),
			Response: &Response{
				StatusCode: 200,
				Credential: &Credential{
					CredentialID: "cred-1",
					Type:         "oauth_bearer_token",
					TokenID:      "tok-1",
					Data:         map[string]string{"api_key": "secret-token"},
					Metadata:     map[string]string{"subject": "alice@example.com", "actor": "agent@example.com"},
				},
			},
		}
	}

	format := func(saltFields []string, entry *LogEntry) Credential {
		f := NewJSONFormat(WithSaltFunc(mockSaltFunc), WithSaltFields(saltFields))
		out, err := f.FormatResponse(context.Background(), entry)
		if err != nil {
			t.Fatalf("FormatResponse: %v", err)
		}
		var got LogEntry
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return *got.Response.Credential
	}

	t.Run("clear by default; data salted", func(t *testing.T) {
		entry := newEntry()
		c := format([]string{"response.credential.data"}, entry)
		if c.Metadata["subject"] != "alice@example.com" {
			t.Errorf("subject should be in clear, got %q", c.Metadata["subject"])
		}
		if !containsBytes([]byte(c.Data["api_key"]), "hmac-sha256:") {
			t.Error("data api_key should be salted")
		}
		// The original entry must be untouched (Clone deep-copy).
		if entry.Response.Credential.Metadata["subject"] != "alice@example.com" {
			t.Error("original metadata mutated by salting (Clone deep-copy missing)")
		}
		if entry.Response.Credential.Data["api_key"] != "secret-token" {
			t.Error("original data mutated by salting")
		}
	})

	t.Run("salt one metadata key", func(t *testing.T) {
		c := format([]string{"response.credential.metadata.subject"}, newEntry())
		if !containsBytes([]byte(c.Metadata["subject"]), "hmac-sha256:") {
			t.Errorf("subject should be salted, got %q", c.Metadata["subject"])
		}
		if c.Metadata["actor"] != "agent@example.com" {
			t.Errorf("actor should stay clear, got %q", c.Metadata["actor"])
		}
	})

	t.Run("salt whole metadata map", func(t *testing.T) {
		c := format([]string{"response.credential.metadata"}, newEntry())
		if !containsBytes([]byte(c.Metadata["subject"]), "hmac-sha256:") {
			t.Error("subject should be salted")
		}
		if !containsBytes([]byte(c.Metadata["actor"]), "hmac-sha256:") {
			t.Error("actor should be salted")
		}
	})
}

// TestJSONFormatPreservesUserAttribution guards a whole class of silent data
// loss: the formatter clones every entry before serialising, so any field
// Clone() forgets is set correctly in memory and then dropped on the way to
// disk. Per-user attribution was lost this way from the day it was added —
// invisible to tests that assert on the in-memory entry, because those sit
// above the layer that loses it.
func TestJSONFormatPreservesUserAttribution(t *testing.T) {
	format := NewJSONFormat()

	newEntry := func() *LogEntry {
		return &LogEntry{
			Timestamp: time.Now(),
			Request:   &Request{ID: "req-1", Operation: "read", Path: "/v1/vault/gateway/x"},
			Auth: &Auth{
				TokenID:     "agent-token",
				PrincipalID: "agent-workload",
				User: &UserAttribution{
					Subject:     "alice@example.com",
					TokenID:     "user-token",
					NamespaceID: "root",
				},
			},
		}
	}

	for _, tc := range []struct {
		name   string
		format func(*LogEntry) ([]byte, error)
	}{
		{"request", func(e *LogEntry) ([]byte, error) {
			return format.FormatRequest(context.Background(), e)
		}},
		{"response", func(e *LogEntry) ([]byte, error) {
			return format.FormatResponse(context.Background(), e)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.format(newEntry())
			if err != nil {
				t.Fatalf("format: %v", err)
			}
			var out LogEntry
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("unmarshal: %v\n%s", err, string(data))
			}
			if out.Auth == nil || out.Auth.User == nil {
				t.Fatalf("user attribution lost between the entry and the wire: %s", string(data))
			}
			if out.Auth.User.Subject != "alice@example.com" {
				t.Errorf("subject = %q, want alice@example.com", out.Auth.User.Subject)
			}
			// The agent must still be there: attribution records the user
			// alongside the agent, never in place of it.
			if out.Auth.PrincipalID != "agent-workload" {
				t.Errorf("agent principal lost: %s", string(data))
			}
		})
	}
}

// TestCloneCopiesUserAttribution pins the specific omission at its source, so a
// future field added to Auth without a matching Clone() line fails here rather
// than silently vanishing from every audit log.
func TestCloneCopiesUserAttribution(t *testing.T) {
	orig := &LogEntry{
		Auth: &Auth{User: &UserAttribution{Subject: "alice", TokenID: "t", NamespaceID: "root"}},
	}
	clone := orig.Clone()

	if clone.Auth == nil || clone.Auth.User == nil {
		t.Fatal("Clone dropped Auth.User")
	}
	if clone.Auth.User.Subject != "alice" {
		t.Errorf("subject = %q, want alice", clone.Auth.User.Subject)
	}
	// Must be a copy, not a shared pointer: entries are cloned precisely so
	// that what one device salts or omits does not reach the next.
	clone.Auth.User.Subject = "mallory"
	if orig.Auth.User.Subject != "alice" {
		t.Error("Clone shares the UserAttribution pointer, defeating the race protection it exists for")
	}
}

// updateGolden rewrites the golden entries from what the format writes now:
//
//	go test ./audit -run TestGoldenEntries -update
var updateGolden = flag.Bool("update", false, "rewrite the golden audit entries")

const (
	goldenPath   = "testdata/golden_entries.txt"
	goldenHeader = "# Generated by go test ./audit -run TestGoldenEntries -update. Do not edit.\n" +
		"# A line \"~ START END TEXT\" is what the default configuration writes for the same\n" +
		"# entry, with TEXT in place of what lies between its first START and last END bytes.\n"
	goldenKey = "golden-hmac-key"
)

// goldenTime is the timestamp of the golden entries built here.
var goldenTime = time.Date(2026, 11, 16, 10, 30, 15, 123456789, time.UTC)

// hostile holds what a JSON string has to escape and what it must leave
// alone: quotes and a backslash, the characters escaped for HTML, control
// characters, DEL, the two Unicode line separators, a replacement character,
// bytes that are not UTF-8, and plain text outside ASCII.
var hostile = "\"q\" \\ <b>&</b> \b\f\n\r\t\x00\x1f \x7f " +
	string(rune(0x2028)) + string(rune(0x2029)) + " " + string(rune(0xFFFD)) +
	" \xff\xc3 caf" + string(rune(0xE9)) + " " + string(rune(0x65E5)) + string(rune(0x672C))

// goldenEntry is one entry of the golden corpus. A narrow entry is one every
// single-path configuration formats: between them the three show what a path
// does to a field that is set, to one that is empty, and to one whose parent
// is missing.
type goldenEntry struct {
	name   string
	entry  *LogEntry
	narrow bool
}

// goldenFull is an entry with every field set, by reflection so that a field
// added later is part of it, then given the shapes one value per field cannot
// show: several elements and keys, empty ones among them, a negative number, a
// pointer to zero, and strings that need escaping, as values and as map keys.
func goldenFull() *LogEntry {
	var e LogEntry
	fill(reflect.ValueOf(&e).Elem())
	e.Timestamp = goldenTime
	e.Error = hostile
	e.Request.Path = hostile

	e.Auth.TokenTTL = -42
	e.Auth.Groups = []string{"ops", "", "dev"}
	e.Auth.Actors = []ActorRef{{Subject: "svc-a", Issuer: "https://idp.example.com"}, {Subject: "svc-b"}}
	e.Auth.Discovery.AdmittedBy = []AdmittedMount{
		{Mount: "jwt", PrincipalID: "principal-1", AliasName: "alias-1", EntityID: "entity-1"},
		{Mount: "cert"},
	}

	results := e.Auth.PolicyResults
	results.GrantingPolicies = []string{"reader", "", "writer"}
	results.Condition.Inputs = map[string]string{
		"agent.metadata.env": "prod",
		"request.data.model": "model-1",
		"agent":              "whole",
		"empty":              "",
		hostile:              hostile,
	}
	zero := 0
	results.MCPDecision.BatchIndex = &zero
	results.MCPDecision.Condition.Inputs = map[string]string{"agent.metadata.env": "prod", "b": "2", "a": "1"}

	e.Response.Warnings = []string{"first", hostile}
	e.Response.Credential.Data = map[string]string{
		"secret_key": "S-SECRET",
		"access_key": "S-ACCESS",
		"empty":      "",
		"Z":          "upper sorts first",
		hostile:      "hostile key",
	}
	e.Response.Credential.Metadata = map[string]string{"email": "alice@example.com", "subject": "sub-1"}
	return &e
}

// goldenEmptyParts is an entry in which every part is present and holds
// nothing: pointers to empty structures, and slices and maps that are empty
// but not nil.
func goldenEmptyParts() *LogEntry {
	return &LogEntry{
		Timestamp: goldenTime,
		Request:   &Request{},
		Response: &Response{
			Warnings:   []string{},
			Credential: &Credential{Data: map[string]string{}, Metadata: map[string]string{}},
			AuthResult: &AuthResult{Policies: []string{}},
		},
		Auth: &Auth{
			Policies: []string{},
			Groups:   []string{},
			Actors:   []ActorRef{},
			PolicyResults: &PolicyResults{
				GrantingPolicies: []string{},
				MCPDecision: &logical.MCPDecision{
					BatchIndex: new(int),
					Condition:  &logical.ConditionResult{Inputs: map[string]string{}},
				},
				MCPClient: &MCPClientInfo{},
				Condition: &logical.ConditionResult{Inputs: map[string]string{}},
			},
			User:      &UserAttribution{Actors: []ActorRef{}},
			Discovery: &DiscoveryAuth{AdmittedBy: []AdmittedMount{}},
		},
	}
}

// goldenManyKeys is a map of twenty keys, k01 to k20, some of them empty.
func goldenManyKeys(value string) map[string]string {
	m := make(map[string]string, 20)
	for n := 1; n <= 20; n++ {
		m[fmt.Sprintf("k%02d", n)] = fmt.Sprintf("%s-%d", value, n)
	}
	m["k05"], m["k13"] = "", ""
	return m
}

// goldenEntries are the entries of the golden corpus: the three narrow ones,
// then entries as requests produce them.
func goldenEntries() []goldenEntry {
	return []goldenEntry{
		{name: "zero", entry: &LogEntry{}, narrow: true},
		{name: "empty-parts", entry: goldenEmptyParts(), narrow: true},
		{name: "full", entry: goldenFull(), narrow: true},
		{name: "gateway-request", entry: gatewayRequestEntry()},
		{name: "gateway-response", entry: gatewayResponseEntry()},
		{name: "login", entry: &LogEntry{
			Timestamp: goldenTime,
			Request: &Request{
				ID: "req-login", Operation: "create", Path: "auth/jwt/login",
				MountPoint: "auth/jwt/", MountType: "jwt", MountClass: "auth",
				Method: "POST", ClientIP: "203.0.113.7",
				NamespaceID: "ns-1", NamespacePath: "team-a/", Unauthenticated: true,
			},
			Response: &Response{
				StatusCode: 200, StatusMessage: "OK", MountClass: "auth",
				Warnings: []string{"token ttl capped"},
				AuthResult: &AuthResult{
					TokenType: logical.TokenTypeIdentity, PrincipalID: "agent-7",
					Policies: []string{"default"}, TokenTTL: 3600,
				},
			},
		}},
		{name: "denied", entry: &LogEntry{
			Timestamp: goldenTime,
			Request: &Request{
				ID: "req-denied", Operation: "read", Path: "vault/role/reader/gateway/v1/secret/data/app",
				MountPoint: "vault/", MountType: "vault", MountClass: "provider",
				Method: "GET", ClientIP: "198.51.100.23",
			},
			Response: &Response{StatusCode: 403},
			Auth: &Auth{
				TokenID: "tok-denied", TokenType: logical.TokenTypeTicket, PrincipalID: "bob@example.com",
				RoleDeniedReason: "not assumable", IdentityStatus: "unclaimed",
				AuthTime: 1794826215, DPoPJKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", ProofID: "a1b2c3d4",
				PolicyResults: &PolicyResults{
					DenyingPolicy: "guard",
					Condition: &logical.ConditionResult{
						Decision:   "deny",
						Expression: "agent.metadata.env == 'prod' && user.email.endsWith('@example.com')",
						ErrorKind:  "no_such_key",
						UserAbsent: true,
						Inputs:     map[string]string{"agent.metadata.env": "staging", "request.data.model": "model-1"},
					},
				},
			},
			Error: "permission denied; 1 error occurred",
		}},
		{name: "discovery", entry: &LogEntry{
			Timestamp: goldenTime,
			Request: &Request{
				ID: "req-discovery", Operation: "update", Path: "sys/mcp",
				MountPoint: "sys/", MountType: "system", MountClass: "system",
				Method: "POST", ClientIP: "10.0.0.9",
			},
			Response: &Response{StatusCode: 200},
			Auth: &Auth{
				PrincipalID: "agent-7", AliasName: "alias-7", SponsoredBy: "group:sponsors",
				Actors: []ActorRef{{Subject: "orchestrator", Issuer: "https://idp.example.com"}, {Subject: "gateway"}},
				User: &UserAttribution{
					Subject: "carol", TokenID: "tok-user", NamespaceID: "ns-1", NamespacePath: "team-a/",
					Actors: []ActorRef{{Subject: "portal"}},
				},
				Discovery: &DiscoveryAuth{
					AdmittedBy: []AdmittedMount{
						{Mount: "jwt", PrincipalID: "agent-7", AliasName: "alias-7", EntityID: "entity-7"},
						{Mount: "cert", PrincipalID: "CN=agent-7"},
					},
					RolesGranted: 2,
				},
			},
		}},
		// Maps with more keys than the encoder sorts in place.
		{name: "many-keys", entry: &LogEntry{
			Timestamp: goldenTime,
			Request:   &Request{ID: "req-many-keys", Operation: "read", Path: "vault/creds", Method: "GET", ClientIP: "10.0.0.9"},
			Response: &Response{StatusCode: 200, Credential: &Credential{
				CredentialID: "cred-many-keys", Type: "vault_token", TokenID: "tok-many-keys",
				Data: goldenManyKeys("secret"), Metadata: goldenManyKeys("meta"),
			}},
			Auth: &Auth{PolicyResults: &PolicyResults{Allowed: true, Condition: &logical.ConditionResult{
				Decision: "allow", Inputs: goldenManyKeys("input"),
			}}},
		}},
		{name: "discovery-anonymous", entry: &LogEntry{
			Timestamp: goldenTime,
			Request:   &Request{ID: "req-anonymous", Operation: "update", Path: "sys/mcp", Method: "POST", ClientIP: "10.0.0.9"},
			Auth:      &Auth{Discovery: &DiscoveryAuth{Anonymous: true, CredentialUnverified: true}},
		}},
	}
}

// goldenFormat is one device configuration of the golden corpus. A broad one
// formats every entry, as a request and as a response; the others, which set
// a single path, format the narrow entries as responses.
type goldenFormat struct {
	name   string
	format *JSONFormat
	broad  bool
}

// goldenFormats are the configurations of the golden corpus: devices as the
// factory builds them, formats built directly in the ways the factory never
// does, and one device for each salt path and each omit path.
func goldenFormats(t *testing.T) []goldenFormat {
	t.Helper()

	// device is the format the factory gives a device with this configuration.
	device := func(config map[string]any) *JSONFormat {
		conf, err := mapToFileDeviceConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		format, _ := jsonFormatFor(conf)
		return format
	}
	hmac := NewHMACer(goldenKey).SaltFunc()
	const (
		credentialData = "response.credential.data"
		credentialMeta = "response.credential.metadata"
		inputs         = "auth.policy_results.condition.inputs"
	)

	formats := []goldenFormat{
		{name: "default", broad: true, format: device(map[string]any{"hmac_key": goldenKey})},
		{name: "no-key", broad: true, format: device(map[string]any{})},
		{name: "prefix", broad: true, format: device(map[string]any{"hmac_key": goldenKey, "prefix": "@cee:"})},
		{name: "every-salt-path", broad: true, format: device(map[string]any{
			"hmac_key": goldenKey, "salt_fields": acceptedSaltPaths,
		})},
		{name: "every-salt-path-no-key", broad: true, format: device(map[string]any{
			"salt_fields": acceptedSaltPaths,
		})},
		{name: "operator-example", broad: true, format: device(map[string]any{
			"hmac_key":    goldenKey,
			"salt_fields": []string{"auth.principal_id", "request.client_ip"},
			"omit_fields": []string{"auth.policy_results.mcp_client"},
		})},
		// A field both salted and omitted is omitted.
		{name: "salted-and-omitted", broad: true, format: device(map[string]any{
			"hmac_key":    goldenKey,
			"salt_fields": []string{"auth.principal_id", "request.client_ip", credentialMeta, inputs},
			"omit_fields": []string{"auth.principal_id", "request.client_ip", credentialMeta + ".email", inputs + ".agent.metadata.env"},
		})},
		// A map that loses its keys one by one is not written at all once it
		// has none left.
		{name: "maps-emptied-by-key", broad: true, format: device(map[string]any{
			"hmac_key": goldenKey,
			"omit_fields": []string{
				credentialData + ".token", credentialData + ".secret_key", credentialData + ".access_key",
				credentialData + ".empty", credentialData + ".Z",
				credentialMeta + ".subject", credentialMeta + ".email",
				inputs + ".agent.metadata.env", inputs + ".request.data.model", inputs + ".agent", inputs + ".empty",
			},
		})},
		// The same key of a map salted and omitted, a key salted in a map that
		// is omitted, and a map both salted and omitted: omitted, each time.
		{name: "map-key-salted-and-omitted", broad: true, format: device(map[string]any{
			"hmac_key":    goldenKey,
			"salt_fields": []string{credentialMeta + ".email", credentialMeta + ".subject", inputs + ".agent", inputs + ".k07"},
			"omit_fields": []string{credentialMeta + ".email", credentialData + ".secret_key", credentialData + ".k07", inputs + ".agent", inputs + ".k07"},
		})},
		{name: "map-key-salted-in-omitted-map", broad: true, format: device(map[string]any{
			"hmac_key":    goldenKey,
			"salt_fields": []string{credentialMeta + ".email", inputs + ".agent.metadata.env"},
			"omit_fields": []string{credentialData, credentialMeta, inputs},
		})},
		{name: "maps-salted-and-omitted", broad: true, format: device(map[string]any{
			"hmac_key":    goldenKey,
			"salt_fields": []string{credentialMeta, inputs},
			"omit_fields": []string{credentialMeta, inputs},
		})},
		{name: "whole-parts-omitted", broad: true, format: device(map[string]any{
			"hmac_key": goldenKey, "omit_fields": []string{"auth", "request", "response", "error"},
		})},
		// Two listed keys, one of whose names starts with the other's: the
		// longer one is taken for a key below the shorter and left in clear.
		{name: "input-key-prefix-of-another", broad: true, format: device(map[string]any{
			"hmac_key": goldenKey, "salt_fields": []string{inputs + ".agent", inputs + ".agent.metadata.env"},
		})},

		// A path and a path below it, and a path listed twice: each value is
		// salted once per path that reaches it. The factory never builds this.
		{name: "direct-overlapping-salt-paths", broad: true, format: NewJSONFormat(
			WithSaltFunc(hmac),
			WithSaltFields([]string{
				credentialData, credentialData + ".secret_key",
				"auth.principal_id", "auth.principal_id",
				inputs, inputs + ".agent",
			}),
		)},
		{name: "direct-salt-paths-without-salt-function", broad: true, format: NewJSONFormat(
			WithSaltFields(acceptedSaltPaths),
		)},
		{name: "direct-salt-paths-before-salt-function", broad: true, format: NewJSONFormat(
			WithSaltFields([]string{"auth.token_id", credentialData}),
			WithSaltFunc(hmac),
		)},
		{name: "direct-unknown-paths", broad: true, format: NewJSONFormat(
			WithSaltFunc(hmac),
			WithSaltFields([]string{"agent.metadata.env", "auth.token_id", "auth"}),
			WithOmitFields([]string{"request.headers", "no.such.field", "request.client_ip"}),
		)},
		{name: "direct-salt-function-fails", broad: true, format: NewJSONFormat(
			WithSaltFunc(func(context.Context, string) (string, error) { return "", errors.New("no salt") }),
			WithSaltFields([]string{"auth.token_id", credentialData}),
		)},
	}

	for _, p := range acceptedSaltPaths {
		formats = append(formats, goldenFormat{name: "salt " + p, format: device(map[string]any{
			"hmac_key": goldenKey, "salt_fields": []string{p},
		})})
	}
	omit := append(entryFieldPaths(),
		inputs, inputs+".agent.metadata.env", inputs+".agent",
		credentialData+".secret_key", credentialMeta+".email",
		// Retired: no entry records these any more.
		"request.data", "request.headers", "response.data", "response.headers",
		"request.data.password", "request.headers.Authorization",
	)
	for _, p := range omit {
		formats = append(formats, goldenFormat{name: "omit " + p, format: device(map[string]any{
			"hmac_key": goldenKey, "omit_fields": []string{p},
		})})
	}
	return formats
}

// goldenBaseFormat names the configuration every other one is compared with.
const goldenBaseFormat = "default"

// goldenRecord is one line a format writes for an entry. A record with a base
// is held in the golden file as its difference from the record of that name:
// a configuration changes a few bytes of what the default one writes for the
// same entry, and the difference is what there is to review.
type goldenRecord struct {
	name string
	line string
	base string
}

// goldenRecords formats the corpus.
func goldenRecords(t *testing.T) []goldenRecord {
	t.Helper()
	ctx := context.Background()
	entries := goldenEntries()

	var records []goldenRecord
	seen := map[string]bool{}
	add := func(name, base string, line []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if seen[name] {
			t.Fatalf("%s: two records share this name", name)
		}
		if base != "" && !seen[base] {
			t.Fatalf("%s: its base %q is not a record before it", name, base)
		}
		if strings.ContainsRune(string(line), '\n') || strings.HasPrefix(string(line), goldenDeltaMark) {
			t.Fatalf("%s: not an entry the golden file can hold on one line: %q", name, line)
		}
		seen[name] = true
		records = append(records, goldenRecord{name: name, line: string(line), base: base})
	}
	for _, f := range goldenFormats(t) {
		for _, e := range entries {
			if !f.broad && !e.narrow {
				continue
			}
			// Only the default configuration's records are held whole.
			name := func(format, kind string) string { return format + " | " + e.name + " | " + kind }
			base := func(kind string) string {
				if f.name == goldenBaseFormat {
					return ""
				}
				return name(goldenBaseFormat, kind)
			}
			if f.broad {
				line, err := f.format.FormatRequest(ctx, e.entry)
				add(name(f.name, "request"), base("request"), line, err)
			}
			line, err := f.format.FormatResponse(ctx, e.entry)
			add(name(f.name, "response"), base("response"), line, err)
		}
	}

	// Every format was handed the same entries: none may have changed one.
	for i, fresh := range goldenEntries() {
		if !reflect.DeepEqual(entries[i].entry, fresh.entry) {
			t.Errorf("formatting changed the %s entry", fresh.name)
		}
	}
	return records
}

// The bytes a device writes for an entry are a released format: log shippers
// and the tools that read them parse it, and a salted value must stay the one
// sys/audit-hash computes. The golden file holds what every configuration
// writes for every entry of the corpus, byte for byte. A change to the
// structures, the paths or the encoding shows here as the records it changes.
func TestGoldenEntries(t *testing.T) {
	records := goldenRecords(t)
	lineOf := map[string]string{}
	var got strings.Builder
	got.WriteString(goldenHeader)
	for _, r := range records {
		lineOf[r.name] = r.line
		held := r.line
		if r.base != "" {
			held = goldenDelta(lineOf[r.base], r.line)
		}
		fmt.Fprintf(&got, "=== %s\n%s\n", r.name, held)
	}

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	const regenerate = "if the change is intended: go test ./audit -run TestGoldenEntries -update"
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("%v; %s", err, regenerate)
	}
	if string(raw) == got.String() {
		return
	}

	// Name the records that changed, not the whole file.
	held := map[string]string{}
	lines := strings.Split(string(raw), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if name, ok := strings.CutPrefix(lines[i], "=== "); ok {
			held[name] = lines[i+1]
			i++
		}
	}
	want := map[string]string{}
	for _, r := range records {
		line, ok := held[r.name]
		if !ok {
			continue
		}
		if strings.HasPrefix(line, goldenDeltaMark) {
			line, err = goldenApply(want[r.base], line)
			if err != nil {
				t.Fatalf("%s: %v; %s", r.name, err, regenerate)
			}
		}
		want[r.name] = line
	}
	differ := 0
	for _, r := range records {
		line, ok := want[r.name]
		switch {
		case !ok:
			t.Errorf("%s: not in the golden file", r.name)
		case line != r.line:
			t.Errorf("%s:\n got %s\nwant %s", r.name, r.line, line)
		default:
			continue
		}
		if differ++; differ == 10 {
			t.Fatalf("more records differ; %s", regenerate)
		}
	}
	if len(held) != len(records) {
		t.Errorf("the golden file holds %d records, the corpus %d", len(held), len(records))
	}
	t.Log(regenerate)
	if !t.Failed() {
		t.Error("the golden file and the corpus hold the same records in a different layout")
	}
}

// randomStrings are the strings randomValue picks from, beside those it makes
// up: each holds something the encoder treats in a way of its own.
var randomStrings = []string{
	"x", "a plain value", "with space ", "42", "null", "{}",
	hostile,
	"quote \" backslash \\ slash /",
	"<script>&amp;</script>",
	"tab\there, newline\nthere, return\r, bell\a, null\x00, escape\x1b, del\x7f",
	"not UTF-8: \xff \xc3 \xe2\x82 \xf0\x9f\x98",
	"separators " + string(rune(0x2028)) + string(rune(0x2029)),
	"replacement " + string(rune(0xFFFD)) + " private " + string(rune(0xE000)) + " astral " + string(rune(0x1F600)),
	strings.Repeat("long ", 200),
}

// randomString is a string picked from randomStrings, or made of bytes drawn
// one by one: letters, the characters JSON and HTML escape, control
// characters, and bytes that are UTF-8 only by chance.
func randomString(r *rand.Rand) string {
	if r.IntN(3) > 0 {
		return randomStrings[r.IntN(len(randomStrings))]
	}
	const letters = "abcXYZ019 _-./:@"
	const escaped = "\"\\<>&\b\f\n\r\t\x00\x01\x1f\x7f"
	b := make([]byte, r.IntN(12))
	for i := range b {
		switch r.IntN(4) {
		case 0:
			b[i] = escaped[r.IntN(len(escaped))]
		case 1:
			b[i] = byte(0x80 + r.IntN(0x80))
		default:
			b[i] = letters[r.IntN(len(letters))]
		}
	}
	return string(b)
}

// randomTimes are the timestamps randomValue picks from: the zero time, times
// with and without a fraction of a second, and times away from UTC.
var randomTimes = []time.Time{
	{},
	goldenTime,
	time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	time.Date(2026, 1, 2, 3, 4, 5, 120000000, time.FixedZone("east", 5*3600+30*60)),
	time.Date(1999, 12, 31, 23, 59, 59, 999999000, time.FixedZone("west", -8*3600)),
}

// randomValue sets v, and everything below it, at random. Every kind of
// field takes each value its encoding has a rule for: empty and not, zero,
// negative and extreme numbers, a nil pointer and one to a zero value, a nil,
// an empty and a filled slice or map, a map with more keys than the encoder
// sorts without allocating.
func randomValue(v reflect.Value, r *rand.Rand) {
	switch v.Kind() {
	case reflect.Pointer:
		if r.IntN(3) == 0 {
			v.SetZero()
			return
		}
		v.Set(reflect.New(v.Type().Elem()))
		// One in four stays a pointer to a zero value.
		if r.IntN(4) > 0 {
			randomValue(v.Elem(), r)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(randomTimes[r.IntN(len(randomTimes))]))
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				randomValue(v.Field(i), r)
			}
		}
	case reflect.Slice:
		switch r.IntN(4) {
		case 0:
			v.SetZero()
		case 1:
			v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		default:
			s := reflect.MakeSlice(v.Type(), 1+r.IntN(3), 4)
			for i := range s.Len() {
				randomValue(s.Index(i), r)
			}
			v.Set(s)
		}
	case reflect.Map:
		switch r.IntN(4) {
		case 0:
			v.SetZero()
		case 1:
			v.Set(reflect.MakeMap(v.Type()))
		default:
			m := reflect.MakeMap(v.Type())
			for range 1 + r.IntN(24) {
				k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
				randomValue(k, r)
				randomValue(e, r)
				m.SetMapIndex(k, e)
			}
			v.Set(m)
		}
	case reflect.String:
		if r.IntN(3) == 0 {
			v.SetString("")
			return
		}
		v.SetString(randomString(r))
	case reflect.Bool:
		v.SetBool(r.IntN(2) == 0)
	case reflect.Int, reflect.Int64:
		numbers := []int64{0, 0, 1, -1, 42, -42, 1794829815, math.MaxInt64, math.MinInt64}
		v.SetInt(numbers[r.IntN(len(numbers))])
	default:
		panic(fmt.Sprintf("randomValue: an audit entry holds a %s, which this test cannot fill", v.Kind()))
	}
}

// firstDifference shows where two encodings part: the bytes around the first
// one that differs.
func firstDifference(got, want []byte) string {
	at := 0
	for at < len(got) && at < len(want) && got[at] == want[at] {
		at++
	}
	around := func(b []byte) string {
		return fmt.Sprintf("%q", b[max(0, at-60):min(len(b), at+60)])
	}
	return fmt.Sprintf("at byte %d:\n got %s\nwant %s", at, around(got), around(want))
}

// The encoder writes an entry byte for byte as encoding/json does. The format
// is a released one, and encoding/json is its definition: a field the encoder
// leaves out or misplaces, an omitempty it applies wrongly, a character it
// escapes differently, a map it orders otherwise each fail here. Entries are
// filled by reflection, so a field added to a structure is part of the test
// the day it is added.
func TestEncoderMatchesEncodingJSON(t *testing.T) {
	check := func(t *testing.T, name string, entry *LogEntry) bool {
		t.Helper()
		want, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("%s: encoding/json: %v", name, err)
		}
		enc := jsonEncoder{}
		if err := enc.entry(entry); err != nil {
			t.Fatalf("%s: the encoder: %v", name, err)
		}
		if string(enc.buf) != string(want) {
			t.Errorf("%s: the encoder differs from encoding/json %s", name, firstDifference(enc.buf, want))
			return false
		}
		return true
	}

	for _, e := range goldenEntries() {
		check(t, e.name, e.entry)
	}

	r := rand.New(rand.NewPCG(2026, 1117))
	for n := range 5000 {
		var entry LogEntry
		randomValue(reflect.ValueOf(&entry).Elem(), r)
		if !check(t, fmt.Sprintf("random entry %d", n), &entry) {
			return
		}
	}
}

// A timestamp encoding/json refuses is refused by the encoder too, where it
// would otherwise write a year no parser of the format reads.
func TestEncoder_RefusesWhatEncodingJSONRefuses(t *testing.T) {
	entry := &LogEntry{Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := json.Marshal(entry); err == nil {
		t.Fatal("encoding/json accepts a five-digit year, so this test shows nothing")
	}
	enc := jsonEncoder{}
	if err := enc.entry(entry); err == nil {
		t.Errorf("the encoder wrote %s", enc.buf)
	}
}

// FuzzAppendJSONString holds the encoder's strings to encoding/json's: what
// is escaped, how, and what is done with bytes that are not UTF-8. Its seeds,
// which every test run goes through, are each single byte and the strings
// the random entries use.
func FuzzAppendJSONString(f *testing.F) {
	for b := range 256 {
		f.Add(string([]byte{byte(b)}))
	}
	for _, s := range randomStrings {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		want, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if got := appendJSONString(nil, s); string(got) != string(want) {
			t.Errorf("%q: the encoder differs from encoding/json %s", s, firstDifference(got, want))
		}
	})
}

// goldenDeltaMark starts a line of the golden file that holds a difference.
const goldenDeltaMark = "~ "

// goldenDelta is line as its difference from base: how many bytes they share
// at the start, how many at the end, and what line holds between the two. The
// counts stop at character boundaries, so the golden file stays readable text.
func goldenDelta(base, line string) string {
	start := 0
	for start < len(base) && start < len(line) && base[start] == line[start] {
		start++
	}
	for start > 0 && start < len(line) && !utf8.RuneStart(line[start]) {
		start--
	}
	end := 0
	for end < len(base)-start && end < len(line)-start && base[len(base)-1-end] == line[len(line)-1-end] {
		end++
	}
	for end > 0 && !utf8.RuneStart(line[len(line)-end]) {
		end--
	}
	if start+end == len(line) {
		return fmt.Sprintf("%s%d %d", goldenDeltaMark, start, end)
	}
	return fmt.Sprintf("%s%d %d %s", goldenDeltaMark, start, end, line[start:len(line)-end])
}

// goldenApply is the line that delta, a difference from base, stands for.
func goldenApply(base, delta string) (string, error) {
	parts := strings.SplitN(strings.TrimPrefix(delta, goldenDeltaMark), " ", 3)
	if len(parts) == 2 {
		parts = append(parts, "")
	}
	if len(parts) != 3 {
		return "", fmt.Errorf("unreadable difference %q", delta)
	}
	start, errStart := strconv.Atoi(parts[0])
	end, errEnd := strconv.Atoi(parts[1])
	if errStart != nil || errEnd != nil || start < 0 || end < 0 || start+end > len(base) {
		return "", fmt.Errorf("difference %q does not fit its base", delta)
	}
	return base[:start] + parts[2] + base[len(base)-end:], nil
}
