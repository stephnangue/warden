package audit

import (
	"testing"
	"time"
)

func TestCloneNil(t *testing.T) {
	var entry *LogEntry
	if entry.Clone() != nil {
		t.Error("Clone of nil should return nil")
	}
}

func TestCloneFull(t *testing.T) {
	entry := &LogEntry{
		Type:      "request",
		Timestamp: time.Now(),
		Error:     "some error",
		Request: &Request{
			ID:              "req-1",
			Operation:       "read",
			Path:            "/test",
			MountPoint:      "mp",
			MountType:       "vault",
			MountClass:      "provider",
			Method:          "GET",
			ClientIP:        "1.2.3.4",
			Headers:         map[string][]string{"X-Token": {"val1", "val2"}},
			Data:            map[string]any{"key": "value", "nested": map[string]any{"a": "b"}},
			NamespaceID:     "ns1",
			NamespacePath:   "root/",
			Unauthenticated: true,
			Streamed:        true,
			Transparent:     true,
		},
		Response: &Response{
			StatusCode:    200,
			StatusMessage: "OK",
			MountClass:    "provider",
			Streamed:      true,
			UpstreamURL:   "http://upstream",
			Headers:       map[string][]string{"Content-Type": {"application/json"}},
			Data:          map[string]any{"result": "ok"},
			Warnings:      []string{"warn1"},
			Credential: &Credential{
				CredentialID: "cred-1",
				Type:         "aws",
				Category:     "cloud",
				LeaseTTL:     3600,
				LeaseID:      "lease-1",
				TokenID:      "token-1",
				SourceName:   "src",
				SourceType:   "local",
				SpecName:     "spec",
				Revocable:    true,
				Data:         map[string]string{"access_key": "AK", "secret_key": "SK"},
			},
			AuthResult: &AuthResult{
				TokenType:      "service",
				PrincipalID:    "user1",
				RoleName:       "admin",
				Policies:       []string{"pol1", "pol2"},
				TokenTTL:       7200,
				CredentialSpec: "spec-1",
			},
		},
		Auth: &Auth{
			TokenID:       "t1",
			TokenAccessor: "ta1",
			TokenType:     "service",
			PrincipalID:   "p1",
			RoleName:      "r1",
			Policies:      []string{"policy1"},
			PolicyResults: &PolicyResults{
				Allowed:          true,
				GrantingPolicies: []string{"gp1"},
			},
			TokenTTL:      3600,
			ExpiresAt:     1234567890,
			NamespaceID:   "ns1",
			NamespacePath: "root/",
			CreatedByIP:   "10.0.0.1",
		},
	}

	clone := entry.Clone()

	// Verify independence - modify original and check clone is unaffected
	entry.Request.Headers["X-Token"][0] = "modified"
	if clone.Request.Headers["X-Token"][0] == "modified" {
		t.Error("clone headers should be independent")
	}

	entry.Request.Data["key"] = "modified"
	if clone.Request.Data["key"] == "modified" {
		t.Error("clone data should be independent")
	}

	entry.Response.Credential.Data["access_key"] = "modified"
	if clone.Response.Credential.Data["access_key"] == "modified" {
		t.Error("clone credential data should be independent")
	}

	entry.Auth.Policies[0] = "modified"
	if clone.Auth.Policies[0] == "modified" {
		t.Error("clone auth policies should be independent")
	}

	entry.Auth.PolicyResults.GrantingPolicies[0] = "modified"
	if clone.Auth.PolicyResults.GrantingPolicies[0] == "modified" {
		t.Error("clone granting policies should be independent")
	}

	entry.Response.Warnings[0] = "modified"
	if clone.Response.Warnings[0] == "modified" {
		t.Error("clone warnings should be independent")
	}

	entry.Response.AuthResult.Policies[0] = "modified"
	if clone.Response.AuthResult.Policies[0] == "modified" {
		t.Error("clone auth result policies should be independent")
	}
}

func TestCloneValue(t *testing.T) {
	// Test various types through cloneValue
	if cloneValue(nil) != nil {
		t.Error("nil should clone to nil")
	}

	// map[string]any
	m := map[string]any{"a": "b"}
	cm := cloneValue(m).(map[string]any)
	m["a"] = "modified"
	if cm["a"] == "modified" {
		t.Error("cloned map should be independent")
	}

	// map[string]string
	ms := map[string]string{"x": "y"}
	cms := cloneValue(ms).(map[string]string)
	ms["x"] = "modified"
	if cms["x"] == "modified" {
		t.Error("cloned string map should be independent")
	}

	// []any
	sa := []any{"a", "b"}
	csa := cloneValue(sa).([]any)
	sa[0] = "modified"
	if csa[0] == "modified" {
		t.Error("cloned slice should be independent")
	}

	// []string
	ss := []string{"a", "b"}
	css := cloneValue(ss).([]string)
	ss[0] = "modified"
	if css[0] == "modified" {
		t.Error("cloned string slice should be independent")
	}

	// primitive
	if cloneValue(42) != 42 {
		t.Error("primitive should clone to same value")
	}
	if cloneValue("hello") != "hello" {
		t.Error("string should clone to same value")
	}
	if cloneValue(true) != true {
		t.Error("bool should clone to same value")
	}
}

func TestCloneHeaders(t *testing.T) {
	if cloneHeaders(nil) != nil {
		t.Error("nil headers should clone to nil")
	}

	h := map[string][]string{
		"X-Token": {"val1"},
		"Empty":   nil,
	}
	ch := cloneHeaders(h)
	h["X-Token"][0] = "modified"
	if ch["X-Token"][0] == "modified" {
		t.Error("cloned headers should be independent")
	}
	if ch["Empty"] != nil {
		t.Error("nil header values should stay nil")
	}
}

func TestCloneMapAnyNil(t *testing.T) {
	if cloneMapAny(nil) != nil {
		t.Error("nil map should clone to nil")
	}
}
