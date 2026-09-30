package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stephnangue/warden/logical"
)

// TestCloneUserAttribution: the user's chain is deep-copied. The user struct is
// copied by value, which alone would share the Actors backing array between the
// entry and every clone a device writes — a race under multiple audit devices.
func TestCloneUserAttribution(t *testing.T) {
	entry := &LogEntry{Auth: &Auth{User: &UserAttribution{
		Subject:       "alice",
		NamespacePath: "team-payments/orders/",
		RoleName:      "users",
		Actors:        []ActorRef{{Subject: "broker-beta", Issuer: "https://idp.example.com"}},
	}}}

	clone := entry.Clone()
	entry.Auth.User.Actors[0].Subject = "modified"
	entry.Auth.User.RoleName = "modified"

	if got := clone.Auth.User.Actors[0]; got != (ActorRef{Subject: "broker-beta", Issuer: "https://idp.example.com"}) {
		t.Errorf("clone shares the user's actor chain: %+v", got)
	}
	if clone.Auth.User.RoleName != "users" || clone.Auth.User.NamespacePath != "team-payments/orders/" {
		t.Errorf("clone user fields mismatch: %+v", clone.Auth.User)
	}
}

// TestUserAttribution_JSONCompat: every new field is omitempty, so an entry that
// carries none of them serializes exactly as it did before they existed — an
// existing log consumer sees no new keys until there is something to report.
func TestUserAttribution_JSONCompat(t *testing.T) {
	b, err := json.Marshal(&Auth{
		Actors: []ActorRef{{Subject: "orchestrator"}},
		User:   &UserAttribution{Subject: "alice", TokenID: "t1", NamespaceID: "root"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"actors":[{"subject":"orchestrator"}],"user":{"subject":"alice","token_id":"t1","namespace_id":"root"}}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}

	// With the new data present, the wire keys are pinned: consumers bind to them.
	b, err = json.Marshal(&Auth{
		Actors: []ActorRef{{Subject: "orchestrator", Issuer: "https://idp.example.com"}},
		User: &UserAttribution{
			Subject: "alice", TokenID: "t1", NamespaceID: "ns-77c0d4",
			NamespacePath: "team-payments/orders/", RoleName: "users",
			Actors: []ActorRef{{Subject: "broker-beta", Issuer: "https://idp.example.com"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want = `{"actors":[{"subject":"orchestrator","issuer":"https://idp.example.com"}],` +
		`"user":{"subject":"alice","token_id":"t1","namespace_id":"ns-77c0d4",` +
		`"namespace_path":"team-payments/orders/","role_name":"users",` +
		`"actors":[{"subject":"broker-beta","issuer":"https://idp.example.com"}]}}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

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
				MCPDecision: &logical.MCPDecision{
					Method:      "tools/call",
					Name:        "get_repository",
					Decision:    "allow",
					MatchedRule: "get_*",
					RuleType:    "allowed_tools",
				},
			},
			TokenTTL:      3600,
			ExpiresAt:     1234567890,
			NamespaceID:   "ns1",
			NamespacePath: "root/",
			CreatedByIP:   "10.0.0.1",
			Actors: []ActorRef{
				{Subject: "agent-alpha@pod-xyz"},
				{Subject: "broker-beta"},
			},
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

	entry.Auth.PolicyResults.MCPDecision.Name = "modified"
	if clone.Auth.PolicyResults.MCPDecision.Name == "modified" {
		t.Error("clone MCPDecision should be independent")
	}

	entry.Response.Warnings[0] = "modified"
	if clone.Response.Warnings[0] == "modified" {
		t.Error("clone warnings should be independent")
	}

	entry.Response.AuthResult.Policies[0] = "modified"
	if clone.Response.AuthResult.Policies[0] == "modified" {
		t.Error("clone auth result policies should be independent")
	}

	entry.Auth.Actors[0].Subject = "modified"
	if clone.Auth.Actors[0].Subject == "modified" {
		t.Error("clone auth actors should be independent")
	}
	if len(clone.Auth.Actors) != 2 {
		t.Errorf("clone auth actors should have 2 entries, got %d", len(clone.Auth.Actors))
	}
	if clone.Auth.Actors[1].Subject != "broker-beta" {
		t.Errorf("clone auth actors[1] mismatch: %+v", clone.Auth.Actors[1])
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
