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

// TestCloneRoleGrant: the role-grant fields survive Clone, and the groups are
// copied, not aliased: the entry's slice may come from a membership every
// request of a credential shares.
func TestCloneRoleGrant(t *testing.T) {
	entry := &LogEntry{Auth: &Auth{
		RoleName:         "deploy",
		RoleGrantedBy:    "group:deployers",
		RoleDeniedReason: "not assumable",
		Groups:           []string{"deployers", "readers"},
	}}

	clone := entry.Clone()
	entry.Auth.Groups[0] = "modified"
	entry.Auth.RoleGrantedBy = "modified"
	entry.Auth.RoleDeniedReason = "modified"

	if clone.Auth.RoleGrantedBy != "group:deployers" || clone.Auth.RoleDeniedReason != "not assumable" {
		t.Errorf("clone role grant fields mismatch: %+v", clone.Auth)
	}
	if len(clone.Auth.Groups) != 2 || clone.Auth.Groups[0] != "deployers" || clone.Auth.Groups[1] != "readers" {
		t.Errorf("clone shares or drops the groups: %v", clone.Auth.Groups)
	}
}

// The native identity fields survive a clone, and the clone does not share the
// admitted mounts with the original.
func TestCloneNativeIdentity(t *testing.T) {
	entry := &LogEntry{Auth: &Auth{
		MountAccessor: "auth_jwt_1",
		AliasName:     "repo:acme/x",
		EntityKind:    "agent",
		Discovery:     &DiscoveryAuth{AdmittedBy: []AdmittedMount{{Mount: "jwt/", AliasName: "repo:acme/x"}}},
	}}
	clone := entry.Clone()
	entry.Auth.Discovery.AdmittedBy[0].AliasName = "modified"
	if clone.Auth.MountAccessor != "auth_jwt_1" || clone.Auth.AliasName != "repo:acme/x" || clone.Auth.EntityKind != "agent" {
		t.Errorf("clone drops a native identity field: %+v", clone.Auth)
	}
	if clone.Auth.Discovery.AdmittedBy[0].AliasName != "repo:acme/x" {
		t.Errorf("clone shares the admitted mounts: %+v", clone.Auth.Discovery.AdmittedBy)
	}

	b, err := json.Marshal(&Auth{MountAccessor: "auth_jwt_1", AliasName: "a", EntityKind: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"mount_accessor":"auth_jwt_1","alias_name":"a","entity_kind":"agent"}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

// TestRoleGrant_JSONKeys: the new keys are omitempty, so an entry for a token
// that carries its role serializes as before, and the wire names are pinned.
func TestRoleGrant_JSONKeys(t *testing.T) {
	b, err := json.Marshal(&Auth{RoleName: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"role_name":"deploy"}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}

	b, err = json.Marshal(&Auth{RoleName: "deploy", RoleGrantedBy: "group:deployers", Groups: []string{"deployers"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"role_name":"deploy","role_granted_by":"group:deployers","groups":["deployers"]}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}

	b, err = json.Marshal(&Auth{RoleName: "", RoleDeniedReason: "role not found"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"role_denied_reason":"role not found"}`; string(b) != want {
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
				TokenType:   "service",
				PrincipalID: "user1",
				Policies:    []string{"pol1", "pol2"},
				TokenTTL:    7200,
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
	entry.Request.ClientIP = "modified"
	if clone.Request.ClientIP == "modified" {
		t.Error("clone request should be independent")
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
