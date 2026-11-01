package audit

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
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
	empty := (&LogEntry{Type: "request"}).Clone()
	if empty.Request != nil || empty.Response != nil || empty.Auth != nil {
		t.Errorf("Clone of an entry without parts made some: %+v", empty)
	}
}

// fill sets every exported field reachable from v to a non-zero value:
// strings, numbers and booleans, a one-element slice, a one-entry map, and a
// fresh value behind every pointer.
func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fill(v.Elem())
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(time.Unix(1761640000, 0).UTC()))
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i))
			}
		}
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0))
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fill(k)
		fill(e)
		m.SetMapIndex(k, e)
		v.Set(m)
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(7)
	}
}

// shared returns the path of every slice, map and pointer reachable from a's
// exported fields that b holds too, walking both in step.
func shared(a, b reflect.Value, path string) []string {
	switch a.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map:
		if a.IsNil() || b.IsNil() {
			return nil
		}
		if a.Pointer() == b.Pointer() {
			return []string{path}
		}
	}
	var out []string
	switch a.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !a.IsNil() && !b.IsNil() {
			out = shared(a.Elem(), b.Elem(), path)
		}
	case reflect.Struct:
		for i := range a.NumField() {
			if f := a.Type().Field(i); f.IsExported() {
				out = append(out, shared(a.Field(i), b.Field(i), path+"."+f.Name)...)
			}
		}
	case reflect.Slice:
		for i := range min(a.Len(), b.Len()) {
			out = append(out, shared(a.Index(i), b.Index(i), fmt.Sprintf("%s[%d]", path, i))...)
		}
	case reflect.Map:
		for it := a.MapRange(); it.Next(); {
			if bv := b.MapIndex(it.Key()); bv.IsValid() {
				out = append(out, shared(it.Value(), bv, fmt.Sprintf("%s[%v]", path, it.Key()))...)
			}
		}
	}
	return out
}

// Clone keeps every field of an entry, however deep, and shares no slice, map
// or pointer with it: a field it drops is missing from every entry written,
// since devices format a clone, and one it shares is a race between devices
// writing the same entry. Filling the entry by reflection makes a field added
// later part of both checks without touching this test.
func TestCloneKeepsEverythingSharesNothing(t *testing.T) {
	var entry LogEntry
	fill(reflect.ValueOf(&entry).Elem())
	if entry.Auth.AuthTime == 0 || entry.Auth.PolicyResults.MCPDecision.BatchIndex == nil {
		t.Fatal("the fill does not reach nested fields")
	}

	clone := entry.Clone()
	if !reflect.DeepEqual(&entry, clone) {
		t.Errorf("clone differs from the entry:\nentry %+v\nclone %+v", entry, *clone)
	}
	if paths := shared(reflect.ValueOf(&entry), reflect.ValueOf(clone), "LogEntry"); len(paths) > 0 {
		t.Errorf("clone shares with the entry: %v", paths)
	}
}
