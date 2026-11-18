package audit

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

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
			NamespacePath: "team-payments/orders/",
			Actors:        []ActorRef{{Subject: "broker-beta", Issuer: "https://idp.example.com"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want = `{"actors":[{"subject":"orchestrator","issuer":"https://idp.example.com"}],` +
		`"user":{"subject":"alice","token_id":"t1","namespace_id":"ns-77c0d4",` +
		`"namespace_path":"team-payments/orders/",` +
		`"actors":[{"subject":"broker-beta","issuer":"https://idp.example.com"}]}}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

// The wire names of the native identity fields are pinned.
func TestNativeIdentity_JSONKeys(t *testing.T) {
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

// The entries the encoder is held to are filled by fill: it has to reach the
// fields below the top ones, or those would go unchecked.
func TestFillReachesNestedFields(t *testing.T) {
	var entry LogEntry
	fill(reflect.ValueOf(&entry).Elem())
	if entry.Auth.AuthTime == 0 || entry.Auth.PolicyResults.MCPDecision.BatchIndex == nil {
		t.Fatal("the fill does not reach nested fields")
	}
}
