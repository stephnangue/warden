package logical

import (
	"reflect"
	"testing"
	"time"
)

// TestTokenEntryCopy_EveryField: Copy carries every field. The sample sets
// every exported field to a non-zero value and the test fails on one it does
// not, so a field added to TokenEntry must be added here, and to Copy.
func TestTokenEntryCopy_EveryField(t *testing.T) {
	adm := &Admission{MountPath: "auth/jwt/"}
	te := &TokenEntry{
		ID:             "id",
		Accessor:       "acc",
		Type:           "jwt_role",
		NamespaceID:    "root",
		NamespacePath:  "team/",
		CreatedAt:      time.Unix(1, 0),
		CreatedByIP:    "10.0.0.1",
		CreatedByReqID: "req",
		PrincipalID:    "agent-1",
		RoleName:       "deploy",
		MountAccessor:  "auth_jwt_1",
		ExpireAt:       time.Unix(2, 0),
		Data:           map[string]string{"k": "v"},
		Metadata:       map[string]string{"repo": "acme/infra"},
		Policies:       []string{"deploy"},
		CredentialSpec: "spec",
		Actors:         []ActorRef{{Subject: "orchestrator"}},
		Admission:      adm,
	}
	te.MarkUsed()

	v := reflect.ValueOf(te).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if f.IsExported() && v.Field(i).IsZero() {
			t.Fatalf("the sample leaves %s unset: set it, and make sure Copy carries it", f.Name)
		}
	}

	cp := te.Copy()
	if cp == te {
		t.Fatal("Copy returned the same entry")
	}
	cv := reflect.ValueOf(cp).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		if !reflect.DeepEqual(v.Field(i).Interface(), cv.Field(i).Interface()) {
			t.Errorf("Copy dropped %s", f.Name)
		}
	}
	if !cp.IsUsed() {
		t.Error("Copy dropped the used flag")
	}
	if cp.Admission != adm {
		t.Error("the copy must share the admission by pointer")
	}

	// The copy's own fields are its own.
	cp.RoleName, cp.Policies = "other", nil
	if te.RoleName != "deploy" || len(te.Policies) != 1 {
		t.Error("writing the copy's fields reached the original")
	}

	if (*TokenEntry)(nil).Copy() != nil {
		t.Error("Copy of nil should be nil")
	}
}

// TestRequestRoleGrant: the grant lives on the request; setting, reading and
// clearing it allocate nothing, and a request copied by value reads its own.
func TestRequestRoleGrant(t *testing.T) {
	var nilReq *Request
	if nilReq.RoleGrant() != nil {
		t.Error("a nil request has no grant")
	}
	req := &Request{}
	if req.RoleGrant() != nil {
		t.Error("a new request has no grant")
	}

	allocs := testing.AllocsPerRun(1000, func() {
		rg := req.SetRoleGrant(RoleGrant{RoleName: "deploy", DeniedReason: RoleDeniedNotAssumable})
		rg.DeniedReason, rg.GrantedBy = "", "group:deployers"
		_ = req.RoleGrant().Granted()
		req.ClearRoleGrant()
	})
	if allocs != 0 {
		t.Errorf("grant set/read/clear allocated %v times", allocs)
	}

	rg := req.SetRoleGrant(RoleGrant{RoleName: "deploy"})
	if req.RoleGrant() != rg {
		t.Error("RoleGrant returns the grant set in place")
	}
	cp := *req
	cp.RoleGrant().RoleName = "other"
	if req.RoleGrant().RoleName != "deploy" {
		t.Error("a request copied by value shares its grant with the original")
	}
	req.ClearRoleGrant()
	if req.RoleGrant() != nil {
		t.Error("ClearRoleGrant leaves a grant")
	}
}

func TestRoleGrant_Granted(t *testing.T) {
	var nilGrant *RoleGrant
	if nilGrant.Granted() {
		t.Error("a nil grant grants nothing")
	}
	if (&RoleGrant{RoleName: "deploy", DeniedReason: RoleDeniedNotAssumable}).Granted() {
		t.Error("a refused grant grants nothing")
	}
	if !(&RoleGrant{RoleName: "deploy", GrantedBy: GroupLabel("deployers")}).Granted() {
		t.Error("a grant with a granting group grants")
	}
}
