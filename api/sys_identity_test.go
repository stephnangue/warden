package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const deployersGroupJSON = `{"data":{
	"id":"0f1e",
	"name":"deployers",
	"type":"virtual",
	"description":"CI deployers",
	"roles":["deploy"],
	"rules":[{"mount":["auth/jwt/"],"repo":["acme/*"]}],
	"rule_count":1,
	"selector_count":2,
	"valid_until":"2026-12-31T23:59:59Z",
	"metadata":{"owner":"platform"},
	"hash":"h1",
	"created_at":"2026-10-20T10:00:00Z",
	"updated_at":"2026-10-20T10:00:00Z",
	"warnings":["role \"deploy\" does not exist yet; the group grants it once it does"]
}}`

func TestSys_CreateGroup(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusCreated, deployersGroupJSON)

	g, err := client.Sys().CreateGroup("deployers", &GroupInput{
		Type:        "virtual",
		Description: strPtr("CI deployers"),
		Roles:       []string{"deploy"},
		Rules:       []map[string][]string{{"mount": {"auth/jwt/"}, "repo": {"acme/*"}}},
		ValidUntil:  strPtr("2026-12-31T23:59:59Z"),
	})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, rec.method)
	assert.Equal(t, "/v1/sys/identity/group/deployers", rec.path)
	assert.Equal(t, map[string]any{
		"type":        "virtual",
		"description": "CI deployers",
		"roles":       []any{"deploy"},
		"rules":       []any{map[string]any{"mount": []any{"auth/jwt/"}, "repo": []any{"acme/*"}}},
		"valid_until": "2026-12-31T23:59:59Z",
	}, rec.body, "only the fields the input sets are sent")

	assert.Equal(t, "0f1e", g.ID)
	assert.Equal(t, "virtual", g.Type)
	assert.Equal(t, []map[string][]string{{"mount": {"auth/jwt/"}, "repo": {"acme/*"}}}, g.Rules)
	assert.Equal(t, 1, g.RuleCount)
	assert.Equal(t, 2, g.SelectorCount)
	assert.Equal(t, "2026-12-31T23:59:59Z", g.ValidUntil)
	assert.Equal(t, "h1", g.Hash)
	assert.Len(t, g.Warnings, 1)
}

func TestSys_ReadUpdateGroup(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, deployersGroupJSON)

	g, err := client.Sys().ReadGroup("deployers", "")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, rec.method)
	assert.Equal(t, "deployers", g.Name)
	assert.False(t, rec.query.Has("type"), "no type when none is asked for")

	_, err = client.Sys().ReadGroup("deployers", "virtual")
	require.NoError(t, err)
	assert.Equal(t, "virtual", rec.query.Get("type"))

	_, err = client.Sys().UpdateGroup("deployers", &GroupInput{Type: "virtual", Roles: []string{}, ExpectedHash: "h1"})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, rec.method)
	assert.Equal(t, map[string]any{"type": "virtual", "roles": []any{}, "expected_hash": "h1"}, rec.body,
		"an empty list clears; valid_until is not sent when unset")

	_, err = client.Sys().UpdateGroup("deployers", &GroupInput{Type: "virtual", ValidUntil: strPtr("")})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"type": "virtual", "valid_until": ""}, rec.body, "an empty valid_until is sent, to clear it")
}

func TestSys_DeleteGroup(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{"name":"deployers"}}`)
	warnings, err := client.Sys().DeleteGroup("deployers", "virtual", "h1", false)
	require.NoError(t, err)
	assert.Nil(t, warnings)
	assert.Equal(t, http.MethodDelete, rec.method)
	assert.Equal(t, "/v1/sys/identity/group/deployers", rec.path)
	assert.Equal(t, "virtual", rec.query.Get("type"))
	assert.Equal(t, "h1", rec.query.Get("expected_hash"))
	assert.Empty(t, rec.query.Get("force"), "no force unless asked")

	client, rec = newRoleServer(t, http.StatusOK, `{"data":{"name":"leads","warnings":["forced: group \"leads\" sponsored 1 entities"]}}`)
	warnings, err = client.Sys().DeleteGroup("leads", "virtual", "", true)
	require.NoError(t, err)
	assert.Equal(t, "true", rec.query.Get("force"))
	assert.Equal(t, []string{`forced: group "leads" sponsored 1 entities`}, warnings)
}

func TestSys_ListGroups(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{
		"keys":["ci","deployers"],
		"groups":[
			{"name":"ci","type":"virtual","roles":["deploy","read"]},
			{"name":"deployers","type":"virtual","roles":["deploy"]}
		]
	}}`)

	groups, err := client.Sys().ListGroups("deploy", "")
	require.NoError(t, err)
	assert.Equal(t, "/v1/sys/identity/group", rec.path)
	assert.Equal(t, "true", rec.query.Get("warden-list"))
	assert.Equal(t, "deploy", rec.query.Get("role"))
	assert.False(t, rec.query.Has("type"))
	require.Len(t, groups, 2)
	assert.Equal(t, []string{"deploy", "read"}, groups[0].Roles)

	_, err = client.Sys().ListGroups("", "virtual")
	require.NoError(t, err)
	assert.False(t, rec.query.Has("role"))
	assert.Equal(t, "virtual", rec.query.Get("type"))
}

func TestSys_ListGroups_Empty(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusOK, `{"data":{"keys":[],"groups":[]}}`)
	groups, err := client.Sys().ListGroups("", "")
	require.NoError(t, err)
	assert.Empty(t, groups)
	assert.NotNil(t, groups)
}

func TestSys_ReadIdentityUsage(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{
		"groups":{
			"total":42,
			"virtual":{"count":42,"max":8000,"selectors":310,"max_selectors":16000}
		},
		"identities":{"entities":7,"max_entities":50000,"aliases":12}
	}}`)

	u, err := client.Sys().ReadIdentityUsage()
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, rec.method)
	assert.Equal(t, "/v1/sys/identity/usage", rec.path)
	assert.Equal(t, &IdentityUsage{
		Groups: GroupsUsage{
			Total:   42,
			Virtual: VirtualGroupsUsage{Count: 42, Max: 8000, Selectors: 310, MaxSelectors: 16000},
		},
		Identities: IdentitiesUsage{Entities: 7, MaxEntities: 50000, Aliases: 12},
	}, u)
}

func TestSys_ReadIdentityUsage_Forbidden(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusForbidden, `{"errors":["permission denied"]}`)
	_, err := client.Sys().ReadIdentityUsage()
	var respErr *ResponseError
	require.ErrorAs(t, err, &respErr)
	assert.Equal(t, http.StatusForbidden, respErr.StatusCode)
}

// billingAgentJSON is an entity as sys/identity/entity/<name> returns it.
const billingAgentJSON = `{"data":{
	"id":"6f1c",
	"name":"billing-agent",
	"kind":"agent",
	"description":"Reconciles supplier invoices",
	"sponsor":{
		"type":"group","namespace":"/","group":"billing-leads","group_id":"g1",
		"added_by":{"mount":"auth/oidc/","mount_accessor":"auth_oidc_1","alias":"0583-oid","principal":"0583-oid"},
		"added_at":"2026-10-26T10:30:00Z",
		"accepted_by":{"mount":"auth/oidc/","mount_accessor":"auth_oidc_1","alias":"0583-oid","principal":"0583-oid"},
		"accepted_at":"2026-10-26T10:30:00Z",
		"status":"accepted"
	},
	"pending_sponsor":{
		"type":"group","namespace":"/","group":"finance-oncall","group_id":"g2",
		"added_by":{"mount":"","mount_accessor":"","alias":"","principal":"root"},
		"added_at":"2026-10-26T10:45:00Z","accepted_by":null,"accepted_at":null,"status":"pending"
	},
	"state":"active",
	"governed_by":"warden",
	"ungoverned_reason":"",
	"profile":{"runtime":"langgraph"},
	"metadata":{"team":"billing"},
	"aliases":[
		{"mount":"auth/kubernetes/","mount_accessor":"auth_kubernetes_1","name":"system:serviceaccount:billing:agent","created_at":"2026-10-26T10:00:00Z"}
	],
	"hash":"e1",
	"created_at":"2026-10-26T10:00:00Z",
	"updated_at":"2026-10-26T11:00:00Z"
}}`

func TestSys_CreateEntity(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusCreated, billingAgentJSON)

	e, err := client.Sys().CreateEntity("billing-agent", &EntityInput{
		Description: strPtr("Reconciles supplier invoices"),
		Profile:     map[string]string{"runtime": "langgraph"},
		Aliases:     []AliasRef{{Mount: "auth/kubernetes/", Name: "system:serviceaccount:billing:agent"}},
	})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, rec.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent", rec.path)
	assert.Equal(t, map[string]any{
		"description": "Reconciles supplier invoices",
		"profile":     map[string]any{"runtime": "langgraph"},
		"aliases":     []any{map[string]any{"mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent"}},
	}, rec.body, "only the fields the input sets are sent")

	assert.Equal(t, "6f1c", e.ID)
	assert.Equal(t, "warden", e.GovernedBy)
	assert.Equal(t, map[string]string{"runtime": "langgraph"}, e.Profile)
	require.Len(t, e.Aliases, 1)
	assert.Equal(t, EntityAlias{
		Mount:         "auth/kubernetes/",
		MountAccessor: "auth_kubernetes_1",
		Name:          "system:serviceaccount:billing:agent",
		CreatedAt:     time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC),
	}, e.Aliases[0])
	assert.Equal(t, time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC), e.UpdatedAt)
	assert.Equal(t, "e1", e.Hash)

	person := SponsorActor{Mount: "auth/oidc/", MountAccessor: "auth_oidc_1", Alias: "0583-oid", Principal: "0583-oid"}
	at := time.Date(2026, 10, 26, 10, 30, 0, 0, time.UTC)
	assert.Equal(t, &EntitySponsor{
		Type: "group", Namespace: "/", Group: "billing-leads", GroupID: "g1",
		AddedBy: person, AddedAt: at, AcceptedBy: &person, AcceptedAt: at, Status: "accepted",
	}, e.Sponsor)
	require.NotNil(t, e.PendingSponsor)
	assert.Equal(t, "finance-oncall", e.PendingSponsor.Group)
	assert.Equal(t, SponsorActor{Principal: "root"}, e.PendingSponsor.AddedBy)
	assert.Nil(t, e.PendingSponsor.AcceptedBy)
	assert.True(t, e.PendingSponsor.AcceptedAt.IsZero())
}

func TestSys_EntitySponsorAndState(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{"name":"billing-agent","warnings":["handover to /finance-oncall is pending: a member must accept it"]}}`)

	e, err := client.Sys().ProposeSponsor("billing-agent", SponsorRef{Group: "finance-oncall", Namespace: "/"}, "e1")
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, rec.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/sponsor", rec.path)
	assert.Equal(t, map[string]any{"group": "finance-oncall", "namespace": "/", "expected_hash": "e1"}, rec.body)
	assert.Equal(t, []string{"handover to /finance-oncall is pending: a member must accept it"}, e.Warnings)

	_, err = client.Sys().ProposeSponsor("billing-agent", SponsorRef{Group: "billing-leads"}, "")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"group": "billing-leads"}, rec.body, "the request's namespace unless named")

	_, err = client.Sys().RemoveSponsor("billing-agent", false, "")
	require.NoError(t, err)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/sponsor/remove", rec.path)
	assert.Equal(t, map[string]any{}, rec.body)
	_, err = client.Sys().RemoveSponsor("billing-agent", true, "e1")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"pending": true, "expected_hash": "e1"}, rec.body)

	_, err = client.Sys().SetEntityState("billing-agent", "suspended", "")
	require.NoError(t, err)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/state", rec.path)
	assert.Equal(t, map[string]any{"state": "suspended"}, rec.body)
}

func TestSys_ReadUpdateEntity(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, billingAgentJSON)

	_, err := client.Sys().ReadEntity("billing-agent")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, rec.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent", rec.path)

	e, err := client.Sys().ReadEntityByID("6f1c")
	require.NoError(t, err)
	assert.Equal(t, "/v1/sys/identity/entity/id/6f1c", rec.path)
	assert.Equal(t, "billing-agent", e.Name)

	_, err = client.Sys().UpdateEntity("billing-agent", &EntityInput{
		Metadata: map[string]string{}, NewName: "invoice-agent", ExpectedHash: "e1",
	})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, rec.method)
	assert.Equal(t, map[string]any{
		"metadata": map[string]any{}, "new_name": "invoice-agent", "expected_hash": "e1",
	}, rec.body, "an empty map clears; unset fields are not sent")
}

func TestSys_DeleteEntity(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{"name":"billing-agent"}}`)
	warnings, err := client.Sys().DeleteEntity("billing-agent", "", false)
	require.NoError(t, err)
	assert.Nil(t, warnings)
	assert.Equal(t, http.MethodDelete, rec.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent", rec.path)
	assert.Empty(t, rec.query, "no expected_hash and no force unless asked")

	_, err = client.Sys().DeleteEntity("billing-agent", "e1", true)
	require.NoError(t, err)
	assert.Equal(t, "e1", rec.query.Get("expected_hash"))
	assert.Equal(t, "true", rec.query.Get("force"))

	client, _ = newRoleServer(t, http.StatusOK, `{"data":{"name":"old-agent","warnings":["forced: retired entity \"old-agent\" deleted"]}}`)
	warnings, err = client.Sys().DeleteEntity("old-agent", "", true)
	require.NoError(t, err)
	assert.Equal(t, []string{`forced: retired entity "old-agent" deleted`}, warnings, "the server's warnings are returned")
}

func TestSys_ListEntities(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{
		"keys":["billing-agent","ci-runner"],
		"entities":[
			{"name":"billing-agent","state":"active","governed_by":"warden","aliases":[]},
			{"name":"ci-runner","state":"suspended","governed_by":"","ungoverned_reason":"no sponsor and no description"}
		]
	}}`)

	entities, err := client.Sys().ListEntities(nil)
	require.NoError(t, err)
	assert.Equal(t, "/v1/sys/identity/entity", rec.path)
	assert.Equal(t, "true", rec.query.Get("warden-list"))
	assert.Len(t, rec.query, 1, "no filter")
	require.Len(t, entities, 2)
	assert.Equal(t, "no sponsor and no description", entities[1].UngovernedReason)

	_, err = client.Sys().ListEntities(&EntityFilter{
		Kind: "agent", State: "active", Sponsor: "billing-leads", SponsorState: "pending", GovernedBy: "warden",
		Ungoverned: true, Orphaned: true,
	})
	require.NoError(t, err)
	for k, v := range map[string]string{
		"kind": "agent", "state": "active", "sponsor": "billing-leads", "sponsor_state": "pending", "governed_by": "warden",
		"ungoverned": "true", "orphaned": "true",
	} {
		assert.Equal(t, v, rec.query.Get(k), k)
	}
}

func TestSys_ListEntities_Empty(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusOK, `{"data":{"keys":[],"entities":[]}}`)
	entities, err := client.Sys().ListEntities(&EntityFilter{Orphaned: true})
	require.NoError(t, err)
	assert.Empty(t, entities)
	assert.NotNil(t, entities)
}

func TestSys_ClaimAlias(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{
		"entity":"invoice-agent","mount":"auth/jwt/","mount_accessor":"auth_jwt_1","name":"repo:corp/x","moved_from":"billing-agent"
	}}`)

	ref := AliasRef{Mount: "auth/jwt/", Name: "repo:corp/x"}
	_, err := client.Sys().ClaimAlias("invoice-agent", ref, false)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, rec.method)
	assert.Equal(t, "/v1/sys/identity/entity/invoice-agent/alias", rec.path)
	assert.Equal(t, map[string]any{"mount": "auth/jwt/", "name": "repo:corp/x"}, rec.body, "no move unless asked")

	claim, err := client.Sys().ClaimAlias("invoice-agent", ref, true)
	require.NoError(t, err)
	assert.Equal(t, true, rec.body["move"])
	assert.Equal(t, &AliasClaim{
		Entity: "invoice-agent", Mount: "auth/jwt/", MountAccessor: "auth_jwt_1", Name: "repo:corp/x", MovedFrom: "billing-agent",
	}, claim)
}

func TestSys_RemoveAlias(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{"entity":"billing-agent"}}`)
	require.NoError(t, client.Sys().RemoveAlias("billing-agent", AliasRef{MountAccessor: "auth_jwt_gone", Name: "repo:corp/x"}))
	assert.Equal(t, http.MethodPost, rec.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/alias/remove", rec.path)
	assert.Equal(t, map[string]any{"mount_accessor": "auth_jwt_gone", "name": "repo:corp/x"}, rec.body,
		"the mount by accessor, which still names a mount disabled since")
}

func TestSys_LookupAlias(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{
		"entity":"billing-agent","entity_id":"6f1c","kind":"agent","state":"active","governed_by":"warden"
	}}`)
	l, err := client.Sys().LookupAlias(AliasRef{Mount: "auth/kubernetes/", Name: "system:serviceaccount:billing:agent"})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, rec.method)
	assert.Equal(t, "/v1/sys/identity/lookup", rec.path)
	assert.Equal(t, map[string]any{"mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent"}, rec.body)
	assert.Equal(t, &AliasLookup{Entity: "billing-agent", EntityID: "6f1c", Kind: "agent", State: "active", GovernedBy: "warden"}, l)
}

func TestSys_LookupAlias_NotClaimed(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusNotFound, `{"errors":["native identity not claimed"]}`)
	_, err := client.Sys().LookupAlias(AliasRef{Mount: "auth/jwt/", Name: "nobody"})
	var respErr *ResponseError
	require.ErrorAs(t, err, &respErr)
	assert.Equal(t, http.StatusNotFound, respErr.StatusCode)
}
