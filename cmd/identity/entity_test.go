package identity

import (
	"bytes"
	"errors"
	"net/http"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cannedEntity = `{"data":{
	"id":"6f1c",
	"name":"billing-agent",
	"kind":"agent",
	"description":"Reconciles supplier invoices",
	"sponsor":{
		"type":"group","namespace":"/","group":"billing-leads","group_id":"g1",
		"added_by":{"mount":"auth/oidc/","mount_accessor":"auth_oidc_1","alias":"0583-oid","principal":"0583-oid"},
		"added_at":"2026-10-26T10:30:00Z",
		"accepted_by":{"mount":"auth/oidc/","mount_accessor":"auth_oidc_1","alias":"0583-oid","principal":"0583-oid"},
		"accepted_at":"2026-10-26T10:30:00Z","status":"accepted"
	},
	"pending_sponsor":{
		"type":"group","namespace":"team-a/","group":"finance-oncall","group_id":"g2",
		"added_by":{"mount":"","mount_accessor":"","alias":"","principal":"root"},
		"added_at":"2026-10-26T10:45:00Z","accepted_by":null,"accepted_at":null,"status":"pending"
	},
	"state":"active",
	"governed_by":"warden",
	"ungoverned_reason":"",
	"profile":{"runtime":"langgraph"},
	"metadata":{},
	"aliases":[
		{"mount":"auth/kubernetes/","mount_accessor":"auth_kubernetes_1","name":"system:serviceaccount:billing:agent","created_at":"2026-10-26T10:00:00Z"},
		{"mount":"","mount_accessor":"auth_jwt_gone","name":"repo:corp/x","created_at":"2026-10-26T10:00:00Z"}
	],
	"hash":"e1",
	"created_at":"2026-10-26T10:00:00Z",
	"updated_at":"2026-10-26T10:00:00Z"
}}`

// setupEntityFake is setupFake for the entity and alias commands: it also
// resets their package-level flags.
func setupEntityFake(t *testing.T, status int, body string) (*fakeWarden, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	f, stdout, stderr := setupFake(t, status, body)
	t.Cleanup(func() {
		entityCreateFlags.reset()
		entityUpdateFlags.reset()
		entityCreateJSON, entityUpdateJSON, entityUpdateExpectedHash, entityReadID = "", "", "", ""
		entityDeleteForce, entityDeleteRetired, entityDeleteExpectedHash = false, false, ""
		entityListFilter = api.EntityFilter{}
		sponsorProposeGroup, sponsorProposeNamespace, sponsorProposeExpectedHash, sponsorProposeJSON = "", "", "", ""
		sponsorRemovePending, sponsorRemoveExpectedHash, entityStateExpectedHash = false, "", ""
		for _, cmd := range []*cobra.Command{EntitySponsorProposeCmd, EntitySponsorRemoveCmd, EntityStateCmd} {
			cmd.Flags().Visit(func(f *pflag.Flag) { f.Changed = false })
		}
		aliasAddFlags.reset()
		aliasMoveFlags.reset()
		aliasRemoveFlags.reset()
		entityLookupFlags.reset()
	})
	return f, stdout, stderr
}

func freshEntityCmd(create bool) *cobra.Command {
	cmd := &cobra.Command{}
	if create {
		entityCreateFlags.bind(cmd, true)
		cmd.Flags().StringVarP(&entityCreateJSON, "json", "j", "", "")
	} else {
		entityUpdateFlags.bind(cmd, false)
		cmd.Flags().StringVar(&entityUpdateExpectedHash, "expected-hash", "", "")
		cmd.Flags().StringVarP(&entityUpdateJSON, "json", "j", "", "")
	}
	return cmd
}

func freshAliasCmd(f *aliasFlags, ac aliasCommand) *cobra.Command {
	cmd := &cobra.Command{}
	f.bind(cmd, ac)
	return cmd
}

func TestEntityCreate_JSON(t *testing.T) {
	f, stdout, _ := setupEntityFake(t, http.StatusCreated, cannedEntity)
	cmd := freshEntityCmd(true)
	entityCreateJSON = `{
		"description": "Reconciles supplier invoices",
		"aliases": [
			{ "mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent" }
		]
	}`
	require.NoError(t, runEntityCreate(cmd, []string{"billing-agent"}))
	req := f.last(t)
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent", req.path)
	assert.Equal(t, map[string]any{
		"description": "Reconciles supplier invoices",
		"aliases": []any{
			map[string]any{"mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent"},
		},
	}, req.body)

	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["created"])
	assert.Equal(t, "warden", out["governed_by"])
	assert.Equal(t, "e1", out["hash"])
}

// Each -alias is <mount>=<name>, split at the first "=": a native identity
// may hold "=" or ":", a mount path never holds "=".
func TestEntityCreate_TypedFlags(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusCreated, cannedEntity)
	cmd := freshEntityCmd(true)
	require.NoError(t, cmd.Flags().Set("description", "Reconciles supplier invoices"))
	require.NoError(t, cmd.Flags().Set("profile", "runtime=langgraph"))
	require.NoError(t, cmd.Flags().Set("alias", "auth/kubernetes/=system:serviceaccount:billing:agent"))
	require.NoError(t, cmd.Flags().Set("alias", "auth/jwt/=repo:corp/x:env=prod"))

	require.NoError(t, runEntityCreate(cmd, []string{"billing-agent"}))
	assert.Equal(t, map[string]any{
		"description": "Reconciles supplier invoices",
		"profile":     map[string]any{"runtime": "langgraph"},
		"aliases": []any{
			map[string]any{"mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent"},
			map[string]any{"mount": "auth/jwt/", "name": "repo:corp/x:env=prod"},
		},
	}, f.last(t).body)
	assert.Nil(t, cmd.Flags().Lookup("new-name"), "-new-name is update only")
	assert.Nil(t, cmd.Flags().Lookup("sponsors"), "the sponsor has commands of its own")
	assert.Nil(t, cmd.Flags().Lookup("state"), "so has the state")
}

func TestEntityCreate_BadAliasFlag(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusCreated, cannedEntity)
	cmd := freshEntityCmd(true)
	require.NoError(t, cmd.Flags().Set("alias", "auth/kubernetes/"))
	err := runEntityCreate(cmd, []string{"a"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Contains(t, err.Error(), "-alias #1 must be <mount>=<name>")
	assert.Zero(t, f.count())
}

// A rename renders the entity under its new name; -expected-hash is sent.
func TestEntityUpdate_Rename(t *testing.T) {
	f, stdout, _ := setupEntityFake(t, http.StatusOK, cannedEntity)
	cmd := freshEntityCmd(false)
	require.NoError(t, cmd.Flags().Set("new-name", "invoice-agent"))
	require.NoError(t, cmd.Flags().Set("description", ""))
	require.NoError(t, cmd.Flags().Set("expected-hash", "e0"))

	require.NoError(t, runEntityUpdate(cmd, []string{"billing-agent"}))
	req := f.last(t)
	assert.Equal(t, http.MethodPut, req.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent", req.path)
	assert.Equal(t, map[string]any{"new_name": "invoice-agent", "description": "", "expected_hash": "e0"}, req.body,
		"an empty -description is sent, to clear it")
	assert.Equal(t, "invoice-agent", decodeOut(t, stdout)["name"])
	assert.Nil(t, cmd.Flags().Lookup("alias"), "-alias is create only")
}

func TestEntityUpdate_NoFields(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, cannedEntity)
	err := runEntityUpdate(freshEntityCmd(false), []string{"a"})
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Zero(t, f.count())
}

func TestEntityRead_ByNameOrID(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, cannedEntity)
	require.NoError(t, runEntityRead(EntityReadCmd, []string{"billing-agent"}))
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent", f.last(t).path)

	entityReadID = "6f1c"
	require.NoError(t, runEntityRead(EntityReadCmd, nil))
	assert.Equal(t, "/v1/sys/identity/entity/id/6f1c", f.last(t).path)

	err := runEntityRead(EntityReadCmd, []string{"billing-agent"})
	assert.True(t, errors.Is(err, helpers.ErrUsage), "a name and -id")
	entityReadID = ""
	assert.True(t, errors.Is(runEntityRead(EntityReadCmd, nil), helpers.ErrUsage), "neither")
}

// The table shows each native identity on its own line, a gone mount by
// accessor.
func TestEntityRead_Table(t *testing.T) {
	setupEntityFake(t, http.StatusOK, cannedEntity)
	helpers.SetOutputFormat("table")
	out := captureStdout(t, func() { require.NoError(t, runEntityRead(EntityReadCmd, []string{"billing-agent"})) })
	assert.Contains(t, out, "auth/kubernetes/  system:serviceaccount:billing:agent")
	assert.Contains(t, out, "auth_jwt_gone (mount gone)  repo:corp/x")
	assert.Contains(t, out, "warden")
	assert.Contains(t, out, "/billing-leads  accepted by auth/oidc/ 0583-oid")
	assert.Contains(t, out, "team-a/finance-oncall  proposed by root")
}

// -retired asks the server to delete a retired entity; -force only skips the
// prompt.
func TestEntityDelete_Retired(t *testing.T) {
	f, stdout, _ := setupEntityFake(t, http.StatusOK, `{"data":{"name":"a"}}`)
	entityDeleteForce = true
	require.NoError(t, runEntityDelete(EntityDeleteCmd, []string{"a"}))
	req := f.last(t)
	assert.Equal(t, http.MethodDelete, req.method)
	assert.Empty(t, req.query.Get("force"))

	entityDeleteRetired, entityDeleteExpectedHash = true, "e1"
	require.NoError(t, runEntityDelete(EntityDeleteCmd, []string{"a"}))
	req = f.last(t)
	assert.Equal(t, "true", req.query.Get("force"))
	assert.Equal(t, "e1", req.query.Get("expected_hash"))
	assert.Contains(t, stdout.String(), `"deleted": true`)
}

// The server's warning on a forced delete goes to stderr and stays in the
// structured output.
func TestEntityDelete_RetiredWarns(t *testing.T) {
	_, stdout, stderr := setupEntityFake(t, http.StatusOK,
		`{"data":{"name":"a","warnings":["forced: retired entity \"a\" deleted; the 2 native identities it claimed are unclaimed again"]}}`)
	entityDeleteForce, entityDeleteRetired = true, true
	require.NoError(t, runEntityDelete(EntityDeleteCmd, []string{"a"}))
	assert.Contains(t, stderr.String(), `warning: forced: retired entity "a" deleted`)
	assert.Contains(t, stdout.String(), `"warnings": [`)
}

// A retired entity refused without -retired says which flag sends force.
func TestEntityDelete_RetiredHint(t *testing.T) {
	setupEntityFake(t, http.StatusConflict,
		`{"errors":["entity \"a\" is retired: its record is read-only, and its native identities can only be moved to another entity; a delete needs force"]}`)
	entityDeleteForce = true
	err := runEntityDelete(EntityDeleteCmd, []string{"a"})
	require.Error(t, err)

	stderr := &bytes.Buffer{}
	helpers.SetErrorWriter(stderr)
	assert.Equal(t, helpers.ExitConflict, helpers.RenderError(err), "the hint keeps the classification")
	assert.Contains(t, stderr.String(), `"hint": "pass -retired to delete a retired entity`)
}

func TestEntityList_Filters(t *testing.T) {
	f, stdout, _ := setupEntityFake(t, http.StatusOK, `{"data":{"keys":["billing-agent"],"entities":[`+
		cannedEntity[len(`{"data":`):len(cannedEntity)-1]+`]}}`)
	entityListFilter = api.EntityFilter{State: "active", Sponsor: "billing-leads", SponsorState: "pending", Ungoverned: true, Orphaned: true}
	require.NoError(t, runEntityList(EntityListCmd, nil))
	req := f.last(t)
	assert.Equal(t, "/v1/sys/identity/entity", req.path)
	assert.Equal(t, "active", req.query.Get("state"))
	assert.Equal(t, "billing-leads", req.query.Get("sponsor"))
	assert.Equal(t, "pending", req.query.Get("sponsor_state"))
	assert.Equal(t, "true", req.query.Get("ungoverned"))
	assert.Equal(t, "true", req.query.Get("orphaned"))
	assert.Empty(t, req.query.Get("kind"), "unset filters are not sent")
	assert.Contains(t, stdout.String(), `"billing-agent"`)
	assert.Contains(t, stdout.String(), `"group": "finance-oncall"`, "the pending handover is listed")

	helpers.SetOutputFormat("table")
	out := captureStdout(t, func() { require.NoError(t, runEntityList(EntityListCmd, nil)) })
	assert.Contains(t, out, "/billing-leads (pending: team-a/finance-oncall)")
}

func TestEntitySponsorPropose(t *testing.T) {
	f, _, stderr := setupEntityFake(t, http.StatusOK,
		`{"data":{"name":"billing-agent","warnings":["handover to /billing-leads is pending: a member must accept it"]}}`)
	sponsorProposeGroup, sponsorProposeNamespace, sponsorProposeExpectedHash = "billing-leads", "/", "e1"
	require.NoError(t, runSponsorPropose(EntitySponsorProposeCmd, []string{"billing-agent"}))
	req := f.last(t)
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/sponsor", req.path)
	assert.Equal(t, map[string]any{"group": "billing-leads", "namespace": "/", "expected_hash": "e1"}, req.body)
	assert.Contains(t, stderr.String(), "warning: handover to /billing-leads is pending")

	sponsorProposeGroup, sponsorProposeNamespace, sponsorProposeExpectedHash = "", "", ""
	sponsorProposeJSON = `{"group": "finance-oncall"}`
	require.NoError(t, runSponsorPropose(EntitySponsorProposeCmd, []string{"billing-agent"}))
	assert.Equal(t, map[string]any{"group": "finance-oncall"}, f.last(t).body)

	for _, payload := range []string{`{"namespace": "/"}`, `{"group": "x", "pending": true}`, `{"group": 5}`} {
		sponsorProposeJSON = payload
		err := runSponsorPropose(EntitySponsorProposeCmd, []string{"billing-agent"})
		assert.True(t, errors.Is(err, helpers.ErrUsage), payload)
	}
	assert.Equal(t, 2, f.count(), "refused locally")
}

func TestEntitySponsorRemove(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, cannedEntity)
	require.NoError(t, runSponsorRemove(EntitySponsorRemoveCmd, []string{"billing-agent"}))
	req := f.last(t)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/sponsor/remove", req.path)
	assert.Empty(t, req.body)

	sponsorRemovePending, sponsorRemoveExpectedHash = true, "e1"
	require.NoError(t, runSponsorRemove(EntitySponsorRemoveCmd, []string{"billing-agent"}))
	assert.Equal(t, map[string]any{"pending": true, "expected_hash": "e1"}, f.last(t).body)
}

// No identity command defines a flag named like the global -n/--namespace,
// which would take the name and leave -n unknown on that command.
func TestIdentityCommands_KeepTheGlobalNamespaceFlag(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if f := c.LocalNonPersistentFlags().Lookup("namespace"); f != nil {
			t.Errorf("%s defines -namespace, which shadows the global -n", c.CommandPath())
		}
		if f := c.LocalNonPersistentFlags().ShorthandLookup("n"); f != nil {
			t.Errorf("%s defines -%s with shorthand n, which shadows the global -n", c.CommandPath(), f.Name)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(IdentityCmd)
}

func TestEntityState(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, cannedEntity)
	entityStateExpectedHash = "e1"
	require.NoError(t, runEntityState(EntityStateCmd, []string{"billing-agent", "suspended"}))
	req := f.last(t)
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/state", req.path)
	assert.Equal(t, map[string]any{"state": "suspended", "expected_hash": "e1"}, req.body)

	err := runEntityState(EntityStateCmd, []string{"billing-agent", "paused"})
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Equal(t, 1, f.count())
}

func TestAliasAdd_And_Move(t *testing.T) {
	f, stdout, _ := setupEntityFake(t, http.StatusOK, `{"data":{
		"entity":"invoice-agent","mount":"auth/jwt/","mount_accessor":"auth_jwt_1","name":"repo:corp/x","moved_from":"billing-agent"
	}}`)
	cmd := freshAliasCmd(&aliasAddFlags, claimCommand)
	require.NoError(t, cmd.Flags().Set("json", `{"mount": "auth/jwt/", "name": "repo:corp/x", "to": "billing-agent"}`))
	require.NoError(t, runAliasClaim(cmd, &aliasAddFlags, false))
	req := f.last(t)
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/alias", req.path)
	assert.Equal(t, map[string]any{"mount": "auth/jwt/", "name": "repo:corp/x"}, req.body)

	cmd = freshAliasCmd(&aliasMoveFlags, claimCommand)
	require.NoError(t, cmd.Flags().Set("mount", "auth/jwt/"))
	require.NoError(t, cmd.Flags().Set("name", "repo:corp/x"))
	require.NoError(t, cmd.Flags().Set("to", "invoice-agent"))
	stdout.Reset()
	require.NoError(t, runAliasClaim(cmd, &aliasMoveFlags, true))
	req = f.last(t)
	assert.Equal(t, "/v1/sys/identity/entity/invoice-agent/alias", req.path)
	assert.Equal(t, map[string]any{"mount": "auth/jwt/", "name": "repo:corp/x", "move": true}, req.body)
	out := decodeOut(t, stdout)
	assert.Equal(t, "billing-agent", out["moved_from"])
	assert.Equal(t, true, out["claimed"])
}

// remove names the entity it releases from; the mount may be named by
// accessor, which still names a mount disabled since.
func TestAliasRemove(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, `{"data":{"entity":"billing-agent"}}`)
	cmd := freshAliasCmd(&aliasRemoveFlags, releaseCommand)
	require.NoError(t, cmd.Flags().Set("json", `{"mount_accessor": "auth_jwt_gone", "name": "repo:corp/x", "from": "billing-agent"}`))
	require.NoError(t, runAliasRemove(cmd, nil))
	req := f.last(t)
	assert.Equal(t, "/v1/sys/identity/entity/billing-agent/alias/remove", req.path)
	assert.Equal(t, map[string]any{"mount_accessor": "auth_jwt_gone", "name": "repo:corp/x"}, req.body)

	cmd = freshAliasCmd(&aliasRemoveFlags, releaseCommand)
	require.NoError(t, cmd.Flags().Set("json", `{"mount": "auth/jwt/", "name": "repo:corp/x"}`))
	err := runAliasRemove(cmd, nil)
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Contains(t, err.Error(), "from is required")
}

// The alias input is refused locally when it names no mount, two mounts, no
// name, or a field the command does not take.
func TestAliasInput_Refused(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, `{"data":{}}`)
	cases := []struct {
		ac   aliasCommand
		json string
		want string
	}{
		{claimCommand, `{"name": "x", "to": "a"}`, "mount is required"},
		{claimCommand, `{"mount_accessor": "acc", "name": "x", "to": "a"}`, `unknown field "mount_accessor"`},
		{releaseCommand, `{"mount": "auth/jwt/", "mount_accessor": "acc", "name": "x", "from": "a"}`, "exclusive"},
		{releaseCommand, `{"mount": "auth/jwt/", "from": "a"}`, "name is required"},
		{lookupCommand, `{"mount": "auth/jwt/", "name": "x", "to": "a"}`, `unknown field "to"`},
		{claimCommand, `{"mount": "auth/jwt/", "name": 5, "to": "a"}`, "must be a string"},
	}
	for _, tc := range cases {
		var fl aliasFlags
		cmd := freshAliasCmd(&fl, tc.ac)
		require.NoError(t, cmd.Flags().Set("json", tc.json))
		_, _, err := fl.input(cmd, tc.ac)
		require.Error(t, err, tc.json)
		assert.True(t, errors.Is(err, helpers.ErrUsage), tc.json)
		assert.Contains(t, err.Error(), tc.want, tc.json)
	}
	assert.Zero(t, f.count())
}

func TestEntityLookup(t *testing.T) {
	f, stdout, _ := setupEntityFake(t, http.StatusOK, `{"data":{
		"entity":"billing-agent","entity_id":"6f1c","kind":"agent","state":"active","governed_by":"warden"
	}}`)
	cmd := freshAliasCmd(&entityLookupFlags, lookupCommand)
	require.NoError(t, cmd.Flags().Set("mount", "auth/kubernetes/"))
	require.NoError(t, cmd.Flags().Set("name", "system:serviceaccount:billing:agent"))
	require.NoError(t, runEntityLookup(cmd, nil))
	req := f.last(t)
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "/v1/sys/identity/lookup", req.path)
	assert.Equal(t, map[string]any{"mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent"}, req.body)
	out := decodeOut(t, stdout)
	assert.Equal(t, "billing-agent", out["entity"])
	assert.Equal(t, "warden", out["governed_by"])
}

// schemaDocs are the body schemas the fake serves per path, as the server
// documents the entity and alias paths.
var schemaDocs = map[string]string{
	"sys/identity/entity/{name}": `{"data":{"openapi":{"paths":{"/sys/identity/entity/{name}":{
		"post":{"requestBody":{"content":{"application/json":{"schema":{"properties":{
			"kind":{"type":"string"},
			"description":{"type":"string"},
			"profile":{"type":"object"},
			"metadata":{"type":"object"},
			"aliases":{"type":"array"},
			"new_name":{"type":"string"},
			"governed_by":{"type":"string"},
			"expected_hash":{"type":"string"},
			"force":{"type":"boolean"}
		}}}}}}
	}}}}}`,
	"sys/identity/entity/{entity}/alias": `{"data":{"openapi":{"paths":{"/sys/identity/entity/{entity}/alias":{
		"post":{"requestBody":{"content":{"application/json":{"schema":{"properties":{
			"mount":{"type":"string"},
			"name":{"type":"string"},
			"move":{"type":"boolean"}
		}}}}}}
	}}}}}`,
}

// -dry-run validates the payload against the server's schema of the path
// and sends nothing; a field the path does not take is flagged.
func TestEntity_DryRun(t *testing.T) {
	f, stdout, _ := setupEntityFake(t, http.StatusCreated, cannedEntity)
	helpers.SetDryRun(true)

	cmd := freshEntityCmd(true)
	require.NoError(t, cmd.Flags().Set("json", `{"description": "x", "aliases": [{"mount": "auth/jwt/", "name": "y"}]}`))
	require.NoError(t, runEntityCreate(cmd, []string{"a"}))
	assert.Equal(t, true, decodeOut(t, stdout)["validated"])

	cmd = freshEntityCmd(false)
	require.NoError(t, cmd.Flags().Set("json", `{"descriptio": "x"}`))
	err := runEntityUpdate(cmd, []string{"a"})
	require.Error(t, err)
	assert.True(t, helpers.IsValidationError(err))
	assert.Contains(t, err.Error(), `did you mean "description"`)

	stdout.Reset()
	cmd = freshAliasCmd(&aliasMoveFlags, claimCommand)
	require.NoError(t, cmd.Flags().Set("mount", "auth/jwt/"))
	require.NoError(t, cmd.Flags().Set("name", "repo:corp/x"))
	require.NoError(t, cmd.Flags().Set("to", "a"))
	require.NoError(t, runAliasClaim(cmd, &aliasMoveFlags, true))
	assert.Equal(t, true, decodeOut(t, stdout)["validated"], "the server body: mount, name, move")
	assert.Zero(t, f.count(), "a dry run sends nothing")
}

// -json and the typed flags are exclusive on every entity and alias command.
func TestEntity_JSONAndFlagsRejected(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, cannedEntity)

	cmd := freshEntityCmd(true)
	require.NoError(t, cmd.Flags().Set("profile", "runtime=langgraph"))
	require.NoError(t, cmd.Flags().Set("json", `{"description": "x"}`))
	assert.True(t, errors.Is(runEntityCreate(cmd, []string{"a"}), helpers.ErrUsage), "create")

	cmd = freshEntityCmd(false)
	require.NoError(t, cmd.Flags().Set("expected-hash", "e1"))
	require.NoError(t, cmd.Flags().Set("json", `{"description": "x"}`))
	assert.True(t, errors.Is(runEntityUpdate(cmd, []string{"a"}), helpers.ErrUsage), "update")

	cmd = freshAliasCmd(&aliasRemoveFlags, releaseCommand)
	require.NoError(t, cmd.Flags().Set("from", "a"))
	require.NoError(t, cmd.Flags().Set("json", `{"mount": "auth/jwt/", "name": "x", "from": "a"}`))
	assert.True(t, errors.Is(runAliasRemove(cmd, nil), helpers.ErrUsage), "alias remove")
	assert.Zero(t, f.count())
}

// alias remove takes the mount by accessor through its typed flags too.
func TestAliasRemove_TypedFlags(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, `{"data":{"entity":"a"}}`)
	cmd := freshAliasCmd(&aliasRemoveFlags, releaseCommand)
	require.NoError(t, cmd.Flags().Set("mount-accessor", "auth_jwt_gone"))
	require.NoError(t, cmd.Flags().Set("name", "repo:corp/x"))
	require.NoError(t, cmd.Flags().Set("from", "a"))
	require.NoError(t, runAliasRemove(cmd, nil))
	req := f.last(t)
	assert.Equal(t, "/v1/sys/identity/entity/a/alias/remove", req.path)
	assert.Equal(t, map[string]any{"mount_accessor": "auth_jwt_gone", "name": "repo:corp/x"}, req.body)
}

// -kind and -governed-by reach the server as query parameters.
func TestEntityList_KindAndGovernedBy(t *testing.T) {
	f, _, _ := setupEntityFake(t, http.StatusOK, `{"data":{"keys":[],"entities":[]}}`)
	entityListFilter = api.EntityFilter{Kind: "agent", GovernedBy: "warden"}
	require.NoError(t, runEntityList(EntityListCmd, nil))
	req := f.last(t)
	assert.Equal(t, "agent", req.query.Get("kind"))
	assert.Equal(t, "warden", req.query.Get("governed_by"))
	assert.Empty(t, req.query.Get("ungoverned"))
}
