package identity

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

const cannedStaticGroup = `{"data":{
	"id":"5a6b",
	"name":"local-ops",
	"type":"static",
	"roles":["deploy"],
	"rules":[],
	"members":[
		{"name":"billing-agent","id":"e1","until":"","expired":false},
		{"name":"release-bot","id":"e2","until":"2026-10-26T18:00:00Z","expired":true}
	],
	"metadata":{},
	"hash":"h1"
}}`

func resetMemberFlags(t *testing.T) {
	t.Cleanup(func() { memberUntil, memberFor = "", 0 })
}

// member add reads the group and writes its member list back with the new
// member, conditional on the hash it read, sending the type as static.
func TestGroupMemberAdd(t *testing.T) {
	resetMemberFlags(t)
	f, _, _ := setupFake(t, http.StatusOK, cannedStaticGroup)
	memberUntil = "2099-12-31T23:59:59Z"
	require.NoError(t, runGroupMemberAdd(GroupMemberAddCmd, []string{"local-ops", "invoice-agent"}))

	require.Equal(t, 2, f.count())
	read := f.requests[0]
	assert.Equal(t, http.MethodGet, read.method)
	assert.Equal(t, "static", read.query.Get("type"))
	write := f.last(t)
	assert.Equal(t, http.MethodPut, write.method)
	assert.Equal(t, "/v1/sys/identity/group/local-ops", write.path)
	assert.Equal(t, map[string]any{
		"type":          "static",
		"expected_hash": "h1",
		// The members read go back by ID; the one added, by name.
		"members": []any{
			map[string]any{"id": "e1"},
			map[string]any{"id": "e2", "until": "2026-10-26T18:00:00Z"},
			map[string]any{"name": "invoice-agent", "until": "2099-12-31T23:59:59Z"},
		},
	}, write.body)
}

// Adding a listed member replaces its until rather than listing it twice.
func TestGroupMemberAdd_ReplacesUntil(t *testing.T) {
	resetMemberFlags(t)
	f, _, _ := setupFake(t, http.StatusOK, cannedStaticGroup)
	require.NoError(t, runGroupMemberAdd(GroupMemberAddCmd, []string{"local-ops", "release-bot"}))
	assert.Equal(t, []any{map[string]any{"id": "e1"}, "release-bot"}, f.last(t).body["members"], "permanent now")
}

func TestGroupMemberAdd_Flags(t *testing.T) {
	resetMemberFlags(t)
	f, _, _ := setupFake(t, http.StatusOK, cannedStaticGroup)
	memberUntil, memberFor = "2099-12-31T23:59:59Z", 1
	assert.ErrorContains(t, runGroupMemberAdd(GroupMemberAddCmd, []string{"local-ops", "x"}), "mutually exclusive")
	memberUntil, memberFor = "tomorrow", 0
	assert.ErrorContains(t, runGroupMemberAdd(GroupMemberAddCmd, []string{"local-ops", "x"}), "RFC 3339")
	memberUntil = "2020-01-01T00:00:00Z"
	assert.ErrorContains(t, runGroupMemberAdd(GroupMemberAddCmd, []string{"local-ops", "x"}), "already past")
	assert.Zero(t, f.count(), "refused before any request")
}

// A write that loses to a concurrent one is read and applied again once; a
// second loss is reported.
func TestGroupMemberAdd_RetriesOnConflict(t *testing.T) {
	resetMemberFlags(t)
	for name, conflicts := range map[string]int{"retried": 1, "reported": 2} {
		t.Run(name, func(t *testing.T) {
			var methods []string
			puts := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				methods = append(methods, r.Method)
				if r.Method == http.MethodPut {
					if puts++; puts <= conflicts {
						w.WriteHeader(http.StatusConflict)
						_, _ = w.Write([]byte(`{"errors":["group \"local-ops\" changed since it was read"]}`))
						return
					}
				}
				_, _ = w.Write([]byte(cannedStaticGroup))
			}))
			t.Cleanup(srv.Close)
			cfg := api.DefaultConfig()
			cfg.Address = srv.URL
			client, err := api.NewClient(cfg)
			require.NoError(t, err)
			client.SetMaxRetries(0)
			helpers.SetTestClient(client)
			t.Cleanup(func() { helpers.SetTestClient(nil) })
			helpers.SetOutputWriter(io.Discard)
			helpers.SetErrorWriter(io.Discard)
			t.Cleanup(helpers.ResetWriters)

			err = runGroupMemberAdd(GroupMemberAddCmd, []string{"local-ops", "x"})
			assert.Equal(t, []string{"GET", "PUT", "GET", "PUT"}, methods)
			if conflicts == 1 {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, "changed since it was read")
			}
		})
	}
}

func TestGroupMemberRemove(t *testing.T) {
	resetMemberFlags(t)
	f, _, _ := setupFake(t, http.StatusOK, cannedStaticGroup)
	require.NoError(t, runGroupMemberRemove(GroupMemberRemoveCmd, []string{"local-ops", "billing-agent"}))
	assert.Equal(t, []any{map[string]any{"id": "e2", "until": "2026-10-26T18:00:00Z"}}, f.last(t).body["members"])

	err := runGroupMemberRemove(GroupMemberRemoveCmd, []string{"local-ops", "ghost"})
	assert.ErrorContains(t, err, `entity "ghost" is not a member of group "local-ops"`)
}

// -dry-run validates the static group write against the path's schema and
// sends nothing: no read of the members, no write.
func TestGroupMember_DryRun(t *testing.T) {
	resetMemberFlags(t)
	f, stdout, _ := setupFake(t, http.StatusOK, cannedStaticGroup)
	helpers.SetDryRun(true)

	memberUntil = "2099-12-31T23:59:59Z"
	require.NoError(t, runGroupMemberAdd(GroupMemberAddCmd, []string{"local-ops", "invoice-agent"}))
	assert.Equal(t, true, decodeOut(t, stdout)["validated"])
	stdout.Reset()
	require.NoError(t, runGroupMemberRemove(GroupMemberRemoveCmd, []string{"local-ops", "billing-agent"}))
	assert.Equal(t, true, decodeOut(t, stdout)["validated"])
	stdout.Reset()
	require.NoError(t, runGroupPrune(GroupPruneCmd, []string{"local-ops"}))
	assert.Equal(t, true, decodeOut(t, stdout)["validated"])
	assert.Zero(t, f.count())
}

// prune is a write with no change, of a static group.
func TestGroupPrune(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusOK, cannedStaticGroup)
	require.NoError(t, runGroupPrune(GroupPruneCmd, []string{"local-ops"}))
	require.Equal(t, 1, f.count())
	assert.Equal(t, http.MethodPut, f.last(t).method)
	assert.Equal(t, map[string]any{"type": "static"}, f.last(t).body)
}

// -member takes a name or a JSON object.
func TestGroupFlags_Member(t *testing.T) {
	t.Cleanup(createFlags.reset)
	f, _, _ := setupFake(t, http.StatusOK, cannedStaticGroup)
	require.NoError(t, GroupCreateCmd.Flags().Set("type", "static"))
	require.NoError(t, GroupCreateCmd.Flags().Set("member", "billing-agent"))
	require.NoError(t, GroupCreateCmd.Flags().Set("member", `{"name": "release-bot", "until": "2026-10-26T18:00:00Z"}`))
	t.Cleanup(func() {
		for _, n := range []string{"type", "member"} {
			GroupCreateCmd.Flags().Lookup(n).Changed = false
		}
	})
	require.NoError(t, runGroupCreate(GroupCreateCmd, []string{"local-ops"}))
	assert.Equal(t, []any{"billing-agent", map[string]any{"name": "release-bot", "until": "2026-10-26T18:00:00Z"}},
		f.last(t).body["members"])
}
