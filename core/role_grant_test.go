package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests here build admission tokens by hand (an admission, a mount
// accessor, no role), as a login issues them; role_grant_login_test.go drives
// them through real logins.

const (
	grantMount    = "auth/jwt/"
	grantAccessor = "auth_jwt_grant"
)

// grantEnv is a core with a role "deploy" (policy "deploy", spec
// "deploy-spec"), a role "other" no group grants, a virtual group "deployers"
// granting "deploy" to repo acme/* through auth/jwt/, and one cached admission
// token whose credential is in acme/infra.
type grantEnv struct {
	t     *testing.T
	c     *Core
	ctx   context.Context
	mf    *logical.MountFacts
	adm   *logical.Admission
	token string
}

func newGrantEnv(t *testing.T) *grantEnv {
	t.Helper()
	e := &grantEnv{t: t, c: createTestCore(t), ctx: rootCtx()}
	e.setPolicy("deploy", `path "secret/*" { capabilities = ["read"] }`)
	e.createRole(&logical.Role{Name: "deploy", Policies: []string{"deploy"}, CredSpecName: "deploy-spec"})
	e.createRole(&logical.Role{Name: "other", Policies: []string{"deploy"}})
	_, err := e.c.identityStore.CreateGroup(e.ctx, deployersGroup())
	require.NoError(t, err)

	e.mf = &logical.MountFacts{}
	e.mf.Publish(testNaming(t, "", map[string]string{"repository": "repo", "sub": "sub"}))
	e.adm = e.admission(grantMount)
	e.token = e.issue(e.adm, nil)
	return e
}

func deployersGroup() *logical.Group {
	return &logical.Group{
		Name:  "deployers",
		Type:  logical.GroupTypeVirtual,
		Roles: []string{"deploy"},
		Rules: []logical.GroupRule{{"mount": {grantMount}, "repo": {"acme/*"}}},
	}
}

// admission admits the env's credential through the mount at mountPath, named
// by the env's mount naming.
func (e *grantEnv) admission(mountPath string) *logical.Admission {
	return &logical.Admission{
		MountPath: mountPath,
		Facts:     selector.NewClaims(map[string]any{"sub": "agent-1", "repository": "acme/infra", "email": "a@acme.example"}),
		Mount:     e.mf,
	}
}

func (e *grantEnv) setPolicy(name, hcl string) {
	e.t.Helper()
	p := testParsePolicy(e.t, hcl)
	p.Name, p.Type = name, PolicyTypeCBP
	require.NoError(e.t, e.c.policyStore.SetPolicy(e.ctx, p, nil))
}

func (e *grantEnv) createRole(r *logical.Role) {
	e.t.Helper()
	_, err := e.c.roleStore.Create(e.ctx, r)
	require.NoError(e.t, err)
}

func (e *grantEnv) updateGroup(g *logical.Group) {
	e.t.Helper()
	_, err := e.c.identityStore.UpdateGroup(e.ctx, g, "")
	require.NoError(e.t, err)
}

// issue caches a token admitted with adm and returns its value. A nil adm
// builds the admission-token shape with no admission.
func (e *grantEnv) issue(adm *logical.Admission, policies []string) string {
	e.t.Helper()
	entry, err := e.c.tokenStore.GenerateToken(e.ctx, TypeServiceToken, &AuthData{
		PrincipalID:   "agent-1",
		MountAccessor: grantAccessor,
		ExpireAt:      time.Now().Add(time.Hour),
		Policies:      policies,
		Admission:     adm,
	})
	require.NoError(e.t, err)
	return entry.Data["token"]
}

// transparent builds a request as implicit auth leaves it: transparent, the
// token's per-request copy set on it and the requested role recorded.
func (e *grantEnv) transparent(token, role string) (*logical.Request, error) {
	te, err := e.c.LookupToken(e.ctx, token)
	if err != nil {
		return nil, err
	}
	req := &logical.Request{
		Operation:     logical.ReadOperation,
		Path:          "secret/x",
		ClientToken:   token,
		Transparent:   true,
		RequestedRole: role,
	}
	req.SetTokenEntry(te)
	return req, nil
}

// check runs CheckToken on a transparent request for role on the env's token.
func (e *grantEnv) check(role string) (*logical.Request, *logical.Auth, *logical.TokenEntry, error) {
	e.t.Helper()
	return e.checkToken(e.token, role)
}

func (e *grantEnv) checkToken(token, role string) (*logical.Request, *logical.Auth, *logical.TokenEntry, error) {
	e.t.Helper()
	req, err := e.transparent(token, role)
	require.NoError(e.t, err)
	auth, _, te, err := e.c.CheckToken(e.ctx, req, false)
	return req, auth, te, err
}

// requireGranted asserts a request for role was granted it through deployers.
func requireGranted(t *testing.T, req *logical.Request, te *logical.TokenEntry, err error, role string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, req.RoleGrant())
	assert.Equal(t, "group:deployers", req.RoleGrant().GrantedBy)
	assert.Empty(t, req.RoleGrant().DeniedReason)
	assert.Equal(t, role, te.RoleName)
}

// requireDenied asserts err is the role verdict's refusal for reason.
func requireDenied(t *testing.T, req *logical.Request, err error, reason string) *ErrRoleNotGranted {
	t.Helper()
	require.Error(t, err)
	var rerr *ErrRoleNotGranted
	require.True(t, errors.As(err, &rerr), "want a role refusal, got %v", err)
	assert.Equal(t, reason, rerr.DeniedReason)
	require.NotNil(t, req.RoleGrant())
	assert.Equal(t, reason, req.RoleGrant().DeniedReason)
	assert.Empty(t, req.RoleGrant().GrantedBy)
	return rerr
}

func TestRoleGrant_GrantedAndProjected(t *testing.T) {
	e := newGrantEnv(t)

	req, auth, te, err := e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
	assert.Equal(t, []string{"deploy"}, te.Policies)
	assert.Equal(t, "deploy-spec", te.CredentialSpec)
	assert.Equal(t, map[string]string{"repo": "acme/infra", "sub": "agent-1"}, te.Metadata,
		"token metadata is the membership's rendering of the mapped facts")
	assert.Equal(t, []string{"deployers"}, req.RoleGrant().Groups)
	assert.Equal(t, "deploy", req.RoleGrant().Role.Name)
	assert.Equal(t, []string{"deploy"}, auth.Policies, "the per-request Auth reads the projection")
	assert.True(t, auth.PolicyResults.Allowed)
	assert.Equal(t, te.Metadata, req.TokenMetadata)

	// The cached entry was never written: the next lookup is unprojected.
	cached, err := e.c.LookupToken(e.ctx, e.token)
	require.NoError(t, err)
	assert.Empty(t, cached.RoleName)
	assert.Nil(t, cached.Policies)
	assert.Empty(t, cached.CredentialSpec)
	assert.Nil(t, cached.Metadata)
	stored, ok := e.c.tokenStore.byID.Get(cached.ID)
	require.True(t, ok)
	assert.Empty(t, stored.RoleName)
	assert.Nil(t, stored.Policies)
	assert.Same(t, e.adm, stored.Admission)
	assert.Same(t, e.adm, te.Admission, "the per-request copy shares the admission")
}

func TestRoleGrant_Refusals(t *testing.T) {
	cases := []struct {
		name    string
		request func(e *grantEnv) *logical.Request
		reason  string
		message string
	}{
		{
			name:    "no role selected",
			request: func(e *grantEnv) *logical.Request { return mustTransparent(e, e.token, "") },
			reason:  logical.RoleDeniedNoRole,
			message: "no role selected: put the role in the URL (role/<name>/), set X-Warden-Role, or set the provider's default_role",
		},
		{
			name:    "role not found",
			request: func(e *grantEnv) *logical.Request { return mustTransparent(e, e.token, "nope") },
			reason:  logical.RoleDeniedNotFound,
			message: `role "nope" not found`,
		},
		{
			name:    "not assumable",
			request: func(e *grantEnv) *logical.Request { return mustTransparent(e, e.token, "other") },
			reason:  logical.RoleDeniedNotAssumable,
			message: `role "other" is not assumable through auth/jwt/: no group grants it to this caller`,
		},
		{
			name: "admission token presented explicitly",
			request: func(e *grantEnv) *logical.Request {
				// No implicit auth ran: the token is looked up from ClientToken
				// and the request is not transparent.
				return &logical.Request{Operation: logical.ReadOperation, Path: "secret/x", ClientToken: e.token}
			},
			reason:  logical.RoleDeniedExplicitAdmission,
			message: "admission token presented explicitly; present the credential instead",
		},
		{
			name: "a requested role without implicit auth",
			request: func(e *grantEnv) *logical.Request {
				// A role recorded on a request implicit auth did not mark
				// transparent grants nothing.
				return &logical.Request{Operation: logical.ReadOperation, Path: "secret/x", ClientToken: e.token, RequestedRole: "deploy"}
			},
			reason:  logical.RoleDeniedExplicitAdmission,
			message: "admission token presented explicitly; present the credential instead",
		},
		{
			name:    "no admission on token",
			request: func(e *grantEnv) *logical.Request { return mustTransparent(e, e.issue(nil, nil), "deploy") },
			reason:  logical.RoleDeniedNoAdmission,
			message: "token carries no admission to grant a role from; present the credential instead",
		},
		{
			// An older version stored the role and its policies on the token;
			// neither is honoured.
			name: "a token stored with a role",
			request: func(e *grantEnv) *logical.Request {
				req := mustTransparent(e, e.issue(nil, []string{"deploy"}), "deploy")
				req.TokenEntry().RoleName = "deploy"
				return req
			},
			reason:  logical.RoleDeniedNoAdmission,
			message: "token carries no admission to grant a role from; present the credential instead",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGrantEnv(t)
			req := tc.request(e)
			auth, _, te, err := e.c.CheckToken(e.ctx, req, false)
			rerr := requireDenied(t, req, err, tc.reason)
			assert.Equal(t, tc.message, rerr.Message)
			assert.Contains(t, err.Error(), tc.message)
			// The response body carries the refusal's message alone, not the
			// bulleted list of the multierror it was gathered in.
			assert.Equal(t, []string{tc.message}, logical.ErrorMessages(logical.ErrorResponse(err).Err))
			assert.Equal(t, http.StatusForbidden, logical.GetErrorCode(err))
			assert.ErrorIs(t, err, sdklogical.ErrPermissionDenied)
			assert.False(t, auth.PolicyResults.Allowed)
			require.NotNil(t, te)
			assert.Empty(t, te.RoleName)
			assert.Nil(t, te.Policies, "a refused admission token keeps no policies")
			assert.Empty(t, te.CredentialSpec)
			for _, secret := range []string{"deployers", "acme", "repo", "agent-1"} {
				assert.NotContains(t, rerr.Message, secret, "a refusal never echoes groups or facts")
			}
		})
	}
}

func mustTransparent(e *grantEnv, token, role string) *logical.Request {
	e.t.Helper()
	req, err := e.transparent(token, role)
	require.NoError(e.t, err)
	return req
}

// With no published roles or groups (an unloaded store, a standby) every role
// is "not found": the empty snapshots fail closed.
func TestRoleGrant_NoSnapshots(t *testing.T) {
	t.Run("unloaded stores", func(t *testing.T) {
		e := newGrantEnv(t)
		e.c.roleStore.Unload()
		e.c.identityStore.Unload()
		req, _, _, err := e.check("deploy")
		requireDenied(t, req, err, logical.RoleDeniedNotFound)
		assert.Empty(t, req.RoleGrant().Groups)
	})
	t.Run("no stores", func(t *testing.T) {
		e := newGrantEnv(t)
		e.c.roleStore, e.c.identityStore = nil, nil
		req, _, _, err := e.check("deploy")
		requireDenied(t, req, err, logical.RoleDeniedNotFound)
	})
}

// With the verdict row switched off, a refused grant is still refused: the
// admission token carries no policies into the CBP, even when its login
// handed it some.
func TestRoleGrant_FailClosedWithoutVerdict(t *testing.T) {
	testHookSkipRoleVerdict = true
	t.Cleanup(func() { testHookSkipRoleVerdict = false })

	e := newGrantEnv(t)
	withPolicies := e.issue(e.adm, []string{"deploy"})

	for name, req := range map[string]*logical.Request{
		"not assumable":                     mustTransparent(e, e.token, "other"),
		"not assumable, login had policies": mustTransparent(e, withPolicies, "other"),
		"explicit, login had policies": {
			Operation: logical.ReadOperation, Path: "secret/x", ClientToken: withPolicies,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, te, err := e.c.CheckToken(e.ctx, req, false)
			require.Error(t, err)
			assert.ErrorIs(t, err, sdklogical.ErrPermissionDenied)
			var rerr *ErrRoleNotGranted
			assert.False(t, errors.As(err, &rerr), "the CBP refused, not the verdict row")
			assert.Nil(t, te.Policies)
		})
	}

	// The same request is granted when a group grants the role: the hook only
	// skips the verdict.
	req, _, te, err := e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
}

// An unauthenticated check (a login) never evaluates the role verdict, as it
// never evaluates the CBP, so it resolves no grant either: its audit entry
// records no role_denied_reason. The admission token still keeps no policies.
func TestRoleGrant_SkippedUnauth(t *testing.T) {
	e := newGrantEnv(t)
	for _, token := range []string{e.token, e.issue(e.adm, []string{"deploy"})} {
		for _, req := range []*logical.Request{
			mustTransparent(e, token, "other"),
			{Operation: logical.UpdateOperation, Path: "auth/jwt/login", ClientToken: token},
		} {
			auth, _, te, err := e.c.CheckToken(e.ctx, req, true)
			require.NoError(t, err)
			assert.True(t, auth.PolicyResults.Allowed)
			assert.Nil(t, req.RoleGrant(), "no grant resolved under unauth")
			require.NotNil(t, te)
			assert.Nil(t, te.Policies)
			assert.Nil(t, auth.Policies)

			entry := e.c.buildRequestAuditEntry(e.ctx, req, auth, te, nil)
			raw, err := json.Marshal(entry)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "role_denied_reason")
			assert.NotContains(t, string(raw), "role_granted_by")
		}
	}
}

// On a steady membership resolving a grant allocates nothing, whatever the
// outcome: the grant lives on the request, the reasons are constants, and the
// membership, role and metadata are shared.
func TestRoleGrant_ResolveDoesNotAllocate(t *testing.T) {
	e := newGrantEnv(t)
	// A token no mount issued (as root and tokens created directly are) keeps
	// the policies it was issued.
	direct, err := e.c.tokenStore.GenerateToken(e.ctx, TypeServiceToken, &AuthData{
		PrincipalID: "agent-1",
		ExpireAt:    time.Now().Add(time.Hour),
		Policies:    []string{"deploy"},
	})
	require.NoError(t, err)
	noAdmission := e.issue(nil, nil)

	explicit := func() *logical.Request {
		req := mustTransparent(e, e.token, "deploy")
		req.Transparent, req.RequestedRole = false, ""
		return req
	}
	cases := []struct {
		name   string
		req    *logical.Request
		reason string // "" granted; "-" no grant at all
	}{
		{"granted", mustTransparent(e, e.token, "deploy"), ""},
		{"no role selected", mustTransparent(e, e.token, ""), logical.RoleDeniedNoRole},
		{"role not found", mustTransparent(e, e.token, "nope"), logical.RoleDeniedNotFound},
		{"not assumable", mustTransparent(e, e.token, "other"), logical.RoleDeniedNotAssumable},
		{"presented explicitly", explicit(), logical.RoleDeniedExplicitAdmission},
		{"no admission", mustTransparent(e, noAdmission, "deploy"), logical.RoleDeniedNoAdmission},
		{"token no mount issued", mustTransparent(e, direct.Data["token"], "deploy"), "-"},
	}
	now := time.Now()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, te := tc.req, tc.req.TokenEntry()
			role := te.RoleName
			e.c.resolveRoleGrant(req, te, now) // computes and caches the membership

			allocs := testing.AllocsPerRun(1000, func() {
				te.RoleName = role
				e.c.resolveRoleGrant(req, te, now)
			})
			assert.Zero(t, allocs)

			switch tc.reason {
			case "-":
				assert.Nil(t, req.RoleGrant())
				assert.Empty(t, te.RoleName)
				assert.Equal(t, []string{"deploy"}, te.Policies)
			case "":
				assert.True(t, req.RoleGrant().Granted())
				assert.Equal(t, "deploy", te.RoleName)
			default:
				assert.Equal(t, tc.reason, req.RoleGrant().DeniedReason)
				assert.Nil(t, te.Policies)
			}
		})
	}
}

// Every consumer reads the role from the token entry, so the projection is what
// they see.
func TestRoleGrant_ProjectionReachesEveryConsumer(t *testing.T) {
	e := newGrantEnv(t)

	// A second role whose spec mints a Warden identity assertion, to reach the
	// assertion cache identity. The spec and the issuer live in the exchange
	// tests' core, which takes a spec without checking it against a live
	// source; the token entry it resolves from is this env's projection.
	xc, xctx := exchangeResolveEnv(t)
	xc.oidcIssuer = newReadyIssuer(t, "https://warden-oidc.example")
	seedSpec(t, xc, xctx, "wid-spec", map[string]string{
		credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
		credential.ConfigAssertionAudience:  "https://sts.example/aud",
	})
	e.createRole(&logical.Role{Name: "minter", Policies: []string{"deploy"}, CredSpecName: "wid-spec"})
	g := deployersGroup()
	g.Roles = []string{"deploy", "minter"}
	e.updateGroup(g)

	req, auth, te, err := e.check("deploy")
	requireGranted(t, req, te, err, "deploy")

	checks := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{"CBP", func(t *testing.T) {
			assert.Equal(t, []string{"deploy"}, auth.Policies)
			assert.True(t, auth.PolicyResults.Allowed, "the role's policy allowed the path")
		}},
		{"audit", func(t *testing.T) {
			entry := e.c.buildRequestAuditEntry(e.ctx, req, auth, te, nil)
			assert.Equal(t, "deploy", entry.Auth.RoleName)
			assert.Equal(t, []string{"deploy"}, entry.Auth.Policies)
			assert.Equal(t, "group:deployers", entry.Auth.RoleGrantedBy)
			assert.Empty(t, entry.Auth.RoleDeniedReason)
			assert.Equal(t, []string{"deployers"}, entry.Auth.Groups)
		}},
		{"credential spec at mint", func(t *testing.T) {
			err := e.c.mintCredentialForRequest(e.ctx, req, te)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `credential spec "deploy-spec" not found or disabled`,
				"the mint reads the role's spec")
		}},
		{"identityFromTokenEntry (warden_role)", func(t *testing.T) {
			id := identityFromTokenEntry(te)
			assert.Equal(t, "deploy", id.RoleName)
			assert.Equal(t, grantAccessor, id.MountAccessor)
		}},
		{"assertion cache identity", func(t *testing.T) {
			mreq, _, mte, err := e.check("minter")
			requireGranted(t, mreq, mte, err, "minter")
			assert.Equal(t, "wid-spec", mte.CredentialSpec)
			inputs, err := xc.callerFor(mreq, mte, time.Hour, nil).ResolveInputs(xctx, mte.CredentialSpec)
			require.NoError(t, err)
			require.NotNil(t, inputs)
			assert.Contains(t, inputs.SubjectCacheIdentity, "\x00role=minter")
		}},
	}
	for _, c := range checks {
		t.Run(c.name, c.fn)
	}

	// CEL reads the projection through agent.*: each condition allows only
	// when it sees the role, policies, metadata and groups.
	cel := []struct {
		cond  string
		allow bool
	}{
		{`agent.role == 'deploy'`, true},
		{`'deploy' in agent.policies`, true},
		{`agent.metadata.repo == 'acme/infra'`, true},
		{`'deployers' in agent.groups`, true},
		{`agent.groups == ['deployers']`, true},
		{`'other' in agent.groups`, false},
		{`agent.role == 'other'`, false},
	}
	for _, c := range cel {
		t.Run("CEL "+c.cond, func(t *testing.T) {
			e.setPolicy("deploy", fmt.Sprintf(`path "secret/*" {
				capabilities = ["read"]
				condition    = %q
			}`, c.cond))
			req, _, te, err := e.check("deploy")
			if c.allow {
				requireGranted(t, req, te, err, "deploy")
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, sdklogical.ErrPermissionDenied)
			var rerr *ErrRoleNotGranted
			assert.False(t, errors.As(err, &rerr), "granted; the condition refused")
		})
	}
}

// After each edit the next request on the cached token sees it, with no
// re-login.
func TestRoleGrant_RevocationTiming(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *grantEnv) // before the first request
		edit  func(e *grantEnv)
		check func(t *testing.T, req *logical.Request, te *logical.TokenEntry, err error)
	}{
		{
			name: "group roles edit",
			edit: func(e *grantEnv) {
				g := deployersGroup()
				g.Roles = []string{"other"}
				e.updateGroup(g)
			},
			check: deniedBecause(logical.RoleDeniedNotAssumable),
		},
		{
			name: "group rules edit",
			edit: func(e *grantEnv) {
				g := deployersGroup()
				g.Rules = []logical.GroupRule{{"mount": {grantMount}, "repo": {"other/*"}}}
				e.updateGroup(g)
			},
			check: deniedBecause(logical.RoleDeniedNotAssumable),
		},
		{
			name: "group delete",
			edit: func(e *grantEnv) {
				require.NoError(e.t, e.c.identityStore.DeleteGroup(e.ctx, "deployers", "", ""))
			},
			check: deniedBecause(logical.RoleDeniedNotAssumable),
		},
		{
			name: "role delete",
			edit: func(e *grantEnv) {
				require.NoError(e.t, e.c.roleStore.Delete(e.ctx, "deploy", ""))
			},
			check: deniedBecause(logical.RoleDeniedNotFound),
		},
		{
			name: "policy change",
			edit: func(e *grantEnv) {
				e.setPolicy("deploy", `path "elsewhere/*" { capabilities = ["read"] }`)
			},
			check: func(t *testing.T, req *logical.Request, te *logical.TokenEntry, err error) {
				require.Error(t, err)
				var rerr *ErrRoleNotGranted
				assert.False(t, errors.As(err, &rerr), "still granted; the policy no longer allows the path")
				assert.ErrorIs(t, err, sdklogical.ErrPermissionDenied)
				assert.Equal(t, "group:deployers", req.RoleGrant().GrantedBy)
			},
		},
		{
			name: "spec change",
			edit: func(e *grantEnv) {
				_, err := e.c.roleStore.Update(e.ctx, &logical.Role{Name: "deploy", Policies: []string{"deploy"}, CredSpecName: "new-spec"}, "")
				require.NoError(e.t, err)
			},
			check: func(t *testing.T, req *logical.Request, te *logical.TokenEntry, err error) {
				requireGranted(t, req, te, err, "deploy")
				assert.Equal(t, "new-spec", te.CredentialSpec)
			},
		},
		{
			name: "mapping edit",
			edit: func(e *grantEnv) {
				e.mf.Publish(testNaming(e.t, "", map[string]string{"sub": "sub"}))
			},
			check: func(t *testing.T, req *logical.Request, te *logical.TokenEntry, err error) {
				deniedBecause(logical.RoleDeniedNotAssumable)(t, req, te, err)
				assert.Equal(t, map[string]string{"sub": "agent-1"}, te.Metadata, "metadata follows the mapping too")
			},
		},
		{
			name: "entity_kind edit",
			setup: func(e *grantEnv) {
				g := deployersGroup()
				g.Rules = []logical.GroupRule{{"mount": {grantMount}, "repo": {"acme/*"}, "kind": {logical.EntityKindAgent}}}
				e.updateGroup(g)
			},
			edit: func(e *grantEnv) {
				e.mf.Publish(testNaming(e.t, logical.EntityKindHuman, map[string]string{"repository": "repo", "sub": "sub"}))
			},
			check: deniedBecause(logical.RoleDeniedNotAssumable),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGrantEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			req, _, te, err := e.check("deploy")
			requireGranted(t, req, te, err, "deploy")

			tc.edit(e)
			req, _, te, err = e.check("deploy")
			tc.check(t, req, te, err)
		})
	}
}

func deniedBecause(reason string) func(t *testing.T, req *logical.Request, te *logical.TokenEntry, err error) {
	return func(t *testing.T, req *logical.Request, te *logical.TokenEntry, err error) {
		t.Helper()
		requireDenied(t, req, err, reason)
		assert.Nil(t, te.Policies)
	}
}

// Requests on one cached admission token race group publishes and mapping
// edits: each sees one consistent state, granted or not assumable.
func TestRoleGrant_ConcurrentPublish(t *testing.T) {
	e := newGrantEnv(t)

	const workers, iterations = 8, 100
	var wg sync.WaitGroup
	errs := make(chan error, workers*iterations)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				req, err := e.transparent(e.token, "deploy")
				if err != nil {
					errs <- err
					return
				}
				_, _, te, err := e.c.CheckToken(e.ctx, req, false)
				switch {
				case err == nil:
					rg := req.RoleGrant()
					if te.RoleName != "deploy" || rg.GrantedBy != "group:deployers" ||
						len(rg.Groups) != 1 || rg.Groups[0] != "deployers" {
						errs <- fmt.Errorf("granted with an inconsistent projection: role %q, grant %+v", te.RoleName, rg)
					}
				default:
					var rerr *ErrRoleNotGranted
					if !errors.As(err, &rerr) || rerr.DeniedReason != logical.RoleDeniedNotAssumable {
						errs <- fmt.Errorf("unexpected refusal: %w", err)
					}
					if te.Policies != nil {
						errs <- errors.New("refused with policies")
					}
				}
			}
		}()
	}

	withRole, without := deployersGroup(), deployersGroup()
	without.Roles = []string{"other"}
	full := testNaming(t, "", map[string]string{"repository": "repo", "sub": "sub"})
	bare := testNaming(t, "", map[string]string{"sub": "sub"})
	for i := range 40 {
		if i%2 == 0 {
			e.updateGroup(without)
			e.mf.Publish(bare)
		} else {
			e.updateGroup(withRole)
			e.mf.Publish(full)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Quiesced on the granting state, the next request is granted.
	req, _, te, err := e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
}

// A fact is reachable only once the mount maps it: the operator vouches for a
// name by mapping it.
func TestRoleGrant_MappingIsTheAllowlist(t *testing.T) {
	e := newGrantEnv(t)
	g := deployersGroup()
	g.Rules = []logical.GroupRule{{"mount": {grantMount}, "email": {"*@acme.example"}}}
	e.updateGroup(g)

	req, _, _, err := e.check("deploy")
	requireDenied(t, req, err, logical.RoleDeniedNotAssumable)

	e.mf.Publish(testNaming(t, "", map[string]string{"repository": "repo", "sub": "sub", "email": "email"}))
	req, _, te, err := e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
	assert.Equal(t, "a@acme.example", te.Metadata["email"])

	e.mf.Publish(testNaming(t, "", map[string]string{"repository": "repo", "sub": "sub"}))
	req, _, _, err = e.check("deploy")
	requireDenied(t, req, err, logical.RoleDeniedNotAssumable)
}

// A rule trusts only the mounts it lists.
func TestRoleGrant_MountPinning(t *testing.T) {
	e := newGrantEnv(t)
	k8s := e.issue(e.admission("auth/k8s/"), nil)
	later := e.issue(e.admission("auth/later/"), nil)

	grant := func(token string) bool {
		t.Helper()
		_, _, _, err := e.checkToken(token, "deploy")
		return err == nil
	}

	assert.True(t, grant(e.token), "the listed mount")
	assert.False(t, grant(k8s), "a mount mapping the same fact but not listed")
	assert.False(t, grant(later))

	g := deployersGroup()
	g.Rules = []logical.GroupRule{{"mount": {grantMount, "auth/k8s/"}, "repo": {"acme/*"}}}
	e.updateGroup(g)
	assert.True(t, grant(e.token))
	assert.True(t, grant(k8s), "listed now")
	assert.False(t, grant(later), "a mount added later matches only once listed")

	g.Rules = []logical.GroupRule{{"mount": {grantMount, "auth/k8s/", "auth/later/"}, "repo": {"acme/*"}}}
	e.updateGroup(g)
	assert.True(t, grant(later))

	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "unpinned", Type: logical.GroupTypeVirtual, Roles: []string{"deploy"},
		Rules: []logical.GroupRule{{"repo": {"acme/*"}}},
	})
	require.Error(t, err, "a rule without mount is refused")

	warnings, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "everywhere", Type: logical.GroupTypeVirtual, Roles: []string{"other"},
		Rules: []logical.GroupRule{{"mount": {"**"}, "repo": {"acme/*"}}},
	})
	require.NoError(t, err)
	assert.True(t, slicesContainSubstring(warnings, `"**"`), "warnings: %v", warnings)
	_, _, _, err = e.checkToken(later, "other")
	assert.NoError(t, err, `"**" trusts every mount`)
}

func slicesContainSubstring(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// A rule on kind keeps an admission through a human mount out.
func TestRoleGrant_KindKeepsHumanMountOut(t *testing.T) {
	e := newGrantEnv(t)
	g := deployersGroup()
	g.Rules = []logical.GroupRule{{"mount": {grantMount}, "kind": {logical.EntityKindAgent}}}
	e.updateGroup(g)

	humanFacts := &logical.MountFacts{}
	humanFacts.Publish(testNaming(t, logical.EntityKindHuman, map[string]string{"sub": "sub"}))
	human := e.admission(grantMount)
	human.Mount = humanFacts
	tok := e.issue(human, nil)

	req, _, _, err := e.checkToken(tok, "deploy")
	requireDenied(t, req, err, logical.RoleDeniedNotAssumable)

	req, _, te, err := e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
}

// A mount that publishes no naming answers no fact, so no group matches; an
// admission with no mount at all is the same.
func TestRoleGrant_NoNamingNoGroups(t *testing.T) {
	for name, mount := range map[string]*logical.MountFacts{
		"no naming published": {},
		"no mount":            nil,
	} {
		t.Run(name, func(t *testing.T) {
			e := newGrantEnv(t)
			adm := e.admission(grantMount)
			adm.Mount = mount
			req, _, te, err := e.checkToken(e.issue(adm, nil), "deploy")
			requireDenied(t, req, err, logical.RoleDeniedNotAssumable)
			assert.Empty(t, req.RoleGrant().Groups)
			assert.Nil(t, te.Metadata)
		})
	}
}

// The transparent marker and the requested role are set by implicit auth
// alone: no other code in core writes them, and neither is decoded from a
// request body. The grant itself is written only where CheckToken resolves it:
// resolveRoleGrant, or withholdRoleGrant for a check that renders no verdict.
func TestRoleGrant_SingleWriters(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)

	writers := map[string][]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.AssignStmt:
						for _, lhs := range n.Lhs {
							if sel, ok := lhs.(*ast.SelectorExpr); ok && (sel.Sel.Name == "RequestedRole" || sel.Sel.Name == "Transparent") {
								writers[sel.Sel.Name] = append(writers[sel.Sel.Name], fn.Name.Name)
							}
						}
					case *ast.CallExpr:
						if sel, ok := n.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "SetRoleGrant" || sel.Sel.Name == "ClearRoleGrant") {
							writers["grant"] = append(writers["grant"], fn.Name.Name)
						}
					}
					return true
				})
			}
		}
	}
	assert.Equal(t, []string{"performImplicitAuth"}, writers["RequestedRole"])
	assert.Equal(t, []string{"performImplicitAuth"}, writers["Transparent"])
	assert.NotEmpty(t, writers["grant"])
	for _, w := range writers["grant"] {
		assert.Contains(t, []string{"resolveRoleGrant", "withholdRoleGrant"}, w,
			"only CheckToken's resolution writes the request's grant")
	}

	f, ok := reflect.TypeOf(logical.Request{}).FieldByName("RequestedRole")
	require.True(t, ok)
	assert.Equal(t, "-", f.Tag.Get("json"))
	f, ok = reflect.TypeOf(logical.Request{}).FieldByName("Transparent")
	require.True(t, ok)
	assert.Equal(t, "-", f.Tag.Get("json"))
}

func TestRoleGrant_AgentGroups(t *testing.T) {
	now := time.Now()

	t.Run("bound by reference", func(t *testing.T) {
		groups := []string{"a", "b"}
		req := &logical.Request{}
		req.SetRoleGrant(logical.RoleGrant{Groups: groups})
		ns := buildPrincipalNS(celAgentInput(req, &logical.TokenEntry{}, now), fieldSet{all: true}, legAgent)
		bound, ok := ns["groups"].([]string)
		require.True(t, ok)
		assert.Equal(t, unsafe.SliceData(groups), unsafe.SliceData(bound), "no copy")
	})

	t.Run("empty, never nil, without a grant", func(t *testing.T) {
		for _, req := range []*logical.Request{nil, {}} {
			ns := buildPrincipalNS(celAgentInput(req, &logical.TokenEntry{}, now), fieldSet{all: true}, legAgent)
			bound, ok := ns["groups"].([]string)
			require.True(t, ok)
			assert.NotNil(t, bound)
			assert.Empty(t, bound)
		}
	})

	t.Run("not on the user leg", func(t *testing.T) {
		ns := buildPrincipalNS(celPrincipalInput{Present: true, Groups: []string{"a"}}, fieldSet{all: true}, legUser)
		_, ok := ns["groups"]
		assert.False(t, ok)
	})

	t.Run("in and not in", func(t *testing.T) {
		for cond, want := range map[string]bool{
			`'deployers' in agent.groups`: true,
			`'other' in agent.groups`:     false,
			`size(agent.groups) == 0`:     true,
		} {
			env, err := baseCELEnv()
			require.NoError(t, err)
			cc, err := compileCELCondition(env, cond)
			require.NoError(t, err, cond)
			te := &logical.TokenEntry{}
			req := &logical.Request{}
			if cond != `size(agent.groups) == 0` {
				req.SetRoleGrant(logical.RoleGrant{Groups: []string{"deployers"}})
			}
			ok, _ := evaluatePathConditions([]*compiledCondition{cc}, req, te, now, "")
			assert.Equal(t, want, ok, cond)
		}
	})
}

// A token no mount issued (one created directly) and a root token authorize
// exactly as before on a transparent request: no grant, the entry is not
// rewritten, and audit gains no field.
func TestRoleGrant_TokensNoMountIssuedUnchanged(t *testing.T) {
	e := newGrantEnv(t)
	metadata := map[string]string{"team": "platform"}
	entry, err := e.c.tokenStore.GenerateToken(e.ctx, TypeServiceToken, &AuthData{
		PrincipalID: "agent-1",
		ExpireAt:    time.Now().Add(time.Hour),
		Policies:    []string{"deploy"},
		Metadata:    metadata,
	})
	require.NoError(t, err)
	direct := entry.Data["token"]
	root, err := e.c.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	run := func(token string, transparent bool) (*logical.Request, *logical.Auth, *logical.TokenEntry, error) {
		t.Helper()
		req := &logical.Request{Operation: logical.ReadOperation, Path: "secret/x", ClientToken: token}
		if transparent {
			te, err := e.c.LookupToken(e.ctx, token)
			require.NoError(t, err)
			req.SetTokenEntry(te)
			req.Transparent, req.RequestedRole = true, "deploy" // what implicit auth records
		}
		auth, _, te, err := e.c.CheckToken(e.ctx, req, false)
		return req, auth, te, err
	}
	auditJSON := func(req *logical.Request, auth *logical.Auth, te *logical.TokenEntry) string {
		t.Helper()
		entry := e.c.buildRequestAuditEntry(e.ctx, req, auth, te, nil)
		entry.Timestamp = time.Time{}
		entry.Auth.TokenTTL = 0
		// The flag records the path a request took, not its token; this
		// compares only what the token decides.
		entry.Request.Transparent = false
		b, err := json.Marshal(entry)
		require.NoError(t, err)
		return string(b)
	}

	for name, token := range map[string]string{"direct token": direct, "root token": root} {
		t.Run(name, func(t *testing.T) {
			plainReq, plainAuth, plainTE, plainErr := run(token, false)
			req, auth, te, err := run(token, true)
			require.NoError(t, plainErr)
			require.NoError(t, err)

			assert.Nil(t, req.RoleGrant(), "no grant for a token no mount issued")
			assert.Equal(t, plainTE, te)
			assert.Equal(t, plainAuth.Policies, auth.Policies)
			assert.Equal(t, plainAuth.PolicyResults, auth.PolicyResults)
			assert.Equal(t, auditJSON(plainReq, plainAuth, plainTE), auditJSON(req, auth, te))
			assert.NotContains(t, auditJSON(req, auth, te), "role_granted_by")
			assert.NotContains(t, auditJSON(req, auth, te), "groups")
		})
	}

	_, _, te, err := run(direct, true)
	require.NoError(t, err)
	assert.Empty(t, te.RoleName)
	assert.Equal(t, []string{"deploy"}, te.Policies)
	assert.Equal(t, metadata, te.Metadata, "the token's own metadata, not a membership's")
}

// Every request that waits on one implicit login gets its own entry, all
// sharing the login's admission; writing one (as an access backend writes the
// spec it returns) reaches no other and not the cache.
func TestResolveTransparentIdentity_EachWaiterGetsItsOwnEntry(t *testing.T) {
	core := createTestCore(t)
	ctx := rootCtx()
	backend := mountBlockingLogin(t, core, "jwt-block/")
	mf := &logical.MountFacts{}
	mf.Publish(testNaming(t, "", nil))
	backend.adm = &logical.Admission{Facts: selector.NewClaims(map[string]any{"sub": "agent-1"}), Mount: mf}
	jwt := mintK8sJWT(`{"sub":"agent-1"}`)

	const waiters = 8
	leader := resolveAsync(core, ctx, jwt)
	receiveWithin(t, backend.entered, "the leader's login to start")
	followers := make([]<-chan resolved, waiters-1)
	for i := range followers {
		followers[i] = resolveAsync(core, ctx, jwt)
	}
	time.Sleep(50 * time.Millisecond) // let the followers join the login in flight
	backend.open()

	results := []resolved{receiveWithin(t, leader, "the leader's token")}
	for i, f := range followers {
		results = append(results, receiveWithin(t, f, fmt.Sprintf("follower %d", i)))
	}
	require.EqualValues(t, 1, backend.logins.Load(), "one login served every waiter")

	seen := map[*TokenEntry]bool{}
	for _, r := range results {
		require.NoError(t, r.err)
		require.NotNil(t, r.te)
		assert.False(t, seen[r.te], "two waiters share one *TokenEntry")
		seen[r.te] = true
		assert.Same(t, backend.adm, r.te.Admission, "every copy shares the login's admission")
	}

	// Each request writes its own entry concurrently, as the access-backend
	// path writes the spec its backend returned. On one shared entry this is a
	// data race (-race) and the requests see each other's spec.
	var wg sync.WaitGroup
	for i, r := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.te.CredentialSpec = fmt.Sprintf("spec-%d", i)
			r.te.RoleName = fmt.Sprintf("role-%d", i)
		}()
	}
	wg.Wait()
	for i, r := range results {
		assert.Equal(t, fmt.Sprintf("spec-%d", i), r.te.CredentialSpec)
	}

	cached, ok := core.tokenStore.byID.Get(results[0].te.ID)
	require.True(t, ok)
	assert.Empty(t, cached.RoleName, "no request's write reached the cache")
	assert.Empty(t, cached.CredentialSpec)
}

// GenerateToken hands out a copy, never the entry the cache holds: neither the
// one it stored nor the one a transparent login found already there.
func TestGenerateToken_ReturnsCopy(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	authData := func() *AuthData {
		return &AuthData{
			PrincipalID:   "agent-1",
			MountAccessor: grantAccessor,
			ExpireAt:      time.Now().Add(time.Hour),
			TokenValue:    mintK8sJWT(`{"sub":"agent-1"}`),
		}
	}

	first, err := c.tokenStore.GenerateToken(ctx, TypeIdentityToken, authData())
	require.NoError(t, err)
	cached, ok := c.tokenStore.byID.Get(first.ID)
	require.True(t, ok)
	assert.NotSame(t, cached, first, "a fresh token is handed out as a copy")

	// Same credential and mount: the dedupe branch finds the cached one.
	again, err := c.tokenStore.GenerateToken(ctx, TypeIdentityToken, authData())
	require.NoError(t, err)
	assert.Equal(t, first.ID, again.ID)
	assert.NotSame(t, cached, again, "the dedupe branch hands out a copy")
	again.RoleName = "projected"
	assert.Empty(t, cached.RoleName)
}
