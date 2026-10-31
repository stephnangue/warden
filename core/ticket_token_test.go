package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// ticketIssuer is an auth backend that publishes facts, as a mount issuing
// tickets does: a live naming, and the sealer core handed it at setup.
type ticketIssuer struct {
	mf     *logical.MountFacts
	sealer logical.Sealer
}

var _ logical.FactsProvider = (*ticketIssuer)(nil)

func (b *ticketIssuer) FactNames() []string                         { return b.mf.Load().Mapping.Names() }
func (b *ticketIssuer) EntityKind() string                          { return b.mf.Load().Kind }
func (b *ticketIssuer) AliasChange(map[string]any) (string, string) { return "", "" }
func (b *ticketIssuer) MountFacts() *logical.MountFacts             { return b.mf }
func (b *ticketIssuer) HandleRequest(context.Context, *logical.Request) (*logical.Response, error) {
	return nil, nil
}
func (b *ticketIssuer) Cleanup(context.Context)                             {}
func (b *ticketIssuer) Setup(context.Context, *logical.BackendConfig) error { return nil }
func (b *ticketIssuer) Initialize(context.Context) error                    { return nil }
func (b *ticketIssuer) Config() map[string]any                              { return nil }
func (b *ticketIssuer) Type() string                                        { return "ticketissuer" }
func (b *ticketIssuer) Class() logical.BackendClass                         { return logical.ClassAuth }
func (b *ticketIssuer) HandleExistenceCheck(context.Context, *logical.Request) (bool, bool, error) {
	return false, false, nil
}
func (b *ticketIssuer) SpecialPaths() *logical.Paths                       { return nil }
func (b *ticketIssuer) ExtractTokens(*http.Request, bool) (string, string) { return "", "" }

// ticketBuiltins are the issuer's built-in facts; ticketFacts what it maps.
var (
	ticketBuiltins = []string{"iss", "sub", "oid", "tid"}
	ticketFacts    = map[string]string{
		"roles":            "roles",
		"/address/country": "country",
		"level":            "level",
		"admin":            "admin",
		"sub":              "sub",
	}
)

// ticketEnv is a test core with a ticket-issuing mount.
type ticketEnv struct {
	t      *testing.T
	c      *Core
	ns     *namespace.Namespace
	ctx    context.Context
	issuer *ticketIssuer
	mount  *MountEntry
}

func newTicketEnv(t *testing.T) *ticketEnv {
	t.Helper()
	c := createTestCore(t)
	e := &ticketEnv{t: t, c: c, ns: namespace.RootNamespace, ctx: rootCtx()}
	e.issuer, e.mount = e.mountIssuer(e.ctx, "oidc/")
	return e
}

// mountIssuer enables a ticket-issuing mount at path in ctx's namespace.
func (e *ticketEnv) mountIssuer(ctx context.Context, path string) (*ticketIssuer, *MountEntry) {
	e.t.Helper()
	mapping, err := selector.CompileMapping(ticketBuiltins, ticketFacts)
	require.NoError(e.t, err)
	naming, err := logical.NewMountNaming(mapping, logical.EntityKindHuman)
	require.NoError(e.t, err)
	naming.AliasSource = "oid"
	b := &ticketIssuer{mf: &logical.MountFacts{}}
	b.mf.Publish(naming)
	e.c.authMethods["ticketissuer"] = func(_ context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b.sealer = conf.Sealer
		return b, nil
	}
	require.NoError(e.t, e.c.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "ticketissuer", Path: path}))
	ns, err := namespace.FromContext(ctx)
	require.NoError(e.t, err)
	me := e.c.router.MatchingMountEntry(ctx, authRoutePrefix+path)
	require.NotNil(e.t, me)
	require.Equal(e.t, ns.ID, me.NamespaceID)
	return b, me
}

// ticketClaims returns the ID-token claims a login keeps, decoded as
// encoding/json decodes them.
func ticketClaims(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(`{
		"iss": "https://idp.example/tenant/v2.0",
		"sub": "pairwise-sub",
		"oid": "0583-oid",
		"tid": "tenant",
		"roles": ["Warden.Operator", "Warden.Auditor"],
		"address": {"country": "CM"},
		"level": 3,
		"admin": true
	}`), &m))
	return m
}

// login issues a ticket through LoginCreateToken, as handleLoginRequest does,
// and returns the value handed to the client and the response.
func (e *ticketEnv) login(ctx context.Context, b *ticketIssuer, me *MountEntry, ttl time.Duration) (string, *logical.Response) {
	e.t.Helper()
	adm := &logical.Admission{
		Facts:       selector.NewClaims(ticketClaims(e.t)),
		PrincipalID: "0583-oid",
		Mount:       b.mf,
		AuthTime:    time.Now().Add(-time.Minute).Truncate(time.Second),
		Bytes:       200,
	}
	ns, err := namespace.FromContext(ctx)
	require.NoError(e.t, err)
	req := &logical.Request{MountAccessor: me.Accessor, MountPoint: ns.Path + authRoutePrefix + me.Path}
	resp := &logical.Response{Data: map[string]any{}, Auth: &logical.Auth{
		TokenType: TypeTicketToken, TokenTTL: ttl, PrincipalID: "0583-oid", Admission: adm,
	}}
	resp, err = e.c.LoginCreateToken(ctx, req, resp)
	require.NoError(e.t, err)
	data, ok := resp.Data["data"].(map[string]string)
	require.True(e.t, ok)
	require.True(e.t, strings.HasPrefix(data["token"], "wdt."), data["token"])
	return data["token"], resp
}

// seal seals any payload under the ticket context, as encodeTicket does.
func (e *ticketEnv) seal(p any) string {
	e.t.Helper()
	plain, err := json.Marshal(p)
	require.NoError(e.t, err)
	sealed, err := e.c.barrier.Encrypt(e.ctx, ticketContext, plain)
	require.NoError(e.t, err)
	return ticketValuePrefix + base64.RawURLEncoding.EncodeToString(sealed)
}

// payload returns a valid payload for e's issuer, which tests then spoil.
func (e *ticketEnv) payload() logical.TicketPayload {
	now := time.Now()
	return logical.TicketPayload{
		V: 1, Alias: "0583-oid", PrincipalID: "0583-oid", Kind: logical.EntityKindHuman,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		NamespaceID: e.ns.ID, MountAccessor: e.mount.Accessor,
		Facts: json.RawMessage(`{"oid":"0583-oid"}`),
	}
}

// sealVersion1 seals plain in the earlier barrier format, whose decryption
// ignores the context it is opened under.
func (e *ticketEnv) sealVersion1(context string, plain []byte) []byte {
	e.t.Helper()
	gcm := e.c.barrier.(*TransactionalAESGCMBarrier).AESGCMBarrier
	gcm.currentAESGCMVersionByte = AESGCMVersion1
	defer func() { gcm.currentAESGCMVersionByte = AESGCMVersion2 }()
	sealed, err := e.c.barrier.Encrypt(e.ctx, context, plain)
	require.NoError(e.t, err)
	return sealed
}

func (e *ticketEnv) flushCache() {
	e.c.tokenStore.byID.Clear()
	e.c.tokenStore.byID.Wait()
}

func TestTicket_LoginIssuesStatelessToken(t *testing.T) {
	e := newTicketEnv(t)
	value, resp := e.login(e.ctx, e.issuer, e.mount, time.Hour)

	assert.Equal(t, TypeTicketToken, resp.Data["token_type"])
	assert.Equal(t, "", resp.Data["token_assessor"], "a ticket has no accessor")
	assert.Regexp(t, `^wdt_[0-9a-f]{32}$`, resp.Data["token_id"])
	assert.Equal(t, "wdt_"+hashTokenID(value), resp.Data["token_id"])
	assert.Equal(t, logical.TicketLen(len(mustDecodePayload(t, e, value))), len(value), "TicketLen predicts the value's length")
	assert.Less(t, len(value), 1000)

	// Nothing reaches storage, and a reload finds no ticket.
	ids, err := e.c.tokenStore.storage.List(e.ctx, tokenIDPrefix)
	require.NoError(t, err)
	assert.Empty(t, ids)
	accessors, err := e.c.tokenStore.storage.List(e.ctx, tokenAccessorPrefix)
	require.NoError(t, err)
	assert.Empty(t, accessors)
	e.flushCache()
	n, err := e.c.tokenStore.loadAllTokensFromStorage(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	// An identity token keeps its accessor.
	te, err := e.c.tokenStore.GenerateToken(e.ctx, TypeIdentityToken, &AuthData{
		TokenValue: "cred", MountAccessor: e.mount.Accessor, ExpireAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, te.Accessor)
}

func mustDecodePayload(t *testing.T, e *ticketEnv, value string) []byte {
	t.Helper()
	sealed, err := base64.RawURLEncoding.DecodeString(value[len(ticketValuePrefix):])
	require.NoError(t, err)
	plain, err := e.c.barrier.Decrypt(e.ctx, ticketContext, sealed)
	require.NoError(t, err)
	return plain
}

// A ticket decoded on a node that never saw the login (an empty cache)
// rebuilds the entry the login cached: every field, and an admission that
// answers every fact alike.
func TestTicket_DecodedEntryMatchesIssued(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)

	issued, err := e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)
	e.flushCache()
	decoded, err := e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)

	assert.Equal(t, issued.ID, decoded.ID)
	assert.Equal(t, TypeTicketToken, decoded.Type)
	assert.Equal(t, issued.NamespaceID, decoded.NamespaceID)
	assert.Equal(t, issued.NamespacePath, decoded.NamespacePath)
	assert.True(t, issued.CreatedAt.Equal(decoded.CreatedAt))
	assert.True(t, issued.ExpireAt.Equal(decoded.ExpireAt))
	assert.Equal(t, issued.PrincipalID, decoded.PrincipalID)
	assert.Equal(t, issued.MountAccessor, decoded.MountAccessor)
	assert.Equal(t, issued.Data, decoded.Data)
	assert.Empty(t, decoded.Accessor)
	assert.Nil(t, decoded.Policies)
	assert.Empty(t, decoded.CreatedByIP)

	a, b := issued.Admission, decoded.Admission
	require.NotNil(t, a)
	require.NotNil(t, b)
	assert.Equal(t, "auth/oidc/", b.MountPath)
	assert.Equal(t, a.MountPath, b.MountPath)
	assert.Equal(t, a.MountAccessor, b.MountAccessor)
	assert.Equal(t, "0583-oid", b.AliasName)
	assert.Equal(t, a.AliasName, b.AliasName)
	assert.Equal(t, a.PrincipalID, b.PrincipalID)
	assert.Equal(t, logical.EntityKindHuman, b.Kind)
	assert.Equal(t, a.Kind, b.Kind)
	assert.True(t, a.AuthTime.Equal(b.AuthTime))
	assert.True(t, a.IssuedAt.Equal(b.IssuedAt), "a ticket's admission is issued with the ticket")
	assert.True(t, b.IssuedAt.Equal(decoded.CreatedAt))
	assert.False(t, a.AudienceBound)
	assert.False(t, b.AudienceBound)
	assert.Same(t, a.Mount, b.Mount, "both read the mount's live naming")

	n := e.issuer.mf.Load()
	for _, name := range append([]string{selector.NameMount, selector.NameKind}, n.Mapping.Names()...) {
		assert.Equal(t, values(a, n, name), values(b, n, name), "fact %q", name)
	}
	assert.Equal(t, []string{"auth/oidc/"}, values(b, n, selector.NameMount))
	assert.Equal(t, []string{"human"}, values(b, n, selector.NameKind))
	assert.Equal(t, []string{"Warden.Operator", "Warden.Auditor"}, values(b, n, "roles"))
	assert.Equal(t, []string{"CM"}, values(b, n, "country"), "a JSON-pointer source")
	assert.Equal(t, []string{"3"}, values(b, n, "level"), "a number keeps its type")
	assert.Equal(t, []string{"true"}, values(b, n, "admin"), "a boolean keeps its type")
	assert.Equal(t, []string{"pairwise-sub"}, values(b, n, "sub"), "an identity mapping")
}

func values(a *logical.Admission, n *logical.MountNaming, name string) []string {
	var out []string
	cur := a.Lookup(n, name)
	for {
		v, ok := cur.Next()
		if !ok {
			return out
		}
		out = append(out, string(selector.FormatScalar(nil, v)))
	}
}

func TestTicket_Refusals(t *testing.T) {
	e := newTicketEnv(t)
	valid := e.seal(e.payload())
	_, err := e.c.LookupToken(e.ctx, valid)
	require.NoError(t, err, "the base payload is valid")

	withPayload := func(edit func(*logical.TicketPayload)) string {
		p := e.payload()
		edit(&p)
		return e.seal(p)
	}
	tamper := func(edit func([]byte)) string {
		sealed, err := base64.RawURLEncoding.DecodeString(valid[len(ticketValuePrefix):])
		require.NoError(t, err)
		edit(sealed)
		return ticketValuePrefix + base64.RawURLEncoding.EncodeToString(sealed)
	}

	// A version-1 ciphertext of a valid payload: the barrier would open it
	// whatever context is named.
	plain, err := json.Marshal(e.payload())
	require.NoError(t, err)
	v1 := e.sealVersion1(ticketContext, plain)
	opened, err := e.c.barrier.Decrypt(e.ctx, "any-context", v1)
	require.NoError(t, err, "the barrier ignores the context of a version-1 value")
	require.Equal(t, plain, opened)

	sealedUnder := func(context string) string {
		sealed, err := e.c.barrier.Encrypt(e.ctx, context, plain)
		require.NoError(t, err)
		return ticketValuePrefix + base64.RawURLEncoding.EncodeToString(sealed)
	}
	backendSealed, err := e.issuer.sealer.Seal(e.ctx, "ticket-token", plain)
	require.NoError(t, err)

	cases := map[string]string{
		"too short":                    "wdt.AAAA",
		"too long":                     "wdt." + strings.Repeat("A", 9*1024),
		"not base64url":                "wdt." + strings.Repeat("*", 100),
		"version-1 format byte":        ticketValuePrefix + base64.RawURLEncoding.EncodeToString(v1),
		"unknown key term":             tamper(func(b []byte) { b[0], b[1], b[2], b[3] = 0, 0, 0, 99 }),
		"bad tag":                      tamper(func(b []byte) { b[len(b)-1] ^= 1 }),
		"sealed under a storage path":  sealedUnder(tokenStorePath + tokenIDPrefix + "x"),
		"sealed with no context":       sealedUnder(""),
		"sealed by a backend's sealer": ticketValuePrefix + base64.RawURLEncoding.EncodeToString(backendSealed),
		"not JSON":                     e.seal("not a payload"),
		"payload version 2":            withPayload(func(p *logical.TicketPayload) { p.V = 2 }),
		"bound to a key":               withPayload(func(p *logical.TicketPayload) { p.Cnf = json.RawMessage(`{"jkt":"x"}`) }),
		"no alias":                     withPayload(func(p *logical.TicketPayload) { p.Alias = "" }),
		"unknown kind":                 withPayload(func(p *logical.TicketPayload) { p.Kind = "robot" }),
		"facts not an object":          withPayload(func(p *logical.TicketPayload) { p.Facts = json.RawMessage(`["x"]`) }),
		"facts null":                   withPayload(func(p *logical.TicketPayload) { p.Facts = json.RawMessage(`null`) }),
		"expires before issue":         withPayload(func(p *logical.TicketPayload) { p.ExpiresAt = p.IssuedAt }),
		"expired": withPayload(func(p *logical.TicketPayload) {
			p.IssuedAt, p.ExpiresAt = time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
		}),
		"unknown mount":              withPayload(func(p *logical.TicketPayload) { p.MountAccessor = "auth_ticketissuer_00000000" }),
		"accessor a strict prefix":   withPayload(func(p *logical.TicketPayload) { p.MountAccessor = e.mount.Accessor[:len(e.mount.Accessor)-2] }),
		"mount in another namespace": withPayload(func(p *logical.TicketPayload) { p.NamespaceID = "other" }),
		"kind the mount does not admit": withPayload(func(p *logical.TicketPayload) {
			p.Kind = logical.EntityKindAgent
		}),
	}
	stub := mountStubAuthMethod(t, e.c, "stub/", "jwt")
	cases["mount publishes no facts"] = withPayload(func(p *logical.TicketPayload) { p.MountAccessor = stub.Accessor })

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.c.LookupToken(e.ctx, value)
			require.Error(t, err)
			assert.ErrorIs(t, err, refusalFor(name))
		})
	}
}

func refusalFor(name string) error {
	if name == "expired" {
		return ErrTokenExpired
	}
	return ErrTokenNotFound
}

// The cached entry must hold the very value presented: a hash prefix match is
// not enough.
func TestTicket_CacheHitComparesValue(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	other, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)

	entry, err := e.c.LookupToken(e.ctx, other)
	require.NoError(t, err)
	entry.ID = ticketIDPrefix + hashTokenID(value)
	e.c.tokenStore.byID.Set(entry.ID, entry, 1)
	e.c.tokenStore.byID.Wait()

	_, err = e.c.LookupToken(e.ctx, value)
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestTicket_KindFlipRefusesLiveTickets(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	_, err := e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)

	n := *e.issuer.mf.Load()
	n.Kind = logical.EntityKindAgent
	e.issuer.mf.Publish(&n)
	_, err = e.c.LookupToken(e.ctx, value)
	assert.ErrorIs(t, err, ErrTokenNotFound, "a cached ticket is refused too")
}

func TestTicket_Namespaces(t *testing.T) {
	e := newTicketEnv(t)
	parent := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), parent))
	child := &namespace.Namespace{Path: "team-a/dev/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), child))
	sibling := &namespace.Namespace{Path: "team-b/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), sibling))
	parentCtx := namespace.ContextWithNamespace(context.Background(), parent)

	b, me := e.mountIssuer(parentCtx, "oidc/")
	value, _ := e.login(parentCtx, b, me, time.Hour)

	for name, ns := range map[string]*namespace.Namespace{"issuing": parent, "child": child} {
		for _, cold := range []bool{false, true} {
			if cold {
				e.flushCache()
			}
			te, err := e.c.LookupToken(namespace.ContextWithNamespace(context.Background(), ns), value)
			require.NoError(t, err, "%s namespace, cold cache %v", name, cold)
			assert.Equal(t, "auth/oidc/", te.Admission.MountPath, "relative to the issuing namespace")
			assert.Equal(t, parent.ID, te.NamespaceID)
		}
	}
	for name, ns := range map[string]*namespace.Namespace{"sibling": sibling, "parent of the issuing namespace": namespace.RootNamespace} {
		_, err := e.c.LookupToken(namespace.ContextWithNamespace(context.Background(), ns), value)
		assert.ErrorIs(t, err, ErrTokenNamespaceMismatch, name)
	}
}

// Disabling the issuing mount refuses its tickets at once, cached or not, and
// a mount enabled again at the same path is a new accessor: they stay refused.
func TestTicket_MountDisableKillsTickets(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	_, err := e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)

	require.NoError(t, e.c.unmount(e.ctx, "oidc/"))
	_, err = e.c.LookupToken(e.ctx, value)
	assert.ErrorIs(t, err, ErrTokenNotFound, "cached")

	_, me := e.mountIssuer(e.ctx, "oidc/")
	assert.NotEqual(t, e.mount.Accessor, me.Accessor)
	for _, cold := range []bool{false, true} {
		if cold {
			e.flushCache()
		}
		_, err = e.c.LookupToken(e.ctx, value)
		assert.ErrorIs(t, err, ErrTokenNotFound, "re-enabled, cold cache %v", cold)
	}
}

func TestTicket_KeyringRotationKeepsTickets(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	_, err := e.c.barrier.Rotate(e.ctx, rand.Reader)
	require.NoError(t, err)
	e.flushCache()
	_, err = e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)

	fresh, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	e.flushCache()
	_, err = e.c.LookupToken(e.ctx, fresh)
	require.NoError(t, err)
}

// No admin path removes a keyring term: a removed term would silently refuse
// every ticket sealed under it.
func TestTicket_NoProductionCallerRemovesKeyringTerms(t *testing.T) {
	root := filepath.Join("..")
	var callers []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == ".git" || name == "e2e" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), ".RemoveKey(") {
			callers = append(callers, path)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, callers)
}

func TestTicket_SealedRefuses(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	atomic.StoreUint32(e.c.sealed, 1)
	defer atomic.StoreUint32(e.c.sealed, 0)
	_, err := e.c.LookupToken(e.ctx, value)
	assert.Error(t, err)
	_, err = e.c.lookupTicket(e.ctx, value)
	assert.Error(t, err)
}

func TestTicket_Metrics(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	before := e.c.tokenStore.GetMetrics()
	_, err := e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)
	e.flushCache()
	_, err = e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)
	after := e.c.tokenStore.GetMetrics()
	assert.Equal(t, before["tokens_resolved"]+2, after["tokens_resolved"])
	assert.Equal(t, before["cache_hits"]+1, after["cache_hits"])
	assert.Equal(t, before["cache_misses"]+1, after["cache_misses"])
}

func TestTicket_EncodeRefusals(t *testing.T) {
	e := newTicketEnv(t)
	entry := &TokenEntry{NamespaceID: e.ns.ID, CreatedAt: time.Now()}
	adm := func(facts map[string]any, alias string) *logical.Admission {
		return &logical.Admission{Facts: selector.NewClaims(facts), Mount: e.issuer.mf, AliasName: alias}
	}
	base := func(a *logical.Admission) *AuthData {
		return &AuthData{Admission: a, MountAccessor: e.mount.Accessor, ExpireAt: time.Now().Add(time.Hour)}
	}

	_, _, err := e.c.encodeTicket(e.ctx, base(adm(map[string]any{}, "a")), entry)
	require.NoError(t, err)

	big := make([]any, 200)
	for i := range big {
		big[i] = "00000000-0000-0000-0000-000000000000"
	}
	_, _, err = e.c.encodeTicket(e.ctx, base(adm(map[string]any{"groups": big}, "a")), entry)
	assert.ErrorIs(t, err, errTicketTooLarge)

	_, _, err = e.c.encodeTicket(e.ctx, base(adm(map[string]any{}, "")), entry)
	assert.ErrorContains(t, err, "alias")

	table := &logical.Admission{Facts: selector.NewTable(), Mount: e.issuer.mf, AliasName: "a"}
	_, _, err = e.c.encodeTicket(e.ctx, base(table), entry)
	assert.ErrorContains(t, err, "claims")

	noExpiry := base(adm(map[string]any{}, "a"))
	noExpiry.ExpireAt = time.Time{}
	_, _, err = e.c.encodeTicket(e.ctx, noExpiry, entry)
	assert.ErrorContains(t, err, "expire")
}

func TestBackendSealer(t *testing.T) {
	e := newTicketEnv(t)
	other, _ := e.mountIssuer(e.ctx, "oidc-b/")
	a, b := e.issuer.sealer, other.sealer
	require.NotNil(t, a)
	require.NotNil(t, b)

	sealed, err := a.Seal(e.ctx, "oidc-login-state/v1", []byte("state"))
	require.NoError(t, err)
	plain, err := a.Open(e.ctx, "oidc-login-state/v1", sealed)
	require.NoError(t, err)
	assert.Equal(t, "state", string(plain))

	_, err = b.Open(e.ctx, "oidc-login-state/v1", sealed)
	assert.Error(t, err, "another mount cannot open it")
	_, err = a.Open(e.ctx, "oidc-login-state/v2", sealed)
	assert.Error(t, err, "another purpose cannot open it")
	_, err = e.c.barrier.Decrypt(e.ctx, ticketContext, sealed)
	assert.Error(t, err, "it never opens as a ticket")

	_, err = a.Seal(e.ctx, "", []byte("x"))
	assert.ErrorIs(t, err, errSealerPurpose)
	_, err = a.Open(e.ctx, "", sealed)
	assert.ErrorIs(t, err, errSealerPurpose)

	// Whatever purpose a backend names, the context starts with its own
	// accessor: it never seals a ticket.
	for _, purpose := range []string{"x", "../../ticket-token/v1", "/ticket-token/v1"} {
		forged, err := a.Seal(e.ctx, purpose, []byte(`{"v":1}`))
		require.NoError(t, err)
		_, err = e.c.barrier.Decrypt(e.ctx, ticketContext, forged)
		assert.Error(t, err, purpose)
	}

	v1 := e.sealVersion1("backend/"+e.mount.Accessor+"/oidc-login-state/v1", []byte("state"))
	_, err = a.Open(e.ctx, "oidc-login-state/v1", v1)
	assert.ErrorIs(t, err, errSealedFormat)
	_, err = a.Open(e.ctx, "oidc-login-state/v1", []byte("short"))
	assert.ErrorIs(t, err, errSealedFormat)

	assert.Nil(t, newBackendSealer(e.c, ""), "a mount without an accessor gets no sealer")
}

// ticketHitAllocs is what a cache hit allocates: the value's bytes for the
// hash, the ID, and the entry's copy. Raise it only with a reason.
const ticketHitAllocs = 3

func TestTicket_HitAllocations(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	_, err := e.c.lookupTicket(e.ctx, value)
	require.NoError(t, err)
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := e.c.lookupTicket(e.ctx, value); err != nil {
			t.Fatal(err)
		}
	})
	assert.LessOrEqual(t, allocs, float64(ticketHitAllocs))
}

func BenchmarkTicketLookupHit(b *testing.B) {
	e := newTicketEnv(&testing.T{})
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	_, _ = e.c.lookupTicket(e.ctx, value)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := e.c.lookupTicket(e.ctx, value); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTicketDecode(b *testing.B) {
	e := newTicketEnv(&testing.T{})
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := e.c.ticketEntry(e.ctx, "id", value); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTicketEncode(b *testing.B) {
	e := newTicketEnv(&testing.T{})
	authData := &AuthData{
		Admission: &logical.Admission{
			Facts: selector.NewClaims(ticketClaims(&testing.T{})), Mount: e.issuer.mf, AliasName: "0583-oid",
		},
		MountAccessor: e.mount.Accessor,
		ExpireAt:      time.Now().Add(time.Hour),
	}
	entry := &TokenEntry{NamespaceID: e.ns.ID, CreatedAt: time.Now()}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := e.c.encodeTicket(e.ctx, authData, entry); err != nil {
			b.Fatal(err)
		}
	}
}
