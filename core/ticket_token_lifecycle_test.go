package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// An authentic ticket presented after its expiry is refused and never cached:
// replaying old tickets cannot fill the cache.
func TestTicket_ExpiredNeverCached(t *testing.T) {
	e := newTicketEnv(t)
	p := e.payload()
	p.IssuedAt, p.ExpiresAt = time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	value := e.seal(p)

	before := e.c.tokenStore.GetMetrics()
	_, err := e.c.LookupToken(e.ctx, value)
	assert.ErrorIs(t, err, ErrTokenExpired)
	e.c.tokenStore.byID.Wait()
	_, cached := e.c.tokenStore.byID.Get(tokenID(ticketIDPrefix, value))
	assert.False(t, cached)
	assert.Equal(t, before["tokens_expired"]+1, e.c.tokenStore.GetMetrics()["tokens_expired"])
}

func TestTicket_NamespaceMismatchMetric(t *testing.T) {
	e := newTicketEnv(t)
	sibling := &namespace.Namespace{Path: "team-b/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), sibling))
	team := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), team))
	teamCtx := namespace.ContextWithNamespace(context.Background(), team)
	b, me := e.mountIssuer(teamCtx, "oidc/")
	value, _ := e.login(teamCtx, b, me, time.Hour)

	siblingCtx := namespace.ContextWithNamespace(context.Background(), sibling)
	for _, cold := range []bool{true, false} {
		if cold {
			e.flushCache()
		}
		before := e.c.tokenStore.GetMetrics()
		_, err := e.c.LookupToken(siblingCtx, value)
		assert.ErrorIs(t, err, ErrTokenNamespaceMismatch, "cold cache %v", cold)
		assert.Equal(t, before["namespace_mismatches"]+1, e.c.tokenStore.GetMetrics()["namespace_mismatches"])
	}
}

func TestTicket_ResolveToken(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	principal, err := e.c.tokenStore.ResolveToken(e.ctx, value)
	require.NoError(t, err)
	assert.Equal(t, "0583-oid", principal)

	_, err = e.c.tokenStore.ResolveToken(e.ctx, value+"x")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

// The expiry timer's revocation of a ticket, which has no accessor, drops the
// cache entry and nothing else; the value still decodes until its expiry.
func TestTicket_RevokeByExpiration(t *testing.T) {
	e := newTicketEnv(t)
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	id := tokenID(ticketIDPrefix, value)
	require.NoError(t, e.c.tokenStore.RevokeByExpiration(id))
	_, cached := e.c.tokenStore.byID.Get(id)
	assert.False(t, cached)
	_, err := e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)
}

// A login writes no expiration record either: the expiry timer is in memory.
func TestTicket_NoPersistedExpiration(t *testing.T) {
	e := newTicketEnv(t)
	e.login(e.ctx, e.issuer, e.mount, time.Hour)
	keys, err := e.c.barrier.List(e.ctx, expirationStoragePath)
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// The audit's token_accessor: an identity token keeps it, a ticket has none.
func TestTicket_AuditTokenAccessor(t *testing.T) {
	e := newTicketEnv(t)
	identity, err := e.c.tokenStore.GenerateToken(e.ctx, TypeIdentityToken, &AuthData{
		TokenValue: "cred", MountAccessor: e.mount.Accessor, ExpireAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	require.NotEmpty(t, identity.Accessor)
	assert.Equal(t, identity.Accessor, buildAuditAuth(nil, identity).TokenAccessor)

	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)
	ticket, err := e.c.LookupToken(e.ctx, value)
	require.NoError(t, err)
	a := buildAuditAuth(nil, ticket)
	assert.Empty(t, a.TokenAccessor)
	assert.Equal(t, logical.TokenTypeTicket, a.TokenType)
}
