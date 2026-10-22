package core

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingLoginBackend is a JWT auth method whose login holds until the test
// releases it, then fails — as an IdP key fetch would — if its context is done.
type blockingLoginBackend struct {
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	logins      atomic.Int32

	// adm, when set, is the admission every login hands over.
	adm *logical.Admission
}

// open releases every login held, once, whether the test or its cleanup calls it.
func (b *blockingLoginBackend) open() { b.releaseOnce.Do(func() { close(b.release) }) }

func (b *blockingLoginBackend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	if req.Path != "login" {
		return nil, nil
	}
	b.logins.Add(1)
	b.entered <- struct{}{}
	<-b.release
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	jwt, _ := req.Data["jwt"].(string)
	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID: "agent-1",
			TokenType:   TypeJWTRole,
			TokenTTL:    time.Hour,
			ClientToken: jwt,
			Admission:   b.adm,
		},
		Data: map[string]any{},
	}, nil
}

func (b *blockingLoginBackend) Cleanup(context.Context) {}
func (b *blockingLoginBackend) Setup(context.Context, *logical.BackendConfig) error {
	return nil
}
func (b *blockingLoginBackend) Initialize(context.Context) error { return nil }
func (b *blockingLoginBackend) Config() map[string]any           { return nil }
func (b *blockingLoginBackend) Type() string                     { return "jwt" }
func (b *blockingLoginBackend) Class() logical.BackendClass      { return logical.ClassAuth }
func (b *blockingLoginBackend) HandleExistenceCheck(context.Context, *logical.Request) (bool, bool, error) {
	return false, false, nil
}
func (b *blockingLoginBackend) SpecialPaths() *logical.Paths {
	return &logical.Paths{Unauthenticated: []string{"login"}}
}
func (b *blockingLoginBackend) ExtractTokens(*http.Request, bool) (string, string) { return "", "" }

// mountBlockingLogin mounts a blockingLoginBackend at auth/<mountPath> in the root
// namespace, as mountStubAuthMethod does with no backend.
func mountBlockingLogin(t *testing.T, c *Core, mountPath string) *blockingLoginBackend {
	t.Helper()
	backend := &blockingLoginBackend{entered: make(chan struct{}, 4), release: make(chan struct{})}
	t.Cleanup(backend.open)

	accessor, err := c.generateMountAccessor("jwt")
	require.NoError(t, err)
	backendUUID, err := uuid.GenerateUUID()
	require.NoError(t, err)
	mountUUID, err := uuid.GenerateUUID()
	require.NoError(t, err)
	entry := &MountEntry{
		Class:            mountClassAuth,
		Path:             mountPath,
		Type:             "jwt",
		UUID:             mountUUID,
		Accessor:         accessor,
		BackendAwareUUID: backendUUID,
		NamespaceID:      namespace.RootNamespace.ID,
		namespace:        namespace.RootNamespace,
	}
	view := NewBarrierView(c.barrier, "auth/"+entry.UUID+"/")
	require.NoError(t, c.router.Mount(authRoutePrefix+mountPath, backend, entry, view))
	c.authLock.Lock()
	c.auth.Entries = append(c.auth.Entries, entry)
	c.authLock.Unlock()
	return backend
}

// receiveWithin waits for ch, failing instead of hanging when a caller that should have
// returned is still stuck.
func receiveWithin[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

type resolved struct {
	te  *TokenEntry
	err error
}

func resolveAsync(core *Core, ctx context.Context, jwt string) <-chan resolved {
	out := make(chan resolved, 1)
	go func() {
		te, _, err := core.resolveTransparentIdentity(ctx, &logical.Request{ClientToken: jwt}, "auth/jwt-block/", "")
		out <- resolved{te, err}
	}()
	return out
}

// Every request presenting one credential and role shares one implicit login, so
// the request that started it going away must not fail the rest: it stops waiting,
// the login completes, and the others get the token it created.
func TestResolveTransparentIdentity_LeaderCancellationDoesNotFailFollowers(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	backend := mountBlockingLogin(t, core, "jwt-block/")
	jwt := mintK8sJWT(`{"sub":"agent-1"}`)

	leaderCtx, cancelLeader := context.WithCancel(ctx)
	leader := resolveAsync(core, leaderCtx, jwt)
	receiveWithin(t, backend.entered, "the leader's login to start")

	follower := resolveAsync(core, ctx, jwt)
	time.Sleep(50 * time.Millisecond) // let the follower join the login in flight

	cancelLeader()
	assert.ErrorIs(t, receiveWithin(t, leader, "the cancelled leader to return").err, context.Canceled)
	backend.open()

	got := receiveWithin(t, follower, "the follower's token")
	require.NoError(t, got.err)
	require.NotNil(t, got.te)
	assert.Equal(t, "agent-1", got.te.PrincipalID)
	assert.EqualValues(t, 1, backend.logins.Load(), "one login served both")
}

// A request that gives up stops waiting at once; the login it joined carries on.
func TestResolveTransparentIdentity_FollowerCancellationReturnsPromptly(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	backend := mountBlockingLogin(t, core, "jwt-block/")
	jwt := mintK8sJWT(`{"sub":"agent-1"}`)

	leader := resolveAsync(core, ctx, jwt)
	receiveWithin(t, backend.entered, "the leader's login to start")

	followerCtx, cancelFollower := context.WithCancel(ctx)
	cancelFollower()
	assert.ErrorIs(t, receiveWithin(t, resolveAsync(core, followerCtx, jwt), "the cancelled follower to return").err, context.Canceled)

	backend.open()
	got := receiveWithin(t, leader, "the leader's token")
	require.NoError(t, got.err)
	assert.EqualValues(t, 1, backend.logins.Load())
}
