package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revisionFixture creates a source and two specs bound to it.
func revisionFixture(t *testing.T) (*CredentialConfigStore, context.Context, *credential.CredSource) {
	t.Helper()
	store, ctx := setupTestCredentialConfigStore(t)

	source := &credential.CredSource{
		Name:   "rev-source",
		Type:   "local",
		Config: credential.NewConfig(map[string]string{"key": "v1"}),
	}
	require.NoError(t, store.CreateSource(ctx, source))
	for _, name := range []string{"rev-a", "rev-b"} {
		require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{Name: name, Type: "vault_token", Source: "rev-source"}))
	}
	return store, ctx, source
}

// A spec's revision keys the credential cache, so every write that can change what
// it mints advances it, and only a write declared not to leaves it.
func TestCredentialConfigStore_SpecRevision(t *testing.T) {
	t.Run("an update advances it", func(t *testing.T) {
		store, ctx, _ := revisionFixture(t)
		before := store.SpecRevision(ctx, "rev-a")
		spec, err := store.GetSpec(ctx, "rev-a")
		require.NoError(t, err)
		require.NoError(t, store.UpdateSpec(ctx, spec))
		assert.Greater(t, store.SpecRevision(ctx, "rev-a"), before)
		assert.Equal(t, uint64(0), store.SpecRevision(ctx, "rev-b"), "another spec is not touched")
	})

	t.Run("the refresh-token write-back leaves it", func(t *testing.T) {
		store, ctx, _ := revisionFixture(t)
		before := store.SpecRevision(ctx, "rev-a")
		spec, err := store.GetSpec(ctx, "rev-a")
		require.NoError(t, err)
		require.NoError(t, store.PersistRotatedSpec(ctx, spec))
		assert.Equal(t, before, store.SpecRevision(ctx, "rev-a"))
	})

	t.Run("delete and create again lands past the old revision", func(t *testing.T) {
		store, ctx, _ := revisionFixture(t)
		before := store.SpecRevision(ctx, "rev-a")
		require.NoError(t, store.DeleteSpec(ctx, "rev-a"))
		require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{Name: "rev-a", Type: "vault_token", Source: "rev-source"}))
		assert.Greater(t, store.SpecRevision(ctx, "rev-a"), before)
	})

	t.Run("an operator source update advances every bound spec", func(t *testing.T) {
		store, ctx, source := revisionFixture(t)
		source.Config = credential.NewConfig(map[string]string{"key": "v2"})
		require.NoError(t, store.UpdateSource(ctx, source))
		assert.Equal(t, uint64(1), store.SpecRevision(ctx, "rev-a"))
		assert.Equal(t, uint64(1), store.SpecRevision(ctx, "rev-b"))
	})

	t.Run("a source update that changes no config leaves them", func(t *testing.T) {
		store, ctx, source := revisionFixture(t)
		require.NoError(t, store.UpdateSource(ctx, source))
		assert.Equal(t, uint64(0), store.SpecRevision(ctx, "rev-a"))
	})

	t.Run("a source rotation leaves them", func(t *testing.T) {
		store, ctx, source := revisionFixture(t)
		source.Config = credential.NewConfig(map[string]string{"key": "v2"})
		require.NoError(t, store.UpdateSource(ctx, source, UpdateSourceOptions{PreservesMintedOutput: true}))
		assert.Equal(t, uint64(0), store.SpecRevision(ctx, "rev-a"))
	})

	t.Run("no namespace reads as zero", func(t *testing.T) {
		store, _, _ := revisionFixture(t)
		assert.Equal(t, uint64(0), store.SpecRevision(context.Background(), "rev-a"))
	})
}

// A spec that mints from another through credential chaining changes with it, so
// an edit to the referenced spec, or to the source it is bound to, re-keys the
// consumer too. The consumer is written straight to storage: what is under test is
// the re-keying, not the create-time chaining rules.
func TestCredentialConfigStore_SpecRevision_ReKeysChainedConsumers(t *testing.T) {
	store, ctx, source := revisionFixture(t)
	ns, err := store.getNamespaceFromContext(ctx)
	require.NoError(t, err)
	require.NoError(t, store.persistSpec(ns.UUID, &credential.CredSpec{
		Name: "consumer", Type: "vault_token", Source: "rev-source",
		Config: credential.NewConfig(map[string]string{credential.ConfigSecretSpec: "rev-a"}),
	}))

	spec, err := store.GetSpec(ctx, "rev-a")
	require.NoError(t, err)
	require.NoError(t, store.UpdateSpec(ctx, spec))
	assert.Equal(t, uint64(1), store.SpecRevision(ctx, "consumer"), "an edit to the referenced spec re-keys its consumer")
	assert.Equal(t, uint64(0), store.SpecRevision(ctx, "rev-b"))

	require.NoError(t, store.PersistRotatedSpec(ctx, spec))
	assert.Equal(t, uint64(1), store.SpecRevision(ctx, "consumer"), "a write that preserves the output does not")

	source.Config = credential.NewConfig(map[string]string{"key": "v2"})
	require.NoError(t, store.UpdateSource(ctx, source))
	// consumer is both bound to the source and a consumer of rev-a; either re-keys it.
	assert.GreaterOrEqual(t, store.SpecRevision(ctx, "consumer"), uint64(2), "an edit to the referenced spec's source re-keys its consumer")
}

func TestChainGraph_ConsumersAndReferrers(t *testing.T) {
	spec := func(name, source, ref string) *credential.CredSpec {
		return &credential.CredSpec{Name: name, Source: source,
			Config: credential.NewConfig(map[string]string{credential.ConfigSecretSpec: ref})}
	}
	source := func(name, ref string) *credential.CredSource {
		return &credential.CredSource{Name: name, Config: credential.NewConfig(map[string]string{credential.ConfigSecretSpec: ref})}
	}
	specs := []*credential.CredSpec{
		spec("secret", "plain", ""),
		spec("own-ref", "plain", "secret"),
		spec("via-source", "chained", ""),
		spec("overrides-source", "chained", "other"),
		spec("unrelated", "plain", ""),
	}
	g := chainGraph{specs: specs, sources: []*credential.CredSource{source("plain", ""), source("chained", "secret")}}

	assert.ElementsMatch(t, []string{"own-ref", "via-source"}, g.consumers([]string{"secret"}))
	assert.Empty(t, g.consumers([]string{"unrelated"}))
	assert.Empty(t, g.consumers(nil))
	assert.ElementsMatch(t, []string{"source/chained", "spec/own-ref"}, g.referrers("secret"))
}

// The bound specs are the ones a source update re-keys, so an update whose
// listing of them fails is refused rather than leaving them on the old config.
func TestCredentialConfigStore_UpdateSource_FailsWhenBoundSpecsCannotBeListed(t *testing.T) {
	store, ctx, source := revisionFixture(t)
	store.storage = &failingSpecList{Storage: store.storage}

	source.Config = credential.NewConfig(map[string]string{"key": "v2"})
	err := store.UpdateSource(ctx, source)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bound to source")
}

// failingSpecList fails every listing of stored specs.
type failingSpecList struct {
	sdklogical.Storage
}

func (f *failingSpecList) List(ctx context.Context, prefix string) ([]string, error) {
	if strings.Contains(prefix, credSpecPrefix) {
		return nil, errors.New("storage unavailable")
	}
	return f.Storage.List(ctx, prefix)
}

// SpecRevision is on every gateway request's path.
func BenchmarkCredentialConfigStore_SpecRevision(b *testing.B) {
	store := &CredentialConfigStore{}
	ctx := createTestNamespaceContext("ns-bench")
	store.bumpSpecRevision("ns-bench", "spec")

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = store.SpecRevision(ctx, "spec")
		}
	})
}
