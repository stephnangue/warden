package core

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// referencedConfig is a spec config a secret_spec may name: minted as the
// session-pinned caller.
func referencedConfig() credential.Config {
	return credential.NewConfig(map[string]string{
		credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
		"assertion_audience":                "https://store.example",
	})
}

// referencedFixture stores a spec "secret" on refSource and a consumer naming it as
// its secret_spec, plus a second referenceable spec "elsewhere" and a source
// "chained-src" whose secret_spec names it. They go straight to storage: what is
// under test is that an edit keeps the chaining rules, not the rules at create.
func referencedFixture(t *testing.T, refSource string) (*CredentialConfigStore, context.Context) {
	t.Helper()
	store, ctx := setupTestCredentialConfigStore(t)
	ns, err := store.getNamespaceFromContext(ctx)
	require.NoError(t, err)

	require.NoError(t, store.persistSource(ns.UUID, &credential.CredSource{Name: "x-src", Type: credential.SourceTypeTokenExchange, Config: credential.NewConfig(nil)}))
	require.NoError(t, store.persistSource(ns.UUID, &credential.CredSource{Name: "y-src", Type: credential.SourceTypeTokenExchange, Config: credential.NewConfig(nil)}))
	require.NoError(t, store.persistSource(ns.UUID, &credential.CredSource{Name: "plain-src", Type: "local", Config: credential.NewConfig(nil)}))
	require.NoError(t, store.persistSource(ns.UUID, &credential.CredSource{Name: "chained-src", Type: credential.SourceTypeTokenExchange,
		Config: credential.NewConfig(map[string]string{credential.ConfigSecretSpec: "elsewhere"})}))

	require.NoError(t, store.persistSpec(ns.UUID, &credential.CredSpec{Name: "elsewhere", Type: "vault_token", Source: "y-src", Config: referencedConfig()}))
	require.NoError(t, store.persistSpec(ns.UUID, &credential.CredSpec{Name: "secret", Type: "vault_token", Source: refSource, Config: referencedConfig()}))
	require.NoError(t, store.persistSpec(ns.UUID, &credential.CredSpec{
		Name: "consumer", Type: "vault_token", Source: "plain-src",
		Config: credential.NewConfig(map[string]string{credential.ConfigSecretSpec: "secret"}),
	}))
	return store, ctx
}

// An edit to a referenced spec that would break the chaining rules is refused,
// naming the consumer, and goes through once the consumer is gone.
func TestCredentialConfigStore_UpdateSpec_KeepsAReferencedSpecReferenceable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string // where the referenced spec sits
		edit   func(*credential.CredSpec)
		reason string
	}{
		{"subject none", "x-src", func(s *credential.CredSpec) {
			s.Config = s.Config.With(credential.ConfigSubjectTokenSource, "none")
		}, "subject_token_source"},
		{"user identity", "x-src", func(s *credential.CredSpec) {
			s.Config = s.Config.With(credential.ConfigSubjectTokenSource, credential.SourceUserIdentity)
		}, "subject_token_source"},
		// A token_exchange spec may not set its own secret_spec at all, so this one
		// sits on a source that lets it; and a chained spec may not keep a subject,
		// so becoming one drops it.
		{"its own secret_spec", "plain-src", func(s *credential.CredSpec) {
			s.Config = credential.NewConfig(map[string]string{credential.ConfigSecretSpec: "elsewhere"})
		}, "must not itself set secret_spec"},
		{"a source that chains", "x-src", func(s *credential.CredSpec) {
			s.Source = "chained-src"
		}, "source must not set secret_spec"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, ctx := referencedFixture(t, tc.source)
			spec, err := store.GetSpec(ctx, "secret")
			require.NoError(t, err)
			edited := *spec
			tc.edit(&edited)

			err = store.UpdateSpec(ctx, &edited, UpdateSpecOptions{SkipVerification: true})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "is the secret_spec of spec/consumer")
			assert.Contains(t, err.Error(), tc.reason)

			require.NoError(t, store.DeleteSpec(ctx, "consumer"))
			require.NoError(t, store.UpdateSpec(ctx, &edited, UpdateSpecOptions{SkipVerification: true}),
				"with no consumer the edit is the spec's own business")
		})
	}
}

// The built-in source is never stored; a referenced spec on it is checked without
// tripping over that.
func TestCredentialConfigStore_UpdateSpec_ReferencedSpecOnTheBuiltinSource(t *testing.T) {
	store, ctx := referencedFixture(t, builtinLocalSourceName)
	spec, err := store.GetSpec(ctx, "secret")
	require.NoError(t, err)
	edited := *spec
	edited.Config = edited.Config.With(credential.ConfigSubjectTokenSource, credential.SourceAgentIdentity)
	require.NoError(t, store.UpdateSpec(ctx, &edited, UpdateSpecOptions{SkipVerification: true}))
}

// A source that gains a secret_spec breaks the one-hop rule for a referenced spec
// on it, so it is refused while one is there.
func TestCredentialConfigStore_UpdateSource_GainingSecretSpecUnderAReferencedSpec(t *testing.T) {
	t.Run("refused while a referenced spec sits on it", func(t *testing.T) {
		store, ctx := referencedFixture(t, "x-src")
		src, err := store.GetSource(ctx, "x-src")
		require.NoError(t, err)
		edited := *src
		edited.Config = edited.Config.With(credential.ConfigSecretSpec, "elsewhere")
		err = store.UpdateSource(ctx, &edited, UpdateSourceOptions{SkipConnectionTest: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `spec "secret" on this source is the secret_spec of spec/consumer`)
	})
	t.Run("allowed when none does", func(t *testing.T) {
		store, ctx := referencedFixture(t, "x-src")
		require.NoError(t, store.DeleteSpec(ctx, "consumer"))
		src, err := store.GetSource(ctx, "x-src")
		require.NoError(t, err)
		edited := *src
		edited.Config = edited.Config.With(credential.ConfigSecretSpec, "elsewhere")
		require.NoError(t, store.UpdateSource(ctx, &edited, UpdateSourceOptions{SkipConnectionTest: true}))
	})
}

// A spec referenced at source level is held to the same rules, and the refusal
// names the source.
func TestCredentialConfigStore_UpdateSpec_NamesASourceLevelReferrer(t *testing.T) {
	store, ctx := referencedFixture(t, "x-src")
	spec, err := store.GetSpec(ctx, "elsewhere")
	require.NoError(t, err)
	edited := *spec
	edited.Config = edited.Config.With(credential.ConfigSubjectTokenSource, "none")

	err = store.UpdateSpec(ctx, &edited, UpdateSpecOptions{SkipVerification: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is the secret_spec of source/chained-src")
}

// A source cannot take its secret_spec from a spec bound to it: the spec would
// chain from itself, and every mint of it would fail.
func TestCredentialConfigStore_UpdateSource_RefusesChainingFromItsOwnSpec(t *testing.T) {
	store, ctx := referencedFixture(t, "x-src")
	require.NoError(t, store.DeleteSpec(ctx, "consumer")) // so only the cycle is in the way
	src, err := store.GetSource(ctx, "x-src")
	require.NoError(t, err)
	edited := *src
	edited.Config = edited.Config.With(credential.ConfigSecretSpec, "secret")

	err = store.UpdateSource(ctx, &edited, UpdateSourceOptions{SkipConnectionTest: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `cannot take its secret_spec from spec "secret", which is bound to it`)
}

// The refresh-token write-back runs on the mint path; it keeps the spec's output
// and its chaining shape, so it lists nothing from storage under the write lock.
// A write that keeps the output but changes the chaining shape still has to check
// the rules, so it does list.
func TestCredentialConfigStore_UpdateSpec_ListsOnlyWhenSomethingFollowsAReference(t *testing.T) {
	store, ctx := referencedFixture(t, "x-src")
	counting := &countingLists{Storage: store.storage}
	store.storage = counting

	spec, err := store.GetSpec(ctx, "secret")
	require.NoError(t, err)
	require.NoError(t, store.PersistRotatedSpec(ctx, spec))
	assert.Equal(t, int64(0), counting.lists.Load(), "the write-back lists nothing")

	edited := *spec
	edited.Config = edited.Config.With(credential.ConfigSubjectTokenSource, credential.SourceAgentIdentity)
	require.NoError(t, store.UpdateSpec(ctx, &edited, UpdateSpecOptions{SkipVerification: true, PreservesMintedOutput: true}))
	assert.Positive(t, counting.lists.Load(), "a chaining-shape change checks the rules")
}

// A source rotation write keeps the minted output and follows no reference, so it
// lists the bound specs and nothing else.
func TestCredentialConfigStore_SourceRotationListsOnlyTheBoundSpecs(t *testing.T) {
	store, ctx := referencedFixture(t, "x-src")
	counting := &countingLists{Storage: store.storage}
	store.storage = counting

	src, err := store.GetSource(ctx, "x-src")
	require.NoError(t, err)
	edited := *src
	edited.Config = edited.Config.With("rotated", "yes")
	require.NoError(t, store.UpdateSource(ctx, &edited, UpdateSourceOptions{SkipConnectionTest: true, PreservesMintedOutput: true}))
	assert.Equal(t, int64(0), counting.sourceLists.Load(), "no source listing on a rotation write")
}

// countingLists counts listings of stored specs and sources (lists), and of
// sources alone (sourceLists).
type countingLists struct {
	sdklogical.Storage
	lists       atomic.Int64
	sourceLists atomic.Int64
}

func (c *countingLists) List(ctx context.Context, prefix string) ([]string, error) {
	if strings.Contains(prefix, credSpecPrefix) || strings.Contains(prefix, credSourcePrefix) {
		c.lists.Add(1)
	}
	if strings.Contains(prefix, credSourcePrefix) {
		c.sourceLists.Add(1)
	}
	return c.Storage.List(ctx, prefix)
}
