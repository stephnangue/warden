package core

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the store's lock discipline. Every mutator used to take a read
// lock, so no read-modify-write was atomic: two creates of one name could both pass
// their existence check and both persist, and a delete could pass its reference scan
// while a spec binding to that source was being written.

// TestCredentialConfigStore_ConcurrentDuplicateCreateSourceHasOneWinner asserts that
// concurrent creates of the same name produce exactly one source and one success.
//
// Under the read lock both callers ran the existence check, both saw nothing, and
// both persisted — last write won, the other's config was silently lost, and
// ErrSourceAlreadyExists never fired.
func TestCredentialConfigStore_ConcurrentDuplicateCreateSourceHasOneWinner(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = store.CreateSource(ctx, &credential.CredSource{
				Name: "contended",
				Type: "local",
			})
		}(i)
	}
	wg.Wait()

	var created int
	for i, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrSourceAlreadyExists):
		default:
			t.Fatalf("caller %d failed unexpectedly: %v", i, err)
		}
	}
	assert.Equal(t, 1, created, "exactly one concurrent create may succeed")

	sources, err := store.ListSources(ctx)
	require.NoError(t, err)
	var matches int
	for _, src := range sources {
		if src.Name == "contended" {
			matches++
		}
	}
	assert.Equal(t, 1, matches, "the namespace must hold exactly one source of this name")
}

// TestCredentialConfigStore_ConcurrentDuplicateCreateSpecHasOneWinner is the spec
// half of the same property.
func TestCredentialConfigStore_ConcurrentDuplicateCreateSpecHasOneWinner(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = store.CreateSpec(ctx, &credential.CredSpec{
				Name:   "contended",
				Type:   "vault_token",
				Source: "src",
				MinTTL: time.Hour,
				MaxTTL: 24 * time.Hour,
			})
		}(i)
	}
	wg.Wait()

	var created int
	for i, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrSpecAlreadyExists):
		default:
			t.Fatalf("caller %d failed unexpectedly: %v", i, err)
		}
	}
	assert.Equal(t, 1, created, "exactly one concurrent create may succeed")
}

// TestCredentialConfigStore_DeleteMissingReportsNotFound covers the delete half of
// the not-found conflation: storage Delete is idempotent and nothing checked first,
// so removing something absent reported success and the handlers' not-found branches
// were unreachable.
func TestCredentialConfigStore_DeleteMissingReportsNotFound(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	err := store.DeleteSpec(ctx, "never-existed")
	assert.ErrorIs(t, err, ErrSpecNotFound)

	err = store.DeleteSource(ctx, "never-existed")
	assert.ErrorIs(t, err, ErrSourceNotFound)
}

// TestCredentialConfigStore_UpdateSourceWithoutCredentialManagerDoesNotPanic covers
// the unguarded dereference on the update path. The delete path guarded it; this one
// did not, and teardown nils the manager while requests can still be in flight.
func TestCredentialConfigStore_UpdateSourceWithoutCredentialManagerDoesNotPanic(t *testing.T) {
	// This harness deliberately builds a Core with no credential manager.
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name:   "src",
		Type:   "local",
		Config: map[string]string{"key": "before"},
	}))

	// A config change is what triggers the driver teardown, so this is the path
	// that used to dereference the nil manager.
	require.NotPanics(t, func() {
		err := store.UpdateSource(ctx, &credential.CredSource{
			Name:   "src",
			Type:   "local",
			Config: map[string]string{"key": "after"},
		})
		require.NoError(t, err)
	})

	updated, err := store.GetSource(ctx, "src")
	require.NoError(t, err)
	assert.Equal(t, "after", updated.Config["key"])
}

// TestCredentialConfigStore_MutatorsDoNotDeadlockAgainstUnload is the regression test
// for the recursive read lock.
//
// Mutators held a read lock and then re-entered it through validation, which calls
// the store's own getters. Go's RWMutex blocks a new reader once a writer is waiting,
// so a seal or step-down — UnloadFromCache takes the write lock — landing between the
// outer and inner acquisition wedged both the request and the teardown permanently.
// Validation now runs before the lock is taken.
//
// The watchdog is the assertion: on the previous code this hangs.
func TestCredentialConfigStore_MutatorsDoNotDeadlockAgainstUnload(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))

	done := make(chan struct{})
	go func() {
		defer close(done)

		var wg sync.WaitGroup
		stop := make(chan struct{})

		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// Errors are irrelevant here; reaching the end without wedging is
				// the whole point.
				_ = store.CreateSpec(ctx, &credential.CredSpec{
					Name:   "spec",
					Type:   "vault_token",
					Source: "src",
					MinTTL: time.Hour,
					MaxTTL: 24 * time.Hour,
				})
				_ = store.DeleteSpec(ctx, "spec")
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				select {
				case <-stop:
					return
				default:
				}
				store.UnloadFromCache()
			}
		}()

		wg.Wait()
		close(stop)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock: mutators and cache teardown wedged against each other")
	}
}

// TestCredentialConfigStore_CreateSpecRacingDeleteSourceLeavesNoDanglingSpec asserts
// the two cannot both succeed.
//
// Validating outside the lock reopens this window — the source is confirmed to exist
// and may be deleted before the spec is written — which is why the commit phase
// re-checks the binding rather than trusting what validation saw.
func TestCredentialConfigStore_CreateSpecRacingDeleteSourceLeavesNoDanglingSpec(t *testing.T) {
	for attempt := 0; attempt < 40; attempt++ {
		store, ctx := setupTestCredentialConfigStore(t)
		require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))

		var wg sync.WaitGroup
		var createErr, deleteErr error

		wg.Add(2)
		go func() {
			defer wg.Done()
			createErr = store.CreateSpec(ctx, &credential.CredSpec{
				Name:   "spec",
				Type:   "vault_token",
				Source: "src",
				MinTTL: time.Hour,
				MaxTTL: 24 * time.Hour,
			})
		}()
		go func() {
			defer wg.Done()
			deleteErr = store.DeleteSource(ctx, "src")
		}()
		wg.Wait()

		// If the spec was written, the source it names must still be there.
		if createErr == nil && deleteErr == nil {
			_, err := store.GetSource(ctx, "src")
			require.NoError(t, err,
				"attempt %d: spec was created bound to a source that was deleted", attempt)
		}
	}
}
