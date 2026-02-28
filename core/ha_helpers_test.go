package core

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/require"
)

// createHACore creates and returns a Core configured for HA with the given
// backend and redirect address. The core is not yet initialized or unsealed.
func createHACore(t *testing.T, backend physical.Backend, haBackend physical.HABackend, redirectAddr string) *Core {
	t.Helper()

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	conf := &CoreConfig{
		RawConfig:    &config.Config{},
		Physical:     backend,
		HAPhysical:   haBackend,
		RedirectAddr: redirectAddr,
		StorageType:  "inmem_ha",
		Logger:       log,
		AuditDevices: map[string]audit.Factory{
			"file": &mockAuditFactory{},
		},
	}

	c, err := NewCore(conf)
	require.NoError(t, err)
	return c
}

// initAndUnsealCore initializes and unseals a core with a single unseal key.
// Returns the root token and the seal key (needed to unseal other cores sharing
// the same storage).
func initAndUnsealCore(t *testing.T, c *Core) (rootToken string, sealKey []byte) {
	t.Helper()

	ctx := context.Background()

	result, err := c.Initialize(ctx, &InitParams{
		BarrierConfig: &SealConfig{
			SecretShares:    1,
			SecretThreshold: 1,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.RootToken)
	require.Len(t, result.SecretShares, 1)

	sealKey = result.SecretShares[0]
	unsealWithSealKey(t, c, sealKey)

	return result.RootToken, sealKey
}

// unsealWithSealKey unseals a core using the seal key. It sets the seal key
// on the Shamir wrapper, retrieves the stored barrier key, and unseals.
func unsealWithSealKey(t *testing.T, c *Core, sealKey []byte) {
	t.Helper()
	ctx := context.Background()

	// Set the seal key on the Shamir wrapper so it can decrypt stored keys
	shamirWrapper, err := c.seal.GetShamirWrapper()
	require.NoError(t, err)
	err = shamirWrapper.SetAesGcmKeyBytes(sealKey)
	require.NoError(t, err)

	// Retrieve the barrier key (stored encrypted under the seal key)
	keys, err := c.seal.GetStoredKeys(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	// Unseal the barrier with the actual barrier key
	c.stateLock.Lock()
	err = c.unsealInternal(ctx, keys[0])
	c.stateLock.Unlock()
	require.NoError(t, err)
}

// unsealCore unseals a core that has already been initialized (via shared storage).
func unsealCore(t *testing.T, c *Core, sealKey []byte) {
	t.Helper()
	unsealWithSealKey(t, c, sealKey)
}

// waitForActiveNode waits until one of the cores becomes active, with timeout.
func waitForActiveNode(t *testing.T, cores []*Core, timeout time.Duration) *Core {
	t.Helper()
	deadline := time.After(timeout)
	for {
		for _, c := range cores {
			if !c.Standby() && !c.Sealed() {
				return c
			}
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for an active node")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// waitForStandbyNode waits until one of the cores becomes standby, with timeout.
func waitForStandbyNode(t *testing.T, cores []*Core, timeout time.Duration) *Core {
	t.Helper()
	deadline := time.After(timeout)
	for {
		for _, c := range cores {
			if c.Standby() && !c.Sealed() {
				return c
			}
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for a standby node")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// newInmemHABackends creates an inmem_ha backend and returns the physical
// storage backend and HA backend separately. The physical backend is the
// underlying TransactionalInmemBackend (needed for barrier transactions),
// while the HA backend provides lock-based leader election.
func newInmemHABackends(t *testing.T) (physical.Backend, physical.HABackend) {
	t.Helper()
	backend, err := inmem.NewInmemHA(nil, nil)
	require.NoError(t, err)

	haBackend := backend.(physical.HABackend)

	// InmemHABackend embeds physical.Backend (interface), which hides the
	// TransactionalBackend methods (BeginTx, BeginReadOnlyTx) from the
	// underlying TransactionalInmemBackend. Extract the embedded backend
	// so the barrier can create transactions.
	physBackend := backend.(*inmem.InmemHABackend).Backend

	return physBackend, haBackend
}

// setupTwoNodeHA is a helper that sets up a 2-node HA cluster and waits for
// one to become active and one to become standby. Returns the active, standby,
// and the unseal key. Both cores share the same backend.
func setupTwoNodeHA(t *testing.T) (active, standby *Core, core1, core2 *Core, unsealKey []byte) {
	t.Helper()

	physBackend, haBackend := newInmemHABackends(t)

	core1 = createHACore(t, physBackend, haBackend, "http://node1:8400")
	core2 = createHACore(t, physBackend, haBackend, "http://node2:8400")

	_, unsealKey = initAndUnsealCore(t, core1)
	unsealCore(t, core2, unsealKey)

	active = waitForActiveNode(t, []*Core{core1, core2}, 5*time.Second)
	standby = waitForStandbyNode(t, []*Core{core1, core2}, 5*time.Second)
	require.True(t, active != standby, "active and standby should be different cores")

	return active, standby, core1, core2, unsealKey
}
