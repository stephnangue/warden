package spiffe

import (
	"context"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	lgr "github.com/stephnangue/warden/logger"
)

// trustDomainStoragePrefix is the internal storage-key prefix for trust-domain
// entries (namespaced away from role/ and config). It is independent of the API
// route, which is "trust-domain/<name>". Storage is per-mount, so the same
// prefix is reused by every method that embeds a Manager.
const trustDomainStoragePrefix = "spiffe/trust-domain/"

// Manager holds the SPIFFE substrate for one auth mount: the per-trust-domain
// bundle store, the in-memory verification set, and the federation refresh loop.
// An auth backend creates one Manager, splices Paths() into its routes, and
// drives RebuildBundleSet/StartFederationRefresh/Stop from its lifecycle hooks.
type Manager struct {
	storage sdklogical.Storage
	logger  *lgr.GatedLogger

	// set holds the per-trust-domain authorities used to verify SVIDs. It serves
	// both the X.509 and JWT verifiers. Guarded by setMu.
	set   *spiffebundle.Set
	setMu sync.RWMutex

	// Federation refresh loop (active-node only). fedCancel stops the goroutine;
	// the *Interval fields override the package defaults and exist for tests.
	fedCancel      context.CancelFunc
	fedMu          sync.Mutex
	tickInterval   time.Duration
	minRefresh     time.Duration
	defaultRefresh time.Duration
}

// NewManager returns a Manager bound to a mount's storage view and logger.
func NewManager(storage sdklogical.Storage, logger *lgr.GatedLogger) *Manager {
	return &Manager{storage: storage, logger: logger}
}

// --- storage helpers ---

// GetTrustDomain loads a trust-domain entry by name, or nil if absent.
func (m *Manager) GetTrustDomain(ctx context.Context, name string) (*TrustDomain, error) {
	entry, err := m.storage.Get(ctx, trustDomainStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var td TrustDomain
	if err := entry.DecodeJSON(&td); err != nil {
		return nil, err
	}
	return &td, nil
}

// SetTrustDomain persists a trust-domain entry.
func (m *Manager) SetTrustDomain(ctx context.Context, td *TrustDomain) error {
	entry, err := sdklogical.StorageEntryJSON(trustDomainStoragePrefix+td.Name, td)
	if err != nil {
		return err
	}
	return m.storage.Put(ctx, entry)
}

// DeleteTrustDomain removes a trust-domain entry by name.
func (m *Manager) DeleteTrustDomain(ctx context.Context, name string) error {
	return m.storage.Delete(ctx, trustDomainStoragePrefix+name)
}

// ListTrustDomains returns the configured trust-domain names.
func (m *Manager) ListTrustDomains(ctx context.Context) ([]string, error) {
	return m.storage.List(ctx, trustDomainStoragePrefix)
}

func (m *Manager) listTrustDomainEntries(ctx context.Context) ([]*TrustDomain, error) {
	names, err := m.ListTrustDomains(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]*TrustDomain, 0, len(names))
	for _, name := range names {
		td, err := m.GetTrustDomain(ctx, name)
		if err != nil {
			return nil, err
		}
		if td != nil {
			entries = append(entries, td)
		}
	}
	return entries, nil
}

// --- bundle-set helpers ---

// RebuildBundleSet loads every configured trust-domain bundle from storage and
// atomically replaces the in-memory verification set.
func (m *Manager) RebuildBundleSet(ctx context.Context) error {
	entries, err := m.listTrustDomainEntries(ctx)
	if err != nil {
		return err
	}
	set, err := BuildBundleSet(entries)
	if err != nil {
		return err
	}
	m.setMu.Lock()
	m.set = set
	m.setMu.Unlock()
	return nil
}

// SnapshotBundleSet returns the current verification set under a read lock. It
// may be nil if no trust domains have been loaded yet (callers fail closed).
func (m *Manager) SnapshotBundleSet() *spiffebundle.Set {
	m.setMu.RLock()
	defer m.setMu.RUnlock()
	return m.set
}
