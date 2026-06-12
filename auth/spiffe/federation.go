package spiffe

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	lgr "github.com/stephnangue/warden/logger"
)

// Federation refresh-loop tunables. The per-Manager fields (tickInterval,
// minRefresh, defaultRefresh) override these and exist for tests.
const (
	federationTickInterval   = time.Minute     // how often the loop wakes to check due domains
	federationMinRefresh     = time.Minute     // floor for a domain's refresh interval
	federationMaxRefresh     = 24 * time.Hour  // cap for a domain's refresh interval
	federationDefaultRefresh = 5 * time.Minute // used when a bundle carries no refresh hint
)

// fetchTimeout bounds a single bundle-endpoint fetch.
const fetchTimeout = 30 * time.Second

// fetchFederatedBundle retrieves a federated trust domain's bundle from its
// endpoint per the configured profile:
//   - https_web:    endpoint TLS validated via Web PKI (custom roots or system).
//   - https_spiffe: endpoint authenticated by its SVID against the trust domain's
//     current X.509 authorities (bootstrap, then the last fetched bundle).
func fetchFederatedBundle(ctx context.Context, d *TrustDomain) (*spiffebundle.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(d.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain %q: %w", d.Name, err)
	}

	var opt federation.FetchOption
	switch d.BundleEndpointProfile {
	case bundleProfileWeb:
		roots, err := rootsFromPEM(d.WebPKICAPEM)
		if err != nil {
			return nil, err
		}
		opt = federation.WithWebPKIRoots(roots) // nil => system roots

	case bundleProfileSPIFFE:
		bundle, err := parseTrustDomainBundle(td, d.BundlePEM, d.BundleJSON)
		if err != nil {
			return nil, fmt.Errorf("https_spiffe requires a bundle to authenticate the endpoint: %w", err)
		}
		endpointID, err := spiffeid.FromString(d.EndpointSPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint_spiffe_id %q: %w", d.EndpointSPIFFEID, err)
		}
		// The endpoint authenticates with its X.509-SVID, validated against the
		// trust domain's current X.509 authorities.
		opt = federation.WithSPIFFEAuth(bundle.X509Bundle(), endpointID)

	default:
		return nil, fmt.Errorf("trust domain %q is not federated", d.Name)
	}

	return federation.FetchBundle(ctx, td, d.BundleEndpointURL, opt)
}

// RefreshFederatedTrustDomain fetches d's bundle, and — when it changed — stores
// it as the active bundle and rebuilds the verification set. It is stale-tolerant:
// on fetch error the last-good bundle is kept and the error recorded. The bool
// reports whether the active bundle changed. Must run on the active node (it writes
// storage); d is mutated and persisted in place.
func (m *Manager) RefreshFederatedTrustDomain(ctx context.Context, d *TrustDomain) (bool, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	bundle, err := fetchFederatedBundle(fetchCtx, d)
	if err != nil {
		// Keep the last-good bundle; record the failure (best-effort persist).
		d.LastError = err.Error()
		_ = m.SetTrustDomain(ctx, d)
		return false, err
	}

	// A bundle with no authorities would erase the trust domain's verification
	// material and break the set rebuild for every domain. Reject it (a remote
	// endpoint controls this input) and keep the last-good bundle.
	if bundle.Empty() {
		d.LastError = "fetched bundle has no authorities"
		_ = m.SetTrustDomain(ctx, d)
		return false, fmt.Errorf("fetched bundle for %q has no authorities", d.Name)
	}

	newSeq, hasSeq := bundle.SequenceNumber()
	fetchedBefore := d.LastRefreshUnix != 0
	d.LastRefreshUnix = time.Now().Unix()
	d.LastError = ""

	// De-dup: a prior fetch with the same sequence means no change.
	if fetchedBefore && hasSeq && d.Sequence == newSeq {
		return false, m.SetTrustDomain(ctx, d)
	}

	marshaled, err := bundle.Marshal()
	if err != nil {
		return false, fmt.Errorf("failed to marshal fetched bundle: %w", err)
	}

	// The fetched bundle becomes the single active source.
	d.BundleJSON = string(marshaled)
	d.BundlePEM = ""
	if hasSeq {
		d.Sequence = newSeq
	}

	if err := m.SetTrustDomain(ctx, d); err != nil {
		return false, err
	}
	if err := m.RebuildBundleSet(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) fedTick() time.Duration {
	if m.tickInterval > 0 {
		return m.tickInterval
	}
	return federationTickInterval
}

func (m *Manager) fedMin() time.Duration {
	if m.minRefresh > 0 {
		return m.minRefresh
	}
	return federationMinRefresh
}

func (m *Manager) fedDefault() time.Duration {
	if m.defaultRefresh > 0 {
		return m.defaultRefresh
	}
	return federationDefaultRefresh
}

// refreshInterval returns how long to wait before re-fetching d, honoring the
// bundle's spiffe_refresh_hint when present and clamping to a sane range.
func (m *Manager) refreshInterval(d *TrustDomain) time.Duration {
	interval := m.fedDefault()
	if d.BundleJSON != "" {
		if td, err := spiffeid.TrustDomainFromString(d.Name); err == nil {
			if bundle, err := spiffebundle.Parse(td, []byte(d.BundleJSON)); err == nil {
				if hint, ok := bundle.RefreshHint(); ok && hint > 0 {
					interval = hint
				}
			}
		}
	}
	if min := m.fedMin(); interval < min {
		interval = min
	}
	if interval > federationMaxRefresh {
		interval = federationMaxRefresh
	}
	return interval
}

// StartFederationRefresh launches (or restarts) the per-mount refresh goroutine.
// It must run only on the active node (the caller's ctx is the active context)
// and stops when ctx is cancelled (step-down) or Stop is called (unmount/seal).
func (m *Manager) StartFederationRefresh(ctx context.Context) {
	m.fedMu.Lock()
	defer m.fedMu.Unlock()
	if m.fedCancel != nil {
		m.fedCancel() // stop any prior loop (e.g. re-init on failover)
	}
	loopCtx, cancel := context.WithCancel(ctx)
	m.fedCancel = cancel
	go m.federationRefreshLoop(loopCtx)
}

// Stop stops the refresh goroutine if running. Idempotent.
func (m *Manager) Stop() {
	m.fedMu.Lock()
	defer m.fedMu.Unlock()
	if m.fedCancel != nil {
		m.fedCancel()
		m.fedCancel = nil
	}
}

func (m *Manager) federationRefreshLoop(ctx context.Context) {
	timer := time.NewTimer(jitter(m.fedTick()))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.refreshDueTrustDomains(ctx)
			timer.Reset(jitter(m.fedTick()))
		}
	}
}

// refreshDueTrustDomains refreshes every federated trust domain whose refresh
// interval has elapsed. A never-fetched domain is always due, which primes it.
func (m *Manager) refreshDueTrustDomains(ctx context.Context) {
	entries, err := m.listTrustDomainEntries(ctx)
	if err != nil {
		m.logger.Warn("federation: failed to list trust domains", lgr.Err(err))
		return
	}
	now := time.Now()
	for _, d := range entries {
		if ctx.Err() != nil { // stop promptly on step-down/unmount
			return
		}
		if !d.IsFederated() {
			continue
		}
		if d.LastRefreshUnix != 0 && now.Before(time.Unix(d.LastRefreshUnix, 0).Add(m.refreshInterval(d))) {
			continue
		}
		if _, err := m.RefreshFederatedTrustDomain(ctx, d); err != nil {
			m.logger.Warn("federation: refresh failed", lgr.String("trust_domain", d.Name), lgr.Err(err))
		}
	}
}

// jitter adds up to ~5% positive jitter to spread refreshes across nodes/restarts.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d + time.Duration(rand.Int63n(int64(d)/20+1))
}
