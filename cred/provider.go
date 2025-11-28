package cred

import (
	"context"
	"fmt"
	"sync"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"
	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/logger"
	"golang.org/x/sync/singleflight"
)

type CredentialProvider struct {
	log         logger.Logger
	cache       *ristretto.Cache[string, *Credential] // key: tokenId -> value: Credential
	fetchers    sync.Map                              // key: roleName -> value: *CredentialFetcher
	roles       *authorize.RoleRegistry
	credSources *CredSourceRegistry
	group       singleflight.Group
}

// NewCredentialProvider creates a new credential provider with caching
func NewCredentialProvider(
	roles *authorize.RoleRegistry,
	credSources *CredSourceRegistry,
	logger logger.Logger) (*CredentialProvider, error) {

	cp := &CredentialProvider{
		log:         logger,
		roles:       roles,
		credSources: credSources,
	}

	cache, err := ristretto.NewCache(&ristretto.Config[string, *Credential]{
		NumCounters: 100000,
		MaxCost:     1_000_000,
		BufferItems: 64,
		OnEvict:     cp.onEvict,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	cp.cache = cache

	return cp, nil
}

// onEvict is called when a credential is evicted from the cache
func (cp *CredentialProvider) onEvict(item *ristretto.Item[*Credential]) {

	cp.log.Debug("credential evicted from cache",
		logger.String("token_id", item.Value.TokenID),
		logger.String("reason", "ttl_expired_or_capacity"),
	)

	// Perform any cleanup if needed
	// For example, if credentials have lease IDs that need to be revoked
	if item.Value != nil && item.Value.LeaseID != "" {
		cp.log.Debug("credential with lease evicted",
			logger.String("token_id", item.Value.TokenID),
			logger.String("lease_id", item.Value.LeaseID),
		)
		// TODO: Add lease revocation logic here if needed
		// cp.revokeLeaseAsync(item.Value.LeaseID)
	}
}

// GetCredentials retrieves credentials for a specific tokenId and role with caching;
// the tokenTTL is the life time of the token whose id is tokenId;
// it determines how long the credential should be cached.
// When the credential also has a ttl (dynamic credential), the cache duration is the minimum
// value between the token_ttl and the 80% of the credential_ttl
func (cp *CredentialProvider) GetCredentials(ctx context.Context, tokenId, roleName string, tokenTTL time.Duration) (*Credential, error) {
	// Check cache first
	if cred, found := cp.cache.Get(tokenId); found {
		cp.log.Debug("using cached credentials",
			logger.String("token_id", tokenId),
			logger.String("request_id", middleware.GetReqID(ctx)),
		)
		return cred, nil
	}

	// Use singleflight to ensure only one creation per tokenId
	v, err, _ := cp.group.Do(tokenId, func() (interface{}, error) {
		// Double-check cache in case another goroutine just added it
		if cred, found := cp.cache.Get(tokenId); found {
			cp.log.Debug("using cached credentials",
				logger.String("token_id", tokenId),
				logger.String("request_id", middleware.GetReqID(ctx)),
			)
			return cred, nil
		}

		// Cache miss - fetch credentials
		cp.log.Debug("cache miss, fetching credentials",
			logger.String("token_id", tokenId),
			logger.String("request_id", middleware.GetReqID(ctx)),
		)

		cred, err := cp.fetchCredentials(ctx, roleName)
		if err != nil {
			return nil, err
		}
		cred.TokenID = tokenId

		cacheTtl := tokenTTL
		if cred.LeaseTTL > 0 {
			cacheTtl = min(tokenTTL, cred.LeaseTTL*4/5)
		}
		cp.cache.SetWithTTL(tokenId, cred, 1, cacheTtl)

		// Wait for value to be processed (Ristretto is async)
		cp.cache.Wait()

		cp.log.Debug("cached credentials",
			logger.String("token_id", tokenId),
			logger.String("ttl", cacheTtl.String()),
			logger.String("request_id", middleware.GetReqID(ctx)),
		)

		return cred, nil
	})

	if err != nil {
		return nil, err
	}

	return v.(*Credential), nil
}

func (cp *CredentialProvider) fetchCredentials(ctx context.Context, roleName string) (*Credential, error) {
	// get the CredentialFetcher for the provided roleName and fetch a secret
	if stored, ok := cp.fetchers.Load(roleName); ok {
		fetcher := stored.(*CredentialFetcher)
		cred, found, err := fetcher.FetchCredential(ctx)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("no credential found for the role '%s', ", roleName)
		}
		return cred, nil
	}
	// if the fetcher does not exist create one
	role, ok := cp.roles.GetRole(roleName)
	if !ok {
		return nil, fmt.Errorf("role named '%s' not found", roleName)
	}
	credSource, ok := cp.credSources.GetSource(role.CredSourceName)
	if !ok {
		return nil, fmt.Errorf("credential source named '%s' not found", role.CredSourceName)
	}

	fetcher, err := NewCredentialFetcher(role, credSource, cp.log)
	if err != nil {
		return nil, err
	}

	// store the new fetcher
	cp.fetchers.Store(roleName, fetcher)

	// then use the new fetcher to fetch credential
	cred, found, err := fetcher.FetchCredential(ctx)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("no credential found for the role '%s', ", roleName)
	}
	return cred, nil
}

// Stop gracefully shuts down the cache
func (cp *CredentialProvider) Stop() {
	cp.cache.Close()
	cp.log.Debug("credential provider cache closed")
}
