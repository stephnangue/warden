package cred

import (
	"context"
	"fmt"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/role"
)

type Fetcher interface {
	FetchCredential(ctx context.Context) (*Credential, bool, error)
	GetSourceType() string // local, vault, aws, azure, cgp, infisical
}

type CredentialFetcher struct {
	fetcher    Fetcher
	role       *role.Role
	credSource *CredSource
	logger     logger.Logger
}

func NewCredentialFetcher(role *role.Role, credSource *CredSource, logger logger.Logger) (*CredentialFetcher, error) {

	var fetcher Fetcher

	switch credSource.Type {
	case "local":
		fetcher = NewLocalFetcher(role)
	case "vault":
		newFetcher, err := NewVaultFetcher(credSource, role, logger)
		if err != nil {
			return nil, err
		}
		fetcher = newFetcher
	default:
		return nil, fmt.Errorf("unkown credential source type : %s", credSource.Type)
	}

	return &CredentialFetcher{
		fetcher: fetcher,
		role: role,
		credSource: credSource,
		logger: logger,
	}, nil
}

func (f *CredentialFetcher) FetchCredential(ctx context.Context) (*Credential, bool, error) {
	
	cred, ok, err := f.fetcher.FetchCredential(ctx)

	return cred, ok, err
}