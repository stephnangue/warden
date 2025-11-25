package cred

import (
	"context"
	"errors"
	"maps"

	"github.com/stephnangue/warden/role"
)

// LocalFetcher fetches credentials from the local credential source.
// With the local credential source the credential is stored directly inside the role
type LocalFetcher struct {
	role *role.Role
}

func NewLocalFetcher(role *role.Role) *LocalFetcher {
	return &LocalFetcher{
		role: role,
	}
}

func (f *LocalFetcher) GetSourceType() string {
	return "local"
}

func (f *LocalFetcher) FetchCredential(ctx context.Context) (*Credential, bool, error) {
	if f.role.Type == "static_database_userpass" {
		cred := Credential{
			Type: DATABASE_USERPASS,
			Data: make(map[string]string),
		}
		maps.Copy(cred.Data, f.role.CredConfig)
		return &cred, true, nil
	} 
	return nil, false, errors.New("unsupported role type")
}