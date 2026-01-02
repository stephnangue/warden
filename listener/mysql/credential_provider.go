package mysql

import (
	"fmt"

	"github.com/stephnangue/warden/logical"
)

type CredentialProvider struct {
	tokenStore logical.TokenAccess
}

func NewCredentialProvider(tokenStore logical.TokenAccess) *CredentialProvider {
	return &CredentialProvider{
		tokenStore: tokenStore,
	}
}

// CheckUsername checks if the a user with username exists
// in our case the user name is the token accessor
// go-mysql library uses this method internaly during mysql handshake
func (p *CredentialProvider) CheckUsername(username string) (bool, error) {
	token := p.tokenStore.GetToken(username)
	if token != nil {
		return true, nil
	}
	return false, nil
}

// GetCredential returns the password associated with the username
// go-mysql library uses this method internaly during mysql handshake
func (p *CredentialProvider) GetCredential(username string) (string, bool, error) {
	token := p.tokenStore.GetToken(username)
	if token != nil {
		return token.Data["password"], true, nil
	}
	return "", false, fmt.Errorf("permission denied")
}
