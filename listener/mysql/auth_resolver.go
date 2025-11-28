package mysql

import (
	"context"

	"github.com/stephnangue/warden/auth/token"
)

type AuthResolver struct {
	tokenStore token.TokenAccess
}

func NewAuthResolver(tokenStore token.TokenAccess) *AuthResolver {
	return &AuthResolver{
		tokenStore: tokenStore,
	}
}

func (r *AuthResolver) Resolve(tokenAccessor string, reqContext map[string]string) (string, string, bool, error) {

	id, role, err := r.tokenStore.ResolveToken(context.Background(), tokenAccessor, reqContext)

	if err != nil {
		return "", "", false, err
	}

	return id, role, true, nil
}
