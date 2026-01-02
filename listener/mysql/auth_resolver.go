package mysql

import (
	"context"

	"github.com/stephnangue/warden/logical"
)

type AuthResolver struct {
	tokenStore logical.TokenAccess
}

func NewAuthResolver(tokenStore logical.TokenAccess) *AuthResolver {
	return &AuthResolver{
		tokenStore: tokenStore,
	}
}

func (r *AuthResolver) Resolve(ctx context.Context, tokenAccessor string) (string, string, bool, error) {

	id, role, err := r.tokenStore.ResolveToken(ctx, tokenAccessor)

	if err != nil {
		return "", "", false, err
	}

	return id, role, true, nil
}
