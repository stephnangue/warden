package server

import "context"

type Resolver interface {
	// Resolve returns the principal_id and the role_name
	Resolve(ctx context.Context, user string) (string, string, bool, error)
}
