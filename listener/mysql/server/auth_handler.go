package server

type Resolver interface {
	// Resolve returns the principal_id and the role_name
	Resolve(user string, reqContext map[string]string) (string, string, bool, error)
}
