package jwt

import (
	"errors"

	"github.com/stephnangue/warden/api"
)

// DefaultMountPath specifies the default mount path for the JWT
// Authentication Method.
const DefaultMountPath = "jwt"

// ErrNoToken is an error, which is returned when [JWTAuth] is configured
// with an empty token.
var ErrNoToken = errors.New("no token specified")

// ErrInvalidMountPath is an error, which is returned when configuring [JWTAuth]
// to use an invalid mount path for an Authentication Method.
var ErrInvalidMountPath = errors.New("invalid auth method mount path specified")

// ErrNoRoleName is an error, which is returned when no role name was specified
// when creating a [JWTAuth].
var ErrNoRoleName = errors.New("no role name specified")

type JWTAuth struct {
	// roleName specifies the name of the role to use.
	roleName string

	// mountPath specifies the mount path for the JWT Authentication Method.
	mountPath string

	// token specifies the JWT token which will be used for authenticating
	// against the OpenBao Authentication Method endpoint.
	token string

	// tokenPath specifies a path from which to read the JWT token.
	tokenPath string
}

var _ api.AuthMethod = &JWTAuth{}