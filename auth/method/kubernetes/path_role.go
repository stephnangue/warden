package kubernetes

import (
	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
)

// pathRoles answers every request under role/ with 410 Gone: auth roles were
// removed, and roles are defined in the namespace and granted by groups.
func pathRoles() []*framework.Path { return helper.RemovedRolePaths() }
