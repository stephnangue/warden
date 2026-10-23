package core

import (
	"context"
	"fmt"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/logger"
)

// detectAuthRoleLeftovers lists, once per auth mount, the storage prefix its
// auth roles were kept under, and records how many each still holds, so
// sys/auth can say so (authRoleLeftoverWarning). A mount that holds some is
// logged once. Nothing under the prefix is read or changed: the roles stay as
// they were, so the previous binary still finds them after a rollback.
//
// It runs at unseal on the active node, after the auth table is loaded. A
// mount whose prefix cannot be listed is logged and skipped: the warning is
// advice, and an unseal never fails for it.
func (c *Core) detectAuthRoleLeftovers(ctx context.Context) {
	c.authLock.RLock()
	var entries []*MountEntry
	if c.auth != nil {
		entries = append(entries, c.auth.Entries...)
	}
	c.authLock.RUnlock()

	found := make(map[string]int)
	for _, entry := range entries {
		view, err := c.mountEntryView(entry)
		if err != nil {
			continue
		}
		keys, err := view.List(ctx, authhelper.RolePrefix)
		if err != nil {
			c.logger.Warn("could not check an auth mount for removed auth roles",
				logger.String("path", authRoutePrefix+entry.Path),
				logger.String("namespace", entry.Namespace().Path),
				logger.Err(err))
			continue
		}
		if len(keys) == 0 {
			continue
		}
		found[entry.UUID] = len(keys)
		c.logger.Warn(authRoleLeftoverWarning(entry.Path, len(keys)),
			logger.String("namespace", entry.Namespace().Path))
	}
	c.authRoleLeftovers.Store(&found)
}

// authRoleLeftoverCount returns how many auth roles the storage of the auth mount
// with UUID uuid still holds, as detectAuthRoleLeftovers counted them.
func (c *Core) authRoleLeftoverCount(uuid string) int {
	if m := c.authRoleLeftovers.Load(); m != nil {
		return (*m)[uuid]
	}
	return 0
}

// authRoleLeftoverWarning is the warning for an auth mount at path (relative
// to its namespace, without the auth/ prefix) whose storage still holds n
// auth roles.
func authRoleLeftoverWarning(path string, n int) string {
	return fmt.Sprintf("%s%s: %d auth roles are no longer used; recreate them as roles and groups (see upgrade notes)",
		authRoutePrefix, path, n)
}
