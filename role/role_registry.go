package role

import "sync"

type Role struct {
	Name            string
	Type            string // static_db, vault_db_lease
	CredSourceName  string
	CredConfig      map[string]string
	TargetName      string
}

type RoleRegistry struct {
	roles map[string]*Role
	mu    sync.RWMutex
}

func NewRoleRegistry() *RoleRegistry {
	return &RoleRegistry{
		roles: make(map[string]*Role),
	}
}

func (r *RoleRegistry) Register(role Role) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.Name] = &role
}

func (r *RoleRegistry) GetRole(name string) (*Role, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role := r.roles[name]
	if role == nil {
		return nil, false
	}
	return role, true
}

