package authorize

import "sync"

type RoleAssignment struct {
	PrincipalID string
	RoleName    string
}

type AccessControl struct {
	ra map[string][]*RoleAssignment
	mu    sync.RWMutex
}

func NewAccessControl() *AccessControl {
	return &AccessControl{
		ra: make(map[string][]*RoleAssignment),
	}
}

func (ac *AccessControl) AssignRole(principalID, roleName string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	assignment := &RoleAssignment{
		PrincipalID: principalID,
		RoleName: roleName,
	}
	var found bool
	assignments := ac.ra[principalID]
	if assignments == nil {
		ac.ra[principalID] = append(ac.ra[principalID], assignment)
	} else {
		for _, a := range assignments {
			if a.RoleName == roleName {
				found = true
				break
			}
		}
		if !found {
			ac.ra[principalID] = append(ac.ra[principalID], assignment)
		}
	}
}

func (ac *AccessControl) IsAllowed(principalID, roleName string) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	var found bool
	assignments := ac.ra[principalID]
	if assignments == nil {
		return false
	}
	for _, a := range assignments {
		if a.RoleName == roleName {
			found = true
			break
		}
	}
	return found
}