package target

import "sync"

type TargetRegistry struct {
	targets map[string]Target
	mu    sync.RWMutex
}

func NewTargetRegistry() *TargetRegistry {
	return &TargetRegistry{
		targets: make(map[string]Target),
	}
}

func (r *TargetRegistry) Register(target Target) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets[target.GetName()] = target
}

func (r *TargetRegistry) GetTarget(name string) (Target, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	target := r.targets[name]
	if target == nil {
		return nil, false
	}
	return target, true
}

