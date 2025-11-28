package cred

import "sync"

type CredSource struct {
	Name   string
	Type   string // local, vault, aws, azure, cgp
	Config map[string]string
}

type CredSourceRegistry struct {
	sources map[string]*CredSource
	mu      sync.RWMutex
}

func NewCredSourceRegistry() *CredSourceRegistry {
	return &CredSourceRegistry{
		sources: make(map[string]*CredSource),
	}
}

func (r *CredSourceRegistry) Register(source CredSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[source.Name] = &source
}

func (r *CredSourceRegistry) GetSource(name string) (*CredSource, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	source := r.sources[name]
	if source == nil {
		return nil, false
	}
	return source, true
}
