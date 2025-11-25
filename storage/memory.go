package storage

import (
	"context"
	"sync"
)

type memoryStorage struct {
	data map[string]map[string]any
	mu sync.RWMutex
}

func NewMemoryStorage() Storage {
	return &memoryStorage{
		data: make(map[string]map[string]any),
	}
}

func(m *memoryStorage) Init(ctx context.Context) error {
	return nil
}

func(m *memoryStorage) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]map[string]any)
	return nil
}

func(m *memoryStorage) Put(ctx context.Context, prefix string, key string, data map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.data[prefix] == nil {
		m.data[prefix] = make(map[string]any)
	}

	m.data[prefix][key] = data

	return nil
}

func(m *memoryStorage) Get(ctx context.Context, prefix string, key string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.data[prefix] == nil {
		return make(map[string]any), nil
	}

	data, exists := m.data[prefix][key]

	if !exists {
		return make(map[string]any), nil
	}

	return data.(map[string]any), nil
}

func(m *memoryStorage) List(ctx context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string

	if m.data[prefix] == nil {
		return keys, nil
	}

	for key := range m.data[prefix] {
		keys = append(keys, key)
	}
	return keys, nil
}

func(m *memoryStorage) Delete(ctx context.Context, prefix string, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.data[prefix] == nil {
		delete(m.data[prefix], key)
	}

	return nil
}

