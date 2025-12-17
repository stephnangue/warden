// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/stephnangue/warden/logger"
)

// mockBackend is a mock implementation of Storage for testing
type mockBackend struct {
	data  map[string]*Entry
	mutex sync.RWMutex

	// Track calls for testing
	getCalls    int
	putCalls    int
	deleteCalls int
	listCalls   int
}

func newMockBackend() *mockBackend {
	return &mockBackend{
		data: make(map[string]*Entry),
	}
}

func (m *mockBackend) Put(ctx context.Context, entry *Entry) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.putCalls++

	// Clone the entry to simulate real backend behavior
	clone := &Entry{
		Key: entry.Key,
	}
	if entry.Value != nil {
		clone.Value = make([]byte, len(entry.Value))
		copy(clone.Value, entry.Value)
	}
	if entry.ValueHash != nil {
		clone.ValueHash = make([]byte, len(entry.ValueHash))
		copy(clone.ValueHash, entry.ValueHash)
	}

	m.data[entry.Key] = clone
	return nil
}

func (m *mockBackend) Get(ctx context.Context, key string) (*Entry, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	m.getCalls++
	return m.data[key], nil
}

func (m *mockBackend) Delete(ctx context.Context, key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.deleteCalls++
	delete(m.data, key)
	return nil
}

func (m *mockBackend) List(ctx context.Context, prefix string) ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	m.listCalls++

	var keys []string
	for key := range m.data {
		if len(prefix) == 0 || len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *mockBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return nil, nil
}

// mockMetricSink is a simple in-memory metric sink for testing
type mockMetricSink struct {
	counters map[string]float32
	mutex    sync.RWMutex
}

func newMockMetricSink() *mockMetricSink {
	return &mockMetricSink{
		counters: make(map[string]float32),
	}
}

func (m *mockMetricSink) IncrCounter(key []string, val float32) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	k := fmt.Sprintf("%v", key)
	m.counters[k] += val
}

func (m *mockMetricSink) SetGauge(key []string, val float32)            {}
func (m *mockMetricSink) EmitKey(key []string, val float32)             {}
func (m *mockMetricSink) AddSample(key []string, val float32)           {}
func (m *mockMetricSink) AddSampleWithLabels(key []string, val float32, labels []metrics.Label) {}
func (m *mockMetricSink) IncrCounterWithLabels(key []string, val float32, labels []metrics.Label) {}
func (m *mockMetricSink) SetGaugeWithLabels(key []string, val float32, labels []metrics.Label) {}

func (m *mockMetricSink) getCounter(key []string) float32 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	k := fmt.Sprintf("%v", key)
	return m.counters[k]
}

// newTestLogger creates a simple test logger
func newTestLogger() logger.Logger {
	config := &logger.Config{
		Level:       logger.DebugLevel,
		Format:      logger.DefaultFormat,
		Outputs:     []io.Writer{io.Discard},
		Environment: "test",
	}
	return logger.NewZerologLogger(config)
}

func TestNewCache(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	if cache == nil {
		t.Fatal("expected cache to be non-nil")
	}
}

func TestNewCacheDefaultSize(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	c := newCache(backend, 0, testLogger, sink).(*cache)
	if c.size != DefaultCacheSize {
		t.Errorf("expected default cache size %d, got %d", DefaultCacheSize, c.size)
	}

	c = newCache(backend, -1, testLogger, sink).(*cache)
	if c.size != DefaultCacheSize {
		t.Errorf("expected default cache size %d, got %d", DefaultCacheSize, c.size)
	}
}

func TestCacheSetEnabled(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	c := newCache(backend, 10, testLogger, sink).(*cache)

	// Enable cache
	c.SetEnabled(true)
	if !c.GetEnabled() {
		t.Error("cache should be enabled")
	}

	// Disable cache
	c.SetEnabled(false)
	if c.GetEnabled() {
		t.Error("cache should be disabled")
	}
}

func TestCachePutGet(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()
	entry := &Entry{
		Key:   "test/key",
		Value: []byte("test-value"),
	}

	// Put entry
	if err := cache.Put(ctx, entry); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get entry - should hit cache
	result, err := cache.Get(ctx, "test/key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result to be non-nil")
	}

	if result.Key != entry.Key {
		t.Errorf("expected key %s, got %s", entry.Key, result.Key)
	}

	if string(result.Value) != string(entry.Value) {
		t.Errorf("expected value %s, got %s", entry.Value, result.Value)
	}

	// Verify it's a cache hit (backend should only be called once for Put)
	if backend.getCalls != 0 {
		t.Errorf("expected 0 backend Get calls (cache hit), got %d", backend.getCalls)
	}
}

func TestCacheMiss(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()

	// Get non-existent entry - should miss cache
	result, err := cache.Get(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if result != nil {
		t.Error("expected nil result for non-existent key")
	}

	// Backend should be called
	if backend.getCalls != 1 {
		t.Errorf("expected 1 backend Get call, got %d", backend.getCalls)
	}

	// Verify cache miss metric
	missCount := sink.getCounter([]string{"cache", "miss"})
	if missCount != 1 {
		t.Errorf("expected 1 cache miss, got %f", missCount)
	}
}

func TestCacheHit(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()
	entry := &Entry{
		Key:   "test/key",
		Value: []byte("test-value"),
	}

	// Put entry
	cache.Put(ctx, entry)

	// Get entry twice
	cache.Get(ctx, "test/key")
	cache.Get(ctx, "test/key")

	// Verify cache hit metric
	hitCount := sink.getCounter([]string{"cache", "hit"})
	if hitCount != 2 {
		t.Errorf("expected 2 cache hits, got %f", hitCount)
	}
}

func TestCacheDelete(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()
	entry := &Entry{
		Key:   "test/key",
		Value: []byte("test-value"),
	}

	// Put entry
	cache.Put(ctx, entry)

	// Verify it's cached
	result, _ := cache.Get(ctx, "test/key")
	if result == nil {
		t.Fatal("expected entry to be cached")
	}

	// Delete entry
	if err := cache.Delete(ctx, "test/key"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Get should now miss cache and return nil from backend
	result, _ = cache.Get(ctx, "test/key")
	if result != nil {
		t.Error("expected nil result after delete")
	}

	// Backend delete should be called
	if backend.deleteCalls != 1 {
		t.Errorf("expected 1 backend Delete call, got %d", backend.deleteCalls)
	}
}

func TestCacheDisabled(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	// Don't enable cache

	ctx := context.Background()
	entry := &Entry{
		Key:   "test/key",
		Value: []byte("test-value"),
	}

	// Put entry
	cache.Put(ctx, entry)

	// Get entry - should always go to backend
	cache.Get(ctx, "test/key")
	cache.Get(ctx, "test/key")

	// Backend should be called every time
	if backend.getCalls != 2 {
		t.Errorf("expected 2 backend Get calls (cache disabled), got %d", backend.getCalls)
	}
}

func TestCacheShouldCache(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	c := NewCache(backend, 10, testLogger, sink).(*cache)
	c.SetEnabled(true)

	// Regular keys should be cached
	if !c.ShouldCache("test/key") {
		t.Error("expected regular key to be cacheable")
	}

	// Exception paths should not be cached
	for _, path := range cacheExceptionsPaths {
		if c.ShouldCache(path) {
			t.Errorf("expected exception path %s to not be cacheable", path)
		}
	}

	// When disabled, nothing should be cached
	c.SetEnabled(false)
	if c.ShouldCache("test/key") {
		t.Error("expected no caching when disabled")
	}
}

func TestCacheExceptionPaths(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()

	// Test each exception path
	for _, path := range cacheExceptionsPaths {
		entry := &Entry{
			Key:   path,
			Value: []byte("value"),
		}

		backend.getCalls = 0

		// Put
		cache.Put(ctx, entry)

		// Get twice - should always go to backend
		cache.Get(ctx, path)
		cache.Get(ctx, path)

		if backend.getCalls != 2 {
			t.Errorf("path %s: expected 2 backend calls, got %d", path, backend.getCalls)
		}
	}
}

func TestCachePurge(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()

	// Add multiple entries
	for i := 0; i < 5; i++ {
		entry := &Entry{
			Key:   fmt.Sprintf("test/key%d", i),
			Value: []byte(fmt.Sprintf("value%d", i)),
		}
		cache.Put(ctx, entry)
	}

	// Verify they're cached
	for i := 0; i < 5; i++ {
		result, _ := cache.Get(ctx, fmt.Sprintf("test/key%d", i))
		if result == nil {
			t.Fatalf("expected key%d to be cached", i)
		}
	}

	// Purge cache
	cache.Purge(ctx)

	// Reset backend call counts
	backend.getCalls = 0

	// Get should now miss cache
	for i := 0; i < 5; i++ {
		cache.Get(ctx, fmt.Sprintf("test/key%d", i))
	}

	if backend.getCalls != 5 {
		t.Errorf("expected 5 backend Get calls after purge, got %d", backend.getCalls)
	}
}

func TestCacheInvalidate(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()
	entry := &Entry{
		Key:   "test/key",
		Value: []byte("test-value"),
	}

	// Put and verify cached
	cache.Put(ctx, entry)
	result, _ := cache.Get(ctx, "test/key")
	if result == nil {
		t.Fatal("expected entry to be cached")
	}

	// Invalidate
	cache.Invalidate(ctx, "test/key")

	// Reset backend calls
	backend.getCalls = 0

	// Get should now miss cache
	cache.Get(ctx, "test/key")

	if backend.getCalls != 1 {
		t.Errorf("expected 1 backend Get call after invalidate, got %d", backend.getCalls)
	}
}

func TestCacheRefreshContext(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()
	entry := &Entry{
		Key:   "test/key",
		Value: []byte("test-value"),
	}

	// Put entry
	cache.Put(ctx, entry)

	// Get with refresh context - should bypass cache
	refreshCtx := CacheRefreshContext(ctx, true)

	backend.getCalls = 0
	cache.Get(refreshCtx, "test/key")

	if backend.getCalls != 1 {
		t.Errorf("expected 1 backend Get call with refresh context, got %d", backend.getCalls)
	}

	// Get without refresh - should hit cache
	backend.getCalls = 0
	cache.Get(ctx, "test/key")

	if backend.getCalls != 0 {
		t.Errorf("expected 0 backend Get calls without refresh, got %d", backend.getCalls)
	}
}

func TestCacheList(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()

	// Add entries to backend
	backend.Put(ctx, &Entry{Key: "prefix/key1", Value: []byte("val1")})
	backend.Put(ctx, &Entry{Key: "prefix/key2", Value: []byte("val2")})
	backend.Put(ctx, &Entry{Key: "other/key3", Value: []byte("val3")})

	// List should pass through to backend
	keys, err := cache.List(ctx, "prefix/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("expected 2 keys with prefix, got %d", len(keys))
	}

	if backend.listCalls != 1 {
		t.Errorf("expected 1 backend List call, got %d", backend.listCalls)
	}
}

func TestCacheConcurrency(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 100, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()

	// Concurrent writes and reads
	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			key := fmt.Sprintf("concurrent/key%d", id)
			entry := &Entry{
				Key:   key,
				Value: []byte(fmt.Sprintf("value%d", id)),
			}

			// Put
			if err := cache.Put(ctx, entry); err != nil {
				t.Errorf("concurrent Put failed: %v", err)
			}

			// Get
			result, err := cache.Get(ctx, key)
			if err != nil {
				t.Errorf("concurrent Get failed: %v", err)
			}

			if result == nil || string(result.Value) != string(entry.Value) {
				t.Errorf("concurrent Get returned wrong value")
			}

			// Delete
			if err := cache.Delete(ctx, key); err != nil {
				t.Errorf("concurrent Delete failed: %v", err)
			}
		}(i)
	}

	wg.Wait()
}

func TestCacheValueCloning(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()

	originalValue := []byte("original")
	originalHash := []byte("hash")

	entry := &Entry{
		Key:       "test/key",
		Value:     originalValue,
		ValueHash: originalHash,
	}

	// Put entry
	cache.Put(ctx, entry)

	// Modify original entry
	entry.Value[0] = 'X'
	entry.ValueHash[0] = 'X'

	// Get from cache - should have original value
	result, _ := cache.Get(ctx, "test/key")

	if result.Value[0] != 'o' {
		t.Error("cache entry was modified - cloning failed")
	}

	if result.ValueHash[0] != 'h' {
		t.Error("cache entry hash was modified - cloning failed")
	}
}

func TestCacheRefreshFromContext(t *testing.T) {
	ctx := context.Background()

	// No refresh value
	if cacheRefreshFromContext(ctx) {
		t.Error("expected false for context without refresh value")
	}

	// With refresh = true
	ctx = CacheRefreshContext(ctx, true)
	if !cacheRefreshFromContext(ctx) {
		t.Error("expected true for refresh context")
	}

	// With refresh = false
	ctx = CacheRefreshContext(context.Background(), false)
	if cacheRefreshFromContext(ctx) {
		t.Error("expected false when refresh is false")
	}
}

func TestCacheMetrics(t *testing.T) {
	backend := newMockBackend()
	testLogger := newTestLogger()
	sink := newMockMetricSink()

	cache := NewCache(backend, 10, testLogger, sink)
	cache.SetEnabled(true)

	ctx := context.Background()

	entry := &Entry{
		Key:   "test/key",
		Value: []byte("value"),
	}

	// Put
	cache.Put(ctx, entry)
	writeCount := sink.getCounter([]string{"cache", "write"})
	if writeCount != 1 {
		t.Errorf("expected 1 write metric, got %f", writeCount)
	}

	// Cache hit
	cache.Get(ctx, "test/key")
	hitCount := sink.getCounter([]string{"cache", "hit"})
	if hitCount != 1 {
		t.Errorf("expected 1 hit metric, got %f", hitCount)
	}

	// Cache miss
	cache.Get(ctx, "nonexistent")
	missCount := sink.getCounter([]string{"cache", "miss"})
	if missCount != 1 {
		t.Errorf("expected 1 miss metric, got %f", missCount)
	}
}
