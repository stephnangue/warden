package inmem

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/logger"
)

func TestInmemHAStorage_Creation(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage, ok := storage.(physical.HABackend)
	if !ok {
		t.Fatal("storage does not implement HAStorage interface")
	}

	if !haStorage.HAEnabled() {
		t.Error("HAEnabled() should return true")
	}
}

func TestInmemHAStorage_BasicStorage(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	ctx := context.Background()

	// Test basic storage operations
	entry := &physical.Entry{
		Key:   "ha/test/key",
		Value: []byte("ha test value"),
	}

	if err := storage.Put(ctx, entry); err != nil {
		t.Fatalf("failed to put entry: %v", err)
	}

	result, err := storage.Get(ctx, "ha/test/key")
	if err != nil {
		t.Fatalf("failed to get entry: %v", err)
	}
	if result == nil {
		t.Fatal("expected entry, got nil")
	}
	if string(result.Value) != "ha test value" {
		t.Errorf("expected value 'ha test value', got %s", string(result.Value))
	}

	if err := storage.Delete(ctx, "ha/test/key"); err != nil {
		t.Fatalf("failed to delete entry: %v", err)
	}

	result, err = storage.Get(ctx, "ha/test/key")
	if err != nil {
		t.Fatalf("failed to get deleted entry: %v", err)
	}
	if result != nil {
		t.Error("expected nil for deleted entry")
	}
}

func TestInmemHAStorage_Lock(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(physical.HABackend)

	// Create a lock
	lock, err := haStorage.LockWith("test/lock", "node1")
	if err != nil {
		t.Fatalf("failed to create lock: %v", err)
	}

	// Check lock value before acquisition
	held, value, err := lock.Value()
	if err != nil {
		t.Fatalf("failed to get lock value: %v", err)
	}
	if held {
		t.Error("lock should not be held initially")
	}
	if value != "" {
		t.Errorf("expected empty value, got %s", value)
	}

	// Acquire the lock
	stopCh := make(chan struct{})
	leaderCh, err := lock.Lock(stopCh)
	if err != nil {
		t.Fatalf("failed to acquire lock: %v", err)
	}
	if leaderCh == nil {
		t.Fatal("expected non-nil leader channel")
	}

	// Check lock value after acquisition
	held, value, err = lock.Value()
	if err != nil {
		t.Fatalf("failed to get lock value: %v", err)
	}
	if !held {
		t.Error("lock should be held")
	}
	if value != "node1" {
		t.Errorf("expected value 'node1', got %s", value)
	}

	// Release the lock
	if err := lock.Unlock(); err != nil {
		t.Fatalf("failed to release lock: %v", err)
	}

	// Verify leader channel is closed
	select {
	case <-leaderCh:
		// Expected - channel should be closed
	case <-time.After(100 * time.Millisecond):
		t.Error("leader channel should be closed after unlock")
	}

	// Check lock value after release
	held, value, err = lock.Value()
	if err != nil {
		t.Fatalf("failed to get lock value: %v", err)
	}
	if held {
		t.Error("lock should not be held after unlock")
	}
}

func TestInmemHAStorage_DoubleLock(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(physical.HABackend)

	lock, err := haStorage.LockWith("test/double", "node1")
	if err != nil {
		t.Fatalf("failed to create lock: %v", err)
	}

	stopCh := make(chan struct{})
	_, err = lock.Lock(stopCh)
	if err != nil {
		t.Fatalf("failed to acquire lock first time: %v", err)
	}

	// Try to lock again without releasing
	_, err = lock.Lock(stopCh)
	if err == nil {
		t.Error("expected error when trying to lock twice")
	}
	if err != nil && err.Error() != "lock already held" {
		t.Errorf("expected 'lock already held' error, got %v", err)
	}

	// Clean up
	lock.Unlock()
}

func TestInmemHAStorage_DoubleUnlock(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(physical.HABackend)

	lock, err := haStorage.LockWith("test/unlock", "node1")
	if err != nil {
		t.Fatalf("failed to create lock: %v", err)
	}

	stopCh := make(chan struct{})
	_, err = lock.Lock(stopCh)
	if err != nil {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// First unlock
	if err := lock.Unlock(); err != nil {
		t.Fatalf("first unlock failed: %v", err)
	}

	// Second unlock (should be no-op)
	if err := lock.Unlock(); err != nil {
		t.Errorf("second unlock should not error: %v", err)
	}
}

func TestInmemHAStorage_ConcurrentLocks(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(physical.HABackend)

	// Create two locks for the same key
	lock1, err := haStorage.LockWith("test/concurrent", "node1")
	if err != nil {
		t.Fatalf("failed to create lock1: %v", err)
	}

	lock2, err := haStorage.LockWith("test/concurrent", "node2")
	if err != nil {
		t.Fatalf("failed to create lock2: %v", err)
	}

	// Acquire first lock
	stopCh1 := make(chan struct{})
	leaderCh1, err := lock1.Lock(stopCh1)
	if err != nil {
		t.Fatalf("failed to acquire lock1: %v", err)
	}

	// Try to acquire second lock in goroutine
	acquired := make(chan bool, 1)
	go func() {
		stopCh2 := make(chan struct{})
		leaderCh2, err := lock2.Lock(stopCh2)
		if err != nil {
			acquired <- false
			return
		}
		if leaderCh2 != nil {
			acquired <- true
			lock2.Unlock()
		} else {
			acquired <- false
		}
	}()

	// Second lock should not acquire immediately
	select {
	case <-acquired:
		t.Error("lock2 should not acquire while lock1 is held")
	case <-time.After(100 * time.Millisecond):
		// Expected - lock2 is waiting
	}

	// Release first lock
	if err := lock1.Unlock(); err != nil {
		t.Fatalf("failed to release lock1: %v", err)
	}

	// Verify leader channel is closed
	select {
	case <-leaderCh1:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("leaderCh1 should be closed after unlock")
	}

	// Now second lock should acquire
	select {
	case success := <-acquired:
		if !success {
			t.Error("lock2 should acquire after lock1 is released")
		}
	case <-time.After(1 * time.Second):
		t.Error("lock2 should acquire after lock1 is released")
	}
}

func TestInmemHAStorage_LockInterrupt(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(physical.HABackend)

	// Create and acquire first lock
	lock1, err := haStorage.LockWith("test/interrupt", "node1")
	if err != nil {
		t.Fatalf("failed to create lock1: %v", err)
	}

	stopCh1 := make(chan struct{})
	_, err = lock1.Lock(stopCh1)
	if err != nil {
		t.Fatalf("failed to acquire lock1: %v", err)
	}

	// Try to acquire second lock with stop channel
	lock2, err := haStorage.LockWith("test/interrupt", "node2")
	if err != nil {
		t.Fatalf("failed to create lock2: %v", err)
	}

	stopCh2 := make(chan struct{})
	resultCh := make(chan error, 1)

	go func() {
		leaderCh, err := lock2.Lock(stopCh2)
		if err != nil {
			resultCh <- err
		} else if leaderCh == nil {
			resultCh <- nil // Interrupted
		} else {
			resultCh <- fmt.Errorf("unexpected success")
		}
	}()

	// Wait a bit to ensure lock2 is waiting
	time.Sleep(50 * time.Millisecond)

	// Close stop channel to interrupt
	close(stopCh2)

	// Should return nil (interrupted)
	select {
	case err := <-resultCh:
		if err != nil {
			t.Errorf("expected nil error for interrupted lock, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("lock should be interrupted")
	}

	// Clean up
	lock1.Unlock()
}

func TestInmemHAStorage_MultipleLocks(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(physical.HABackend)

	// Create locks for different keys
	lock1, err := haStorage.LockWith("test/lock1", "node1")
	if err != nil {
		t.Fatalf("failed to create lock1: %v", err)
	}

	lock2, err := haStorage.LockWith("test/lock2", "node2")
	if err != nil {
		t.Fatalf("failed to create lock2: %v", err)
	}

	// Both should acquire successfully (different keys)
	stopCh1 := make(chan struct{})
	leaderCh1, err := lock1.Lock(stopCh1)
	if err != nil {
		t.Fatalf("failed to acquire lock1: %v", err)
	}
	if leaderCh1 == nil {
		t.Fatal("expected non-nil leader channel for lock1")
	}

	stopCh2 := make(chan struct{})
	leaderCh2, err := lock2.Lock(stopCh2)
	if err != nil {
		t.Fatalf("failed to acquire lock2: %v", err)
	}
	if leaderCh2 == nil {
		t.Fatal("expected non-nil leader channel for lock2")
	}

	// Both should be held
	held1, _, _ := lock1.Value()
	held2, _, _ := lock2.Value()
	if !held1 || !held2 {
		t.Error("both locks should be held")
	}

	// Release both
	lock1.Unlock()
	lock2.Unlock()
}

func TestInmemHAStorage_LockMapSize(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(*InmemHAStorage)

	// Initially empty
	if size := haStorage.LockMapSize(); size != 0 {
		t.Errorf("expected lock map size 0, got %d", size)
	}

	// Create and acquire locks
	lock1, _ := haStorage.LockWith("test/size1", "node1")
	lock2, _ := haStorage.LockWith("test/size2", "node2")

	stopCh := make(chan struct{})
	lock1.Lock(stopCh)
	lock2.Lock(stopCh)

	// Should have 2 locks
	if size := haStorage.LockMapSize(); size != 2 {
		t.Errorf("expected lock map size 2, got %d", size)
	}

	// Release one lock
	lock1.Unlock()

	// Should have 1 lock
	if size := haStorage.LockMapSize(); size != 1 {
		t.Errorf("expected lock map size 1, got %d", size)
	}

	// Release second lock
	lock2.Unlock()

	// Should be empty again
	if size := haStorage.LockMapSize(); size != 0 {
		t.Errorf("expected lock map size 0, got %d", size)
	}
}

func TestInmemHAStorage_Invalidation(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(*InmemHAStorage)
	ctx := context.Background()

	// Track invalidations
	var mu sync.Mutex
	invalidated := make(map[string]int)

	// Hook invalidation handler
	haStorage.HookInvalidate(func(keys ...string) {
		mu.Lock()
		defer mu.Unlock()
		for _, key := range keys {
			invalidated[key]++
		}
	})

	// Put entry (should trigger invalidation)
	entry := &physical.Entry{
		Key:   "test/invalidate",
		Value: []byte("value"),
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatalf("failed to put entry: %v", err)
	}

	// Wait for async invalidation
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := invalidated["test/invalidate"]
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 invalidation for put, got %d", count)
	}

	// Delete entry (should trigger invalidation)
	if err := storage.Delete(ctx, "test/invalidate"); err != nil {
		t.Fatalf("failed to delete entry: %v", err)
	}

	// Wait for async invalidation
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count = invalidated["test/invalidate"]
	mu.Unlock()

	if count != 2 {
		t.Errorf("expected 2 invalidations (put+delete), got %d", count)
	}
}

func TestInmemHAStorage_MultipleInvalidationHooks(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(*InmemHAStorage)
	ctx := context.Background()

	// Track invalidations from multiple hooks
	var mu1, mu2 sync.Mutex
	invalidated1 := make(map[string]int)
	invalidated2 := make(map[string]int)

	// Hook multiple handlers
	haStorage.HookInvalidate(func(keys ...string) {
		mu1.Lock()
		defer mu1.Unlock()
		for _, key := range keys {
			invalidated1[key]++
		}
	})

	haStorage.HookInvalidate(func(keys ...string) {
		mu2.Lock()
		defer mu2.Unlock()
		for _, key := range keys {
			invalidated2[key]++
		}
	})

	// Put entry
	entry := &physical.Entry{
		Key:   "test/multi",
		Value: []byte("value"),
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatalf("failed to put entry: %v", err)
	}

	// Wait for async invalidations
	time.Sleep(50 * time.Millisecond)

	mu1.Lock()
	count1 := invalidated1["test/multi"]
	mu1.Unlock()

	mu2.Lock()
	count2 := invalidated2["test/multi"]
	mu2.Unlock()

	if count1 != 1 {
		t.Errorf("expected 1 invalidation in handler 1, got %d", count1)
	}
	if count2 != 1 {
		t.Errorf("expected 1 invalidation in handler 2, got %d", count2)
	}
}

func TestInmemHAStorage_CacheInvalidationInterface(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	// Verify it implements CacheInvalidationBackend
	_, ok := storage.(physical.CacheInvalidationBackend)
	if !ok {
		t.Error("InmemHAStorage should implement CacheInvalidationBackend interface")
	}
}

func TestInmemHAStorage_LockValue_Consistency(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(physical.HABackend)

	lock1, _ := haStorage.LockWith("test/value", "node1")
	lock2, _ := haStorage.LockWith("test/value", "node2")

	// Both locks should see the same value
	stopCh := make(chan struct{})
	lock1.Lock(stopCh)

	held1, value1, _ := lock1.Value()
	held2, value2, _ := lock2.Value()

	if !held1 {
		t.Error("lock1 should report lock as held")
	}
	if !held2 {
		t.Error("lock2 should also report lock as held (by someone)")
	}
	if value1 != value2 {
		t.Errorf("both locks should see same value: %s vs %s", value1, value2)
	}
	if value1 != "node1" {
		t.Errorf("expected value 'node1', got %s", value1)
	}

	lock1.Unlock()
}

func TestInmemHAStorage_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA Backend: %v", err)
	}

	haStorage := storage.(physical.HABackend)

	var wg sync.WaitGroup
	concurrency := 20
	iterations := 100

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(nodeID int) {
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				lock, err := haStorage.LockWith("stress/lock", fmt.Sprintf("node%d", nodeID))
				if err != nil {
					t.Errorf("failed to create lock: %v", err)
					continue
				}

				stopCh := make(chan struct{})
				leaderCh, err := lock.Lock(stopCh)
				if err != nil {
					t.Errorf("failed to acquire lock: %v", err)
					continue
				}

				if leaderCh != nil {
					// Hold lock briefly
					time.Sleep(time.Microsecond)
					lock.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestInmemHAStorage_InvalidationRace(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	haStorage := storage.(*InmemHAStorage)
	ctx := context.Background()

	var wg sync.WaitGroup

	// Add multiple invalidation hooks
	for i := 0; i < 10; i++ {
		haStorage.HookInvalidate(func(keys ...string) {
			time.Sleep(time.Millisecond)
		})
	}

	// Perform concurrent puts
	concurrency := 50
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			entry := &physical.Entry{
				Key:   fmt.Sprintf("race/key-%d", idx),
				Value: []byte(fmt.Sprintf("value-%d", idx)),
			}
			if err := storage.Put(ctx, entry); err != nil {
				t.Errorf("failed to put entry: %v", err)
			}
		}(i)
	}

	wg.Wait()
}

func TestInmemHAStorage_ListPage(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	ctx := context.Background()

	// Create test entries with predictable names
	keys := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	for _, key := range keys {
		entry := &physical.Entry{
			Key:   "test/" + key,
			Value: []byte("value"),
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatalf("failed to put entry: %v", err)
		}
	}

	// Check that storage supports ListPage through type assertion
	listPageStorage, ok := storage.(interface {
		ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error)
	})
	if !ok {
		t.Fatal("storage does not support ListPage")
	}

	t.Run("first page with limit", func(t *testing.T) {
		result, err := listPageStorage.ListPage(ctx, "test/", "", 5)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		if len(result) != 5 {
			t.Fatalf("expected 5 keys, got %d", len(result))
		}
	})

	t.Run("second page with after", func(t *testing.T) {
		result, err := listPageStorage.ListPage(ctx, "test/", "e", 5)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		if len(result) != 5 {
			t.Fatalf("expected 5 keys, got %d", len(result))
		}
	})

	t.Run("last page partial results", func(t *testing.T) {
		result, err := listPageStorage.ListPage(ctx, "test/", "h", 5)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		if len(result) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(result))
		}
	})

	t.Run("no limit returns all", func(t *testing.T) {
		result, err := listPageStorage.ListPage(ctx, "test/", "", -1)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		if len(result) != 10 {
			t.Fatalf("expected 10 keys, got %d", len(result))
		}
	})

	t.Run("limit larger than results", func(t *testing.T) {
		result, err := listPageStorage.ListPage(ctx, "test/", "", 100)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		if len(result) != 10 {
			t.Fatalf("expected 10 keys, got %d", len(result))
		}
	})

	t.Run("after last key", func(t *testing.T) {
		result, err := listPageStorage.ListPage(ctx, "test/", "j", 5)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		if len(result) != 0 {
			t.Fatalf("expected 0 keys, got %d", len(result))
		}
	})
}

func TestInmemHAStorage_ListPage_WithDirectories(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	ctx := context.Background()

	// Create mixed entries: files and directories
	entries := []*physical.Entry{
		{Key: "test/aaa", Value: []byte("value1")},
		{Key: "test/bbb", Value: []byte("value2")},
		{Key: "test/dir1/key1", Value: []byte("value3")},
		{Key: "test/dir2/key2", Value: []byte("value4")},
		{Key: "test/zzz", Value: []byte("value5")},
	}

	for _, entry := range entries {
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	listPageStorage := storage.(interface {
		ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error)
	})

	t.Run("list with directories first page", func(t *testing.T) {
		result, err := listPageStorage.ListPage(ctx, "test/", "", 3)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		// Should return first 3 items
		if len(result) != 3 {
			t.Fatalf("expected 3 items, got %d", len(result))
		}
	})

	t.Run("list with directories second page", func(t *testing.T) {
		result, err := listPageStorage.ListPage(ctx, "test/", "dir1/", 3)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		// Should return remaining items
		if len(result) != 2 {
			t.Fatalf("expected 2 items, got %d", len(result))
		}
	})
}

func TestInmemHAStorage_ListPage_EmptyPrefix(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	ctx := context.Background()

	// Create entries at root level
	entries := []*physical.Entry{
		{Key: "key1", Value: []byte("value1")},
		{Key: "key2", Value: []byte("value2")},
		{Key: "key3", Value: []byte("value3")},
	}

	for _, entry := range entries {
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	listPageStorage := storage.(interface {
		ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error)
	})

	result, err := listPageStorage.ListPage(ctx, "", "", 2)
	if err != nil {
		t.Fatalf("ListPage failed: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(result))
	}
}

func TestInmemHAStorage_ListPage_NonExistentPrefix(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	ctx := context.Background()

	listPageStorage := storage.(interface {
		ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error)
	})

	result, err := listPageStorage.ListPage(ctx, "nonexistent/", "", 10)
	if err != nil {
		t.Fatalf("expected no error for non-existent prefix, got %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty list for non-existent prefix, got %v", result)
	}
}

func TestInmemHAStorage_ListPage_CancelledContext(t *testing.T) {
	logger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	storage, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem HA storage: %v", err)
	}

	// Create some test entries
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		entry := &physical.Entry{
			Key:   fmt.Sprintf("test/key%d", i),
			Value: []byte("value"),
		}
		storage.Put(ctx, entry)
	}

	listPageStorage := storage.(interface {
		ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error)
	})

	// Try to list with cancelled context
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = listPageStorage.ListPage(cancelledCtx, "test/", "", 10)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}