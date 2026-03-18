package locking

import (
	"sync"
	"testing"
)

// Compile-time interface assertions.
var (
	_ RWMutex = (*DeadlockRWMutex)(nil)
	_ RWMutex = (*SyncRWMutex)(nil)
)

func TestDeadlockRWMutex_LockUnlock(t *testing.T) {
	var mu DeadlockRWMutex
	mu.Lock()
	mu.Unlock()
}

func TestDeadlockRWMutex_RLockRUnlock(t *testing.T) {
	var mu DeadlockRWMutex
	mu.RLock()
	mu.RUnlock()
}

func TestDeadlockRWMutex_RLocker(t *testing.T) {
	var mu DeadlockRWMutex
	locker := mu.RLocker()
	if locker == nil {
		t.Fatal("RLocker() returned nil")
	}
	locker.Lock()
	locker.Unlock()
}

func TestSyncRWMutex_LockUnlock(t *testing.T) {
	var mu SyncRWMutex
	mu.Lock()
	mu.Unlock()
}

func TestSyncRWMutex_RLockRUnlock(t *testing.T) {
	var mu SyncRWMutex
	mu.RLock()
	mu.RUnlock()
}

func TestSyncRWMutex_RLocker(t *testing.T) {
	var mu SyncRWMutex
	locker := mu.RLocker()
	if locker == nil {
		t.Fatal("RLocker() returned nil")
	}
	locker.Lock()
	locker.Unlock()
}

func TestConcurrentReadWrite(t *testing.T) {
	for _, impl := range []struct {
		name string
		mu   RWMutex
	}{
		{"DeadlockRWMutex", &DeadlockRWMutex{}},
		{"SyncRWMutex", &SyncRWMutex{}},
	} {
		t.Run(impl.name, func(t *testing.T) {
			mu := impl.mu
			var counter int
			var wg sync.WaitGroup

			// Concurrent writers
			for i := 0; i < 10; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					mu.Lock()
					counter++
					mu.Unlock()
				}()
			}

			// Concurrent readers
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					mu.RLock()
					_ = counter
					mu.RUnlock()
				}()
			}

			wg.Wait()
			if counter != 10 {
				t.Fatalf("expected counter=10, got %d", counter)
			}
		})
	}
}
