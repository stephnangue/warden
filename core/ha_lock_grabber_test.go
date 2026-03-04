package core

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLockGrabber_Acquire(t *testing.T) {
	var mu sync.Mutex
	stopCh := make(chan struct{})

	stopped := grabLockOrStop(mu.Lock, mu.Unlock, stopCh)
	assert.False(t, stopped, "should have acquired the lock")

	// The lock should be held — try to lock again in a goroutine
	acquired := make(chan struct{})
	go func() {
		mu.Lock()
		close(acquired)
		mu.Unlock()
	}()

	// Should not acquire immediately since we hold it
	select {
	case <-acquired:
		t.Fatal("lock should still be held by grabber")
	case <-time.After(50 * time.Millisecond):
	}

	// Release and verify goroutine acquires
	mu.Unlock()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for goroutine to acquire lock")
	}
}

func TestLockGrabber_Stop(t *testing.T) {
	var mu sync.Mutex
	stopCh := make(chan struct{})

	// Hold the lock so grabber blocks
	mu.Lock()

	// Close stopCh immediately so lockOrStop returns stopped=true
	close(stopCh)

	stopped := grabLockOrStop(mu.Lock, mu.Unlock, stopCh)
	assert.True(t, stopped, "should have been stopped")

	// Release the original lock
	mu.Unlock()

	// Give the grab() goroutine time to acquire and then release the lock
	time.Sleep(50 * time.Millisecond)

	// The lock should be free now (grab() should have released it since parent wasn't waiting)
	acquired := make(chan bool, 1)
	go func() {
		mu.Lock()
		acquired <- true
		mu.Unlock()
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("lock should be free after stop")
	}
}

func TestLockGrabber_StopAfterAcquire(t *testing.T) {
	// This tests the race case: lock is acquired AND stopCh fires.
	// Both doneCh and stopCh are ready, so Go's select picks randomly.
	// Either way, the lock must end up released.
	var mu sync.Mutex
	stopCh := make(chan struct{})

	l := newLockGrabber(mu.Lock, mu.Unlock, stopCh)
	go l.grab()

	// Wait for lock to be acquired
	<-l.doneCh

	// Now close stop — both channels are ready
	close(stopCh)
	stopped := l.lockOrStop()

	if !stopped {
		// doneCh won the select — lock is held by caller, release it
		mu.Unlock()
	}
	// If stopped=true, lockOrStop already released the lock

	// Verify lock is free
	acquired := make(chan bool, 1)
	go func() {
		mu.Lock()
		acquired <- true
		mu.Unlock()
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("lock should be free after stop-after-acquire")
	}
}
