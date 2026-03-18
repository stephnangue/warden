// Package locking provides mutex wrappers with optional deadlock detection.
// This replaces the internal github.com/openbao/openbao/helper/locking package.
package locking

import (
	"sync"

	"github.com/sasha-s/go-deadlock"
)

// RWMutex is a common read/write mutex interface to allow either built-in
// or imported deadlock-detecting use.
type RWMutex interface {
	Lock()
	RLock()
	RLocker() sync.Locker
	RUnlock()
	Unlock()
}

// DeadlockRWMutex wraps go-deadlock's RWMutex for periodic deadlock detection.
// When a potential deadlock is found, it outputs diagnostics prefixed with
// "POTENTIAL DEADLOCK". See https://github.com/sasha-s/go-deadlock
type DeadlockRWMutex struct {
	deadlock.RWMutex
}

// SyncRWMutex wraps the standard library sync.RWMutex.
type SyncRWMutex struct {
	sync.RWMutex
}
