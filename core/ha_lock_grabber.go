package core

import "sync"

// lockGrabber implements non-blocking lock acquisition with cancellation.
// It spawns a goroutine to acquire a mutex, and the caller can select
// between successful acquisition or a stop signal. This prevents
// indefinite blocking when acquiring stateLock during HA transitions.
type lockGrabber struct {
	stopCh     <-chan struct{}
	doneCh     chan struct{}
	lockFunc   func()
	unlockFunc func()

	mu            sync.Mutex
	parentWaiting bool
	locked        bool
}

func newLockGrabber(lockFunc, unlockFunc func(), stopCh <-chan struct{}) *lockGrabber {
	return &lockGrabber{
		lockFunc:      lockFunc,
		unlockFunc:    unlockFunc,
		stopCh:        stopCh,
		doneCh:        make(chan struct{}),
		parentWaiting: true,
	}
}

// grab is called in a goroutine. It acquires the lock, then checks
// whether the parent is still waiting. If not, it releases the lock.
func (l *lockGrabber) grab() {
	defer close(l.doneCh)
	l.lockFunc()

	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.parentWaiting {
		l.unlockFunc()
	} else {
		l.locked = true
	}
}

// lockOrStop waits for either the lock to be acquired (doneCh) or
// for cancellation (stopCh). Returns true if stopped before lock
// was acquired.
func (l *lockGrabber) lockOrStop() (stopped bool) {
	select {
	case <-l.doneCh:
		return false
	case <-l.stopCh:
		l.mu.Lock()
		defer l.mu.Unlock()
		l.parentWaiting = false
		if l.locked {
			l.unlockFunc()
			l.locked = false
		}
		return true
	}
}

// grabLockOrStop is a convenience function that acquires lockFunc
// non-blockingly. If stopCh closes before acquisition completes,
// the lock is released (if it was grabbed) and stopped=true is returned.
func grabLockOrStop(lockFunc, unlockFunc func(), stopCh <-chan struct{}) (stopped bool) {
	l := newLockGrabber(lockFunc, unlockFunc, stopCh)
	go l.grab()
	return l.lockOrStop()
}
