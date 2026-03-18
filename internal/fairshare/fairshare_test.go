package fairshare

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testJob is a simple Job implementation for testing.
type testJob struct {
	id        string
	executeFn func() error
	failureFn func(error)
}

func (j *testJob) Execute() error {
	if j.executeFn != nil {
		return j.executeFn()
	}
	return nil
}

func (j *testJob) OnFailure(err error) {
	if j.failureFn != nil {
		j.failureFn(err)
	}
}

func TestJobManager_SingleQueue(t *testing.T) {
	jm := NewJobManager("test", 2, nil, nil)
	jm.Start()
	defer jm.Stop()

	var count atomic.Int32
	var wg sync.WaitGroup
	n := 10
	wg.Add(n)

	for i := 0; i < n; i++ {
		jm.AddJob(&testJob{
			executeFn: func() error {
				count.Add(1)
				wg.Done()
				return nil
			},
		}, "queue-1")
	}

	wg.Wait()
	if got := count.Load(); got != int32(n) {
		t.Fatalf("expected %d executions, got %d", n, got)
	}
}

func TestJobManager_ExecuteAndOnFailure(t *testing.T) {
	jm := NewJobManager("test", 1, nil, nil)
	jm.Start()
	defer jm.Stop()

	var failErr atomic.Value
	var wg sync.WaitGroup
	wg.Add(1)

	expectedErr := errors.New("job failed")
	jm.AddJob(&testJob{
		executeFn: func() error {
			return expectedErr
		},
		failureFn: func(err error) {
			failErr.Store(err)
			wg.Done()
		},
	}, "queue-1")

	wg.Wait()
	if got := failErr.Load(); got != expectedErr {
		t.Fatalf("expected error %v, got %v", expectedErr, got)
	}
}

func TestJobManager_MultiQueueFairness(t *testing.T) {
	jm := NewJobManager("test", 4, nil, nil)
	jm.Start()
	defer jm.Stop()

	var countA, countB atomic.Int32
	var wg sync.WaitGroup
	n := 20

	wg.Add(n * 2)

	// Add jobs to queue A
	for i := 0; i < n; i++ {
		jm.AddJob(&testJob{
			executeFn: func() error {
				countA.Add(1)
				// Small sleep to simulate work and allow interleaving
				time.Sleep(time.Millisecond)
				wg.Done()
				return nil
			},
		}, "queue-A")
	}

	// Add jobs to queue B
	for i := 0; i < n; i++ {
		jm.AddJob(&testJob{
			executeFn: func() error {
				countB.Add(1)
				time.Sleep(time.Millisecond)
				wg.Done()
				return nil
			},
		}, "queue-B")
	}

	wg.Wait()
	if countA.Load() != int32(n) {
		t.Fatalf("queue A: expected %d, got %d", n, countA.Load())
	}
	if countB.Load() != int32(n) {
		t.Fatalf("queue B: expected %d, got %d", n, countB.Load())
	}
}

func TestJobManager_WorkerSaturation(t *testing.T) {
	// Saturation limits control how many jobs from a given queue are
	// dispatched concurrently. With 10 workers and 2 queues, the
	// per-queue limit is ceil(0.9 * 10 / 2) = 5.
	// We verify both queues get work dispatched (neither starves).
	jm := NewJobManager("test", 10, nil, nil)
	jm.Start()
	defer jm.Stop()

	var countA, countB atomic.Int32
	var wg sync.WaitGroup

	n := 20
	wg.Add(n * 2)

	// Queue A: slow jobs
	for i := 0; i < n; i++ {
		jm.AddJob(&testJob{
			executeFn: func() error {
				countA.Add(1)
				time.Sleep(5 * time.Millisecond)
				wg.Done()
				return nil
			},
		}, "saturate-A")
	}

	// Queue B: slow jobs too
	for i := 0; i < n; i++ {
		jm.AddJob(&testJob{
			executeFn: func() error {
				countB.Add(1)
				time.Sleep(5 * time.Millisecond)
				wg.Done()
				return nil
			},
		}, "saturate-B")
	}

	wg.Wait()

	// Both queues must have processed all their jobs
	if countA.Load() != int32(n) {
		t.Fatalf("queue A: expected %d, got %d", n, countA.Load())
	}
	if countB.Load() != int32(n) {
		t.Fatalf("queue B: expected %d, got %d", n, countB.Load())
	}
}

func TestJobManager_DynamicQueueAddRemove(t *testing.T) {
	jm := NewJobManager("test", 2, nil, nil)
	jm.Start()
	defer jm.Stop()

	var wg sync.WaitGroup

	// Add jobs to a queue, let them complete (queue gets removed)
	wg.Add(5)
	for i := 0; i < 5; i++ {
		jm.AddJob(&testJob{
			executeFn: func() error {
				wg.Done()
				return nil
			},
		}, "dynamic-queue")
	}
	wg.Wait()

	// Small delay to let queue cleanup happen
	time.Sleep(100 * time.Millisecond)

	// Add more jobs to same queue ID — should recreate the queue
	wg.Add(5)
	for i := 0; i < 5; i++ {
		jm.AddJob(&testJob{
			executeFn: func() error {
				wg.Done()
				return nil
			},
		}, "dynamic-queue")
	}
	wg.Wait()
}

func TestJobManager_StopNoGoroutineLeak(t *testing.T) {
	jm := NewJobManager("test", 4, nil, nil)
	jm.Start()

	var wg sync.WaitGroup
	wg.Add(5)
	for i := 0; i < 5; i++ {
		jm.AddJob(&testJob{
			executeFn: func() error {
				wg.Done()
				return nil
			},
		}, "leak-test")
	}
	wg.Wait()

	// Stop should return without hanging (all goroutines cleaned up)
	done := make(chan struct{})
	go func() {
		jm.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within 5 seconds — possible goroutine leak")
	}
}

func TestJobManager_ConcurrentAddJob(t *testing.T) {
	jm := NewJobManager("test", 4, nil, nil)
	jm.Start()
	defer jm.Stop()

	var total atomic.Int32
	var wg sync.WaitGroup
	n := 100
	wg.Add(n)

	// Add jobs concurrently from multiple goroutines
	for i := 0; i < n; i++ {
		go func(id int) {
			jm.AddJob(&testJob{
				executeFn: func() error {
					total.Add(1)
					wg.Done()
					return nil
				},
			}, "concurrent-queue")
		}(i)
	}

	wg.Wait()
	if got := total.Load(); got != int32(n) {
		t.Fatalf("expected %d jobs executed, got %d", n, got)
	}
}
