// Package fairshare provides a multi-queue fair-sharing job manager with
// round-robin worker dispatch and per-queue saturation limits.
// This replaces the internal github.com/openbao/openbao/helper/fairshare package.
package fairshare

import (
	"fmt"
	"io"
	"sync"

	log "github.com/hashicorp/go-hclog"
)

// Job is an interface for jobs used with the job manager.
type Job interface {
	// Execute performs the work. It should be synchronous.
	Execute() error

	// OnFailure handles the error resulting from a failed Execute().
	OnFailure(err error)
}

type (
	initFn    func()
	cleanupFn func()
)

type wrappedJob struct {
	job     Job
	init    initFn
	cleanup cleanupFn
}

// worker represents a single worker in a pool.
type worker struct {
	name   string
	jobCh  <-chan wrappedJob
	quit   chan struct{}
	logger log.Logger
	wg     *sync.WaitGroup
}

func (w *worker) start() {
	w.wg.Add(1)

	go func() {
		for {
			select {
			case <-w.quit:
				w.wg.Done()
				return
			case wJob := <-w.jobCh:
				if wJob.init != nil {
					wJob.init()
				}

				err := wJob.job.Execute()
				if err != nil {
					wJob.job.OnFailure(err)
				}

				if wJob.cleanup != nil {
					wJob.cleanup()
				}
			}
		}
	}()
}

// dispatcher represents a worker pool.
type dispatcher struct {
	name       string
	numWorkers int
	workers    []worker
	jobCh      chan wrappedJob
	onceStart  sync.Once
	onceStop   sync.Once
	quit       chan struct{}
	logger     log.Logger
	wg         *sync.WaitGroup
}

func newDispatcher(name string, numWorkers int, l log.Logger) *dispatcher {
	if l == nil {
		l = log.New(&log.LoggerOptions{
			Output: io.Discard,
			Level:  log.NoLevel,
		})
	}
	if numWorkers <= 0 {
		numWorkers = 1
		l.Warn("must have 1 or more workers, setting number of workers to 1")
	}

	if name == "" {
		name = "dispatcher"
	}

	var wg sync.WaitGroup
	d := &dispatcher{
		name:       name,
		numWorkers: numWorkers,
		workers:    make([]worker, 0, numWorkers),
		jobCh:      make(chan wrappedJob),
		quit:       make(chan struct{}),
		logger:     l,
		wg:         &wg,
	}

	for i := 0; i < numWorkers; i++ {
		d.workers = append(d.workers, worker{
			name:   fmt.Sprintf("worker-%d", i),
			jobCh:  d.jobCh,
			quit:   d.quit,
			logger: l,
			wg:     &wg,
		})
	}

	d.logger.Trace("created dispatcher", "name", d.name, "num_workers", d.numWorkers)
	return d
}

func (d *dispatcher) dispatch(job Job, init initFn, cleanup cleanupFn) {
	wJob := wrappedJob{
		init:    init,
		job:     job,
		cleanup: cleanup,
	}

	select {
	case d.jobCh <- wJob:
	case <-d.quit:
		d.logger.Info("shutting down during dispatch")
	}
}

func (d *dispatcher) start() {
	d.onceStart.Do(func() {
		d.logger.Trace("starting dispatcher")
		for i := range d.workers {
			d.workers[i].start()
		}
	})
}

func (d *dispatcher) stop() {
	d.onceStop.Do(func() {
		d.logger.Trace("terminating dispatcher")
		close(d.quit)
		d.wg.Wait()
	})
}
