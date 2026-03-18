package fairshare

import (
	"container/list"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics/compat"
)

// JobManager manages multiple named queues of jobs and dispatches them to a
// worker pool using round-robin scheduling with per-queue saturation limits.
type JobManager struct {
	name   string
	queues map[string]*list.List

	quit    chan struct{}
	newWork chan struct{} // must be buffered

	workerPool  *dispatcher
	workerCount map[string]int

	onceStart sync.Once
	onceStop  sync.Once

	logger log.Logger

	totalJobs  int
	metricSink metrics.MetricSink

	// waitgroup to synchronize stopping of work scheduling loop
	wg sync.WaitGroup

	// protects queues, workerCount, queuesIndex, lastQueueAccessed
	l sync.RWMutex

	// track queues by index for round robin worker assignment
	queuesIndex       []string
	lastQueueAccessed int
}

// NewJobManager creates a job manager with the given name and number of workers.
// An optional metrics.MetricSink can be provided for instrumentation (nil to disable).
func NewJobManager(name string, numWorkers int, l log.Logger, metricSink metrics.MetricSink) *JobManager {
	if l == nil {
		l = log.New(&log.LoggerOptions{
			Output: io.Discard,
			Level:  log.NoLevel,
		})
	}
	if name == "" {
		name = "jobmanager"
	}

	wp := newDispatcher(fmt.Sprintf("%s-dispatcher", name), numWorkers, l)

	j := &JobManager{
		name:              name,
		queues:            make(map[string]*list.List),
		quit:              make(chan struct{}),
		newWork:           make(chan struct{}, 1),
		workerPool:        wp,
		workerCount:       make(map[string]int),
		logger:            l,
		metricSink:        metricSink,
		queuesIndex:       make([]string, 0),
		lastQueueAccessed: -1,
	}

	j.logger.Trace("created job manager", "name", name, "pool_size", numWorkers)
	return j
}

// Start starts the job manager.
// Note: a given job manager cannot be restarted after it has been stopped.
func (j *JobManager) Start() {
	j.onceStart.Do(func() {
		j.logger.Trace("starting job manager", "name", j.name)
		j.workerPool.start()
		j.assignWork()
	})
}

// Stop stops the job manager, waiting for all workers to exit.
func (j *JobManager) Stop() {
	j.onceStop.Do(func() {
		j.logger.Trace("terminating job manager...")
		close(j.quit)
		j.wg.Wait()
		j.workerPool.stop()
	})
}

// AddJob adds a job to the given queue, creating the queue if it doesn't exist.
func (j *JobManager) AddJob(job Job, queueID string) {
	j.l.Lock()
	if len(j.queues) == 0 {
		defer func() {
			// newWork must be buffered to avoid deadlocks if work is added
			// before the job manager is started
			j.newWork <- struct{}{}
		}()
	}
	defer j.l.Unlock()

	if _, ok := j.queues[queueID]; !ok {
		j.addQueue(queueID)
	}

	j.queues[queueID].PushBack(job)
	j.totalJobs++

	if j.metricSink != nil {
		j.metricSink.SetGaugeWithLabels([]string{j.name, "job_manager", "queue_length"}, float32(j.queues[queueID].Len()), []metrics.Label{{Name: "queue_id", Value: queueID}})
		j.metricSink.SetGauge([]string{j.name, "job_manager", "total_jobs"}, float32(j.totalJobs))
	}
}

// GetPendingJobCount returns the total number of pending jobs in the job manager.
func (j *JobManager) GetPendingJobCount() int {
	j.l.RLock()
	defer j.l.RUnlock()

	cnt := 0
	for _, q := range j.queues {
		cnt += q.Len()
	}

	return cnt
}

// GetWorkerCounts returns a map of queue ID to number of active workers.
func (j *JobManager) GetWorkerCounts() map[string]int {
	j.l.RLock()
	defer j.l.RUnlock()
	return j.workerCount
}

// GetWorkQueueLengths returns a map of queue ID to number of jobs in the queue.
func (j *JobManager) GetWorkQueueLengths() map[string]int {
	out := make(map[string]int)

	j.l.RLock()
	defer j.l.RUnlock()

	for k, v := range j.queues {
		out[k] = v.Len()
	}

	return out
}

// getNextJob pops the next job to be processed and prunes empty queues.
// It also returns the ID of the queue the job is associated with.
func (j *JobManager) getNextJob() (Job, string) {
	j.l.Lock()
	defer j.l.Unlock()

	if len(j.queues) == 0 {
		return nil, ""
	}

	queueID, canAssignWorker := j.getNextQueue()
	if !canAssignWorker {
		return nil, ""
	}

	jobElement := j.queues[queueID].Front()
	jobRaw := j.queues[queueID].Remove(jobElement)

	j.totalJobs--

	if j.metricSink != nil {
		j.metricSink.SetGaugeWithLabels([]string{j.name, "job_manager", "queue_length"}, float32(j.queues[queueID].Len()), []metrics.Label{{Name: "queue_id", Value: queueID}})
		j.metricSink.SetGauge([]string{j.name, "job_manager", "total_jobs"}, float32(j.totalJobs))
	}

	if j.queues[queueID].Len() == 0 {
		// remove the empty queue, but keep worker count tracking
		// in case we are still working on previous jobs from this queue.
		j.removeLastQueueAccessed()
	}

	return jobRaw.(Job), queueID
}

// getNextQueue returns the next queue to assign work from using round-robin.
// note: must be called with j.l held
func (j *JobManager) getNextQueue() (string, bool) {
	var nextQueue string
	var canAssignWorker bool

	queueIdx := j.nextQueueIndex(j.lastQueueAccessed)
	for i := 0; i < len(j.queuesIndex); i++ {
		potentialQueueID := j.queuesIndex[queueIdx]

		if !j.queueWorkersSaturated(potentialQueueID) {
			nextQueue = potentialQueueID
			canAssignWorker = true
			j.lastQueueAccessed = queueIdx
			break
		}

		queueIdx = j.nextQueueIndex(queueIdx)
	}

	return nextQueue, canAssignWorker
}

// nextQueueIndex returns the index of the next queue in round-robin order.
// note: must be called with j.l held
func (j *JobManager) nextQueueIndex(currentIdx int) int {
	return (currentIdx + 1) % len(j.queuesIndex)
}

// queueWorkersSaturated returns true if there are already too many workers on this queue.
// note: must be called with j.l held (at least for read).
func (j *JobManager) queueWorkersSaturated(queueID string) bool {
	numActiveQueues := float64(len(j.queues))
	numTotalWorkers := float64(j.workerPool.numWorkers)
	maxWorkersPerQueue := math.Ceil(0.9 * numTotalWorkers / numActiveQueues)

	return j.workerCount[queueID] >= int(maxWorkersPerQueue)
}

func (j *JobManager) incrementWorkerCount(queueID string) {
	j.l.Lock()
	defer j.l.Unlock()
	j.workerCount[queueID]++
}

func (j *JobManager) decrementWorkerCount(queueID string) {
	j.l.Lock()
	defer j.l.Unlock()

	j.workerCount[queueID]--

	_, queueExists := j.queues[queueID]
	if !queueExists && j.workerCount[queueID] < 1 {
		delete(j.workerCount, queueID)
	}
}

// assignWork continually checks for new jobs and dispatches them to the worker pool.
func (j *JobManager) assignWork() {
	j.wg.Add(1)

	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			for {
				select {
				case <-j.quit:
					j.wg.Done()
					return
				case <-j.newWork:
					// keep the channel empty since we're already processing work
				default:
				}

				job, queueID := j.getNextJob()
				if job != nil {
					j.workerPool.dispatch(job,
						func() {
							j.incrementWorkerCount(queueID)
						},
						func() {
							j.decrementWorkerCount(queueID)
						})
				} else {
					break
				}
			}

			ticker.Reset(50 * time.Millisecond)
			select {
			case <-j.quit:
				j.wg.Done()
				return
			case <-j.newWork:
			case <-ticker.C:
			}
		}
	}()
}

// addQueue generates a new queue if one doesn't exist for queueID.
// note: must be called with j.l held for write
func (j *JobManager) addQueue(queueID string) {
	if _, ok := j.queues[queueID]; !ok {
		j.queues[queueID] = list.New()
		j.queuesIndex = append(j.queuesIndex, queueID)
	}

	if _, ok := j.workerCount[queueID]; !ok {
		j.workerCount[queueID] = 0
	}
}

// removeLastQueueAccessed removes the queue and index tracker for the last queue accessed.
// note: must be called with j.l held.
func (j *JobManager) removeLastQueueAccessed() {
	if j.lastQueueAccessed == -1 || j.lastQueueAccessed > len(j.queuesIndex)-1 {
		j.logger.Warn("call to remove queue out of bounds", "idx", j.lastQueueAccessed)
		return
	}

	queueID := j.queuesIndex[j.lastQueueAccessed]

	delete(j.queues, queueID)

	j.queuesIndex = append(j.queuesIndex[:j.lastQueueAccessed], j.queuesIndex[j.lastQueueAccessed+1:]...)

	if j.lastQueueAccessed > 0 {
		j.lastQueueAccessed--
	} else {
		j.lastQueueAccessed = len(j.queuesIndex) - 1
	}
}
