package audit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/stephnangue/warden/logger"
)

const (
	// DefaultCloseTimeout is the maximum time to wait for graceful shutdown
	DefaultCloseTimeout = 10 * time.Second
)

// BufferedSink wraps a sink with buffering capabilities
type BufferedSink struct {
	mu           sync.Mutex
	sink         Sink
	buffer       [][]byte
	bufferSize   int
	flushPeriod  time.Duration
	closeTimeout time.Duration
	done         chan struct{}
	closed       bool // Prevents operations after Close() starts
	wg           sync.WaitGroup
	logger       *logger.GatedLogger
}

// BufferedSinkConfig contains configuration for buffered sink
type BufferedSinkConfig struct {
	Sink         Sink
	BufferSize   int           // Number of entries to buffer before flushing
	FlushPeriod  time.Duration // Time between automatic flushes
	CloseTimeout time.Duration // Maximum time to wait for graceful shutdown
	Logger       *logger.GatedLogger
}

// NewBufferedSink creates a new buffered sink
func NewBufferedSink(config BufferedSinkConfig) (*BufferedSink, error) {
	if config.Sink == nil {
		return nil, fmt.Errorf("sink is required")
	}

	if config.BufferSize <= 0 {
		config.BufferSize = 100
	}

	if config.FlushPeriod <= 0 {
		config.FlushPeriod = 5 * time.Second
	}

	if config.CloseTimeout <= 0 {
		config.CloseTimeout = DefaultCloseTimeout
	}

	bs := &BufferedSink{
		sink:         config.Sink,
		buffer:       make([][]byte, 0, config.BufferSize),
		bufferSize:   config.BufferSize,
		flushPeriod:  config.FlushPeriod,
		closeTimeout: config.CloseTimeout,
		done:         make(chan struct{}),
		logger:       config.Logger,
	}

	// Start periodic flush goroutine
	bs.wg.Add(1)
	go bs.periodicFlush()

	return bs, nil
}

// Write adds an entry to the buffer
func (bs *BufferedSink) Write(ctx context.Context, entry []byte) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return fmt.Errorf("sink is closed")
	}

	// Make a copy of the entry since it might be reused
	entryCopy := make([]byte, len(entry))
	copy(entryCopy, entry)

	bs.buffer = append(bs.buffer, entryCopy)

	// Flush if buffer is full
	if len(bs.buffer) >= bs.bufferSize {
		return bs.flushLocked(ctx)
	}

	return nil
}

// Flush flushes the buffer to the underlying sink
func (bs *BufferedSink) Flush(ctx context.Context) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Allow flush even when closed (needed for final flush during Close)
	return bs.flushLocked(ctx)
}

// flushLocked flushes the buffer (must be called with lock held).
// On partial failure, only successfully written entries are removed from the buffer.
func (bs *BufferedSink) flushLocked(ctx context.Context) error {
	if len(bs.buffer) == 0 {
		return nil
	}

	// Write all buffered entries, tracking how many succeed
	var writeErr error
	successCount := 0
	for _, entry := range bs.buffer {
		if err := bs.sink.Write(ctx, entry); err != nil {
			writeErr = fmt.Errorf("failed to write buffered entry: %w", err)
			break
		}
		successCount++
	}

	// Remove only successfully written entries from buffer
	if successCount > 0 {
		bs.buffer = bs.buffer[successCount:]
	}

	return writeErr
}

// periodicFlush periodically flushes the buffer
func (bs *BufferedSink) periodicFlush() {
	defer bs.wg.Done()

	ticker := time.NewTicker(bs.flushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			if err := bs.Flush(ctx); err != nil {
				if bs.logger != nil {
					bs.logger.Warn("periodic flush error",
						logger.String("sink", bs.sink.Name()),
						logger.Err(err),
					)
				}
			}
		case <-bs.done:
			return
		}
	}
}

// Close closes the buffered sink with a timeout to prevent hanging on shutdown
func (bs *BufferedSink) Close() error {
	// Mark as closed to prevent new writes
	bs.mu.Lock()
	if bs.closed {
		bs.mu.Unlock()
		return nil // Already closed
	}
	bs.closed = true
	bs.mu.Unlock()

	// Signal periodic flush to stop
	close(bs.done)

	// Wait for periodic flush goroutine with timeout
	waitDone := make(chan struct{})
	go func() {
		bs.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// Goroutine stopped gracefully
	case <-time.After(bs.closeTimeout):
		if bs.logger != nil {
			bs.logger.Warn("timeout waiting for periodic flush goroutine to stop",
				logger.String("sink", bs.sink.Name()),
				logger.Duration("timeout", bs.closeTimeout),
			)
		}
	}

	// Flush remaining buffer with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), bs.closeTimeout)
	defer cancel()

	if err := bs.Flush(ctx); err != nil {
		return fmt.Errorf("failed to flush on close: %w", err)
	}

	// Close underlying sink
	return bs.sink.Close()
}

// Name returns the sink name
func (bs *BufferedSink) Name() string {
	return bs.sink.Name()
}

// Type returns the sink type
func (bs *BufferedSink) Type() string {
	return "buffered-" + bs.sink.Type()
}
