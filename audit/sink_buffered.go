package audit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BufferedSink wraps a sink with buffering capabilities
type BufferedSink struct {
	mu          sync.Mutex
	sink        Sink
	buffer      [][]byte
	bufferSize  int
	flushPeriod time.Duration
	done        chan struct{}
	wg          sync.WaitGroup
}

// BufferedSinkConfig contains configuration for buffered sink
type BufferedSinkConfig struct {
	Sink        Sink
	BufferSize  int           // Number of entries to buffer before flushing
	FlushPeriod time.Duration // Time between automatic flushes
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
	
	bs := &BufferedSink{
		sink:        config.Sink,
		buffer:      make([][]byte, 0, config.BufferSize),
		bufferSize:  config.BufferSize,
		flushPeriod: config.FlushPeriod,
		done:        make(chan struct{}),
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
	
	return bs.flushLocked(ctx)
}

// flushLocked flushes the buffer (must be called with lock held)
func (bs *BufferedSink) flushLocked(ctx context.Context) error {
	if len(bs.buffer) == 0 {
		return nil
	}
	
	// Write all buffered entries
	for _, entry := range bs.buffer {
		if err := bs.sink.Write(ctx, entry); err != nil {
			return fmt.Errorf("failed to write buffered entry: %w", err)
		}
	}
	
	// Clear buffer
	bs.buffer = bs.buffer[:0]
	
	return nil
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
				// Log error but continue
				// In production, you might want to use a proper logger
				fmt.Printf("periodic flush error: %v\n", err)
			}
		case <-bs.done:
			return
		}
	}
}

// Close closes the buffered sink
func (bs *BufferedSink) Close() error {
	// Signal periodic flush to stop
	close(bs.done)
	bs.wg.Wait()
	
	// Flush remaining buffer
	ctx := context.Background()
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