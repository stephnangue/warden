package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBufferedSink(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	fileSink, err := NewFileSink(FileSinkConfig{
		Path: logPath,
	})
	if err != nil {
		t.Fatalf("Failed to create file sink: %v", err)
	}

	bufferedSink, err := NewBufferedSink(BufferedSinkConfig{
		Sink:        fileSink,
		BufferSize:  10,
		FlushPeriod: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create buffered sink: %v", err)
	}
	defer bufferedSink.Close()

	ctx := context.Background()

	// Write several entries
	for i := 0; i < 5; i++ {
		data := []byte(`{"entry":"` + string(rune(i)) + `"}`)
		if err := bufferedSink.Write(ctx, data); err != nil {
			t.Errorf("Failed to write entry %d: %v", i, err)
		}
	}

	// Wait for periodic flush
	time.Sleep(200 * time.Millisecond)

	// Verify file contains data
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Errorf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty after buffered writes")
	}
}

func TestBufferedSinkNameAndType(t *testing.T) {
	tmpDir := t.TempDir()
	fileSink, err := NewFileSink(FileSinkConfig{Path: filepath.Join(tmpDir, "audit.log")})
	if err != nil {
		t.Fatalf("NewFileSink failed: %v", err)
	}

	bs, err := NewBufferedSink(BufferedSinkConfig{Sink: fileSink})
	if err != nil {
		t.Fatalf("NewBufferedSink failed: %v", err)
	}
	defer bs.Close()

	if bs.Name() == "" {
		t.Error("expected non-empty name")
	}
	if bs.Type() != "buffered-file" {
		t.Errorf("expected buffered-file, got %s", bs.Type())
	}
}

// errDiskFull is what flakyFile fails with.
var errDiskFull = errors.New("no space left on device")

// flakyFile stands in for the audit file. It keeps what is written to it and
// accepts only as many bytes as its budget allows: the write that exceeds the
// budget keeps the bytes that fit and fails, as a write to a full disk does.
type flakyFile struct {
	mu      sync.Mutex
	out     bytes.Buffer
	limited bool
	budget  int
}

func (f *flakyFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.limited {
		return f.out.Write(p)
	}
	n := min(len(p), f.budget)
	f.out.Write(p[:n])
	f.budget -= n
	if n < len(p) {
		return n, errDiskFull
	}
	return n, nil
}

// accept lets n more bytes through before writes fail.
func (f *flakyFile) accept(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.limited, f.budget = true, n
}

// recover lets every write through again.
func (f *flakyFile) recover() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.limited = false
}

func (f *flakyFile) content() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.String()
}

// newFlakySink returns a buffered file sink that flushes every bufferSize
// entries, and the file it writes to. Its periodic flush never fires within a
// test, so every flush is one the test asked for.
func newFlakySink(t *testing.T, bufferSize int) (*BufferedSink, *flakyFile) {
	t.Helper()
	fileSink, err := NewFileSink(FileSinkConfig{Path: filepath.Join(t.TempDir(), "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	file := &flakyFile{}
	fileSink.writer = file
	sink, err := NewBufferedSink(BufferedSinkConfig{Sink: fileSink, BufferSize: bufferSize, FlushPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	return sink, file
}

// sinkEntry is the n-th entry a test writes.
func sinkEntry(n int) []byte {
	return []byte(fmt.Sprintf(`{"n":%d}`, n))
}

// sinkLines is the file content that holds entries from..to, one per line.
func sinkLines(from, to int) string {
	var b strings.Builder
	for n := from; n <= to; n++ {
		b.Write(sinkEntry(n))
		b.WriteByte('\n')
	}
	return b.String()
}

// The write that fills the buffer flushes it, and is the one told when the
// flush fails. While the file keeps failing every write is refused, so the
// request behind it is too; every entry is kept all the same, and written in
// order, once, by the first write after the file recovers.
func TestBufferedSink_FlushFailure(t *testing.T) {
	sink, file := newFlakySink(t, 3)
	ctx := context.Background()

	file.accept(0)
	for n := 1; n <= 2; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d, below the buffer size, was refused: %v", n, err)
		}
	}
	for n := 3; n <= 4; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); !errors.Is(err, errDiskFull) {
			t.Fatalf("entry %d: got %v, want the flush failure", n, err)
		}
	}
	if got := file.content(); got != "" {
		t.Fatalf("written while the file was failing: %q", got)
	}

	file.recover()
	if err := sink.Write(ctx, sinkEntry(5)); err != nil {
		t.Fatalf("first write after recovery: %v", err)
	}
	if got, want := file.content(), sinkLines(1, 5); got != want {
		t.Errorf("file after recovery:\n got %q\nwant %q", got, want)
	}
}

// A flush that fails part-way removes the entries it wrote and keeps the
// rest, so the next flush writes each remaining entry once.
func TestBufferedSink_FlushFailsPartWay(t *testing.T) {
	sink, file := newFlakySink(t, 4)
	ctx := context.Background()

	file.accept(len(sinkLines(1, 2)))
	for n := 1; n <= 3; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	if err := sink.Write(ctx, sinkEntry(4)); !errors.Is(err, errDiskFull) {
		t.Fatalf("the write that flushed: got %v, want the flush failure", err)
	}
	if got, want := file.content(), sinkLines(1, 2); got != want {
		t.Fatalf("file after the failed flush:\n got %q\nwant %q", got, want)
	}

	file.recover()
	if err := sink.Flush(ctx); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if got, want := file.content(), sinkLines(1, 4); got != want {
		t.Errorf("file after recovery:\n got %q\nwant %q", got, want)
	}
}

// A flush asked for while the file fails reports the failure and keeps the
// entries. This is the periodic flush's case: it logs the error and the
// writers below the buffer size are not refused.
func TestBufferedSink_FailedFlushKeepsEntries(t *testing.T) {
	sink, file := newFlakySink(t, 10)
	ctx := context.Background()

	file.accept(0)
	for n := 1; n <= 2; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	if err := sink.Flush(ctx); !errors.Is(err, errDiskFull) {
		t.Fatalf("flush: got %v, want the failure", err)
	}
	if err := sink.Write(ctx, sinkEntry(3)); err != nil {
		t.Fatalf("a write below the buffer size was refused after a failed flush: %v", err)
	}

	file.recover()
	if err := sink.Flush(ctx); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if got, want := file.content(), sinkLines(1, 3); got != want {
		t.Errorf("file after recovery:\n got %q\nwant %q", got, want)
	}
}

// A write the disk cuts short leaves the start of the entry in the file. The
// entry is kept and written again whole, but straight after that fragment: the
// two share a line no JSON parser reads, so the entry is lost to whoever reads
// the log.
func TestBufferedSink_ShortWrite(t *testing.T) {
	sink, file := newFlakySink(t, 3)
	ctx := context.Background()

	const fragment = `{"n"`
	file.accept(len(sinkLines(1, 1)) + len(fragment))
	for n := 1; n <= 2; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	if err := sink.Write(ctx, sinkEntry(3)); !errors.Is(err, errDiskFull) {
		t.Fatalf("the write that flushed: got %v, want the flush failure", err)
	}

	file.recover()
	if err := sink.Flush(ctx); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if got, want := file.content(), sinkLines(1, 1)+fragment+sinkLines(2, 3); got != want {
		t.Errorf("file after recovery:\n got %q\nwant %q", got, want)
	}
}

// Closing writes what is still buffered, and a closed sink refuses writes.
func TestBufferedSink_CloseFlushes(t *testing.T) {
	sink, file := newFlakySink(t, 10)
	ctx := context.Background()

	for n := 1; n <= 2; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	if got := file.content(); got != "" {
		t.Fatalf("written before the buffer filled: %q", got)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got, want := file.content(), sinkLines(1, 2); got != want {
		t.Errorf("file after close:\n got %q\nwant %q", got, want)
	}
	if err := sink.Write(ctx, sinkEntry(3)); err == nil {
		t.Error("a closed sink accepted a write")
	}
}

// Writers sharing a sink lose no entry, write none twice, and each finds its
// own entries in the file in the order it wrote them: a request's entry comes
// before its response's.
func TestBufferedSink_ConcurrentWriters(t *testing.T) {
	const writers, perWriter = 8, 250
	sink, file := newFlakySink(t, 7)
	ctx := context.Background()

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < perWriter; n++ {
				if err := sink.Write(ctx, []byte(fmt.Sprintf("%d %d", w, n))); err != nil {
					t.Errorf("writer %d, entry %d: %v", w, n, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(file.content(), "\n"), "\n")
	if len(lines) != writers*perWriter {
		t.Fatalf("%d lines in the file, want %d", len(lines), writers*perWriter)
	}
	next := make([]int, writers)
	for _, line := range lines {
		var w, n int
		if _, err := fmt.Sscanf(line, "%d %d", &w, &n); err != nil || w < 0 || w >= writers {
			t.Fatalf("unreadable line %q", line)
		}
		if n != next[w] {
			t.Fatalf("writer %d: found entry %d where %d was due", w, n, next[w])
		}
		next[w]++
	}
}
