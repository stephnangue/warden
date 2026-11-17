package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	writes  int
	limited bool
	budget  int
}

// writeCount is how many writes the file has received.
func (f *flakyFile) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

func (f *flakyFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
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

// A write the disk cuts short leaves the start of an entry in the file. The
// entry is kept and written again whole, on a line of its own: the fragment is
// ended first, and is the one line a JSON parser cannot read. Written straight
// after the fragment, as it used to be, the entry was lost with it.
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
	if got, want := file.content(), sinkLines(1, 1)+fragment+"\n"+sinkLines(2, 3); got != want {
		t.Errorf("file after recovery:\n got %q\nwant %q", got, want)
	}
}

// A sink whose last flush fails is closed all the same, and says how many
// entries it could not write. Left open, its file stayed beside the one the
// next device opened for the same path, and the entries went unreported.
func TestBufferedSink_CloseWhenTheLastFlushFails(t *testing.T) {
	fileSink, err := NewFileSink(FileSinkConfig{Path: filepath.Join(t.TempDir(), "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	realFile := fileSink.file
	file := &flakyFile{}
	fileSink.writer = file
	sink, err := NewBufferedSink(BufferedSinkConfig{Sink: fileSink, BufferSize: 10, FlushPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	file.accept(0)
	for n := 1; n <= 2; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	err = sink.Close()
	if !errors.Is(err, errDiskFull) || !strings.Contains(err.Error(), "2 entries are not written") {
		t.Errorf("Close: got %v, want the flush failure and the 2 entries it leaves", err)
	}
	if _, err := realFile.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("the file is still open after Close: writing to it gave %v", err)
	}
}

// A flush hands a file its whole buffer in one write, where it used to make
// one per entry while every request waited for the buffer.
func TestBufferedSink_OneWritePerFlush(t *testing.T) {
	sink, file := newFlakySink(t, 50)
	ctx := context.Background()

	for n := 1; n <= 125; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := file.content(), sinkLines(1, 125); got != want {
		t.Errorf("file:\n got %q\nwant %q", got, want)
	}
	// Two full buffers, and the flush of what was left.
	if got := file.writeCount(); got != 3 {
		t.Errorf("%d writes for 125 entries buffered by 50, want 3", got)
	}
}

// A buffer of one entry writes each entry as it comes: what a device set that
// way is for, to show an entry as soon as it is made.
func TestBufferedSink_BufferOfOne(t *testing.T) {
	sink, file := newFlakySink(t, 1)
	ctx := context.Background()

	for n := 1; n <= 3; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
		if got, want := file.content(), sinkLines(1, n); got != want {
			t.Fatalf("file after entry %d:\n got %q\nwant %q", n, got, want)
		}
	}
}

// entrySink is a sink that takes one entry per write, like a syslog or a
// socket. It keeps the entries it was given and refuses the one numbered
// failOn.
type entrySink struct {
	discardSink
	entries []string
	failOn  int
}

func (s *entrySink) Write(_ context.Context, entry []byte) error {
	if s.failOn != 0 && string(entry) == string(sinkEntry(s.failOn)) {
		return errDiskFull
	}
	s.entries = append(s.entries, string(entry))
	return nil
}

// A sink that takes no batch is written one entry at a time, each as it was
// given, with no newline added; one it refuses stays buffered with those after
// it.
func TestBufferedSink_SinkWithoutBatches(t *testing.T) {
	inner := &entrySink{failOn: 3}
	sink, err := NewBufferedSink(BufferedSinkConfig{Sink: inner, BufferSize: 4, FlushPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	ctx := context.Background()
	entries := func(from, to int) []string {
		var out []string
		for n := from; n <= to; n++ {
			out = append(out, string(sinkEntry(n)))
		}
		return out
	}

	for n := 1; n <= 3; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	if err := sink.Write(ctx, sinkEntry(4)); !errors.Is(err, errDiskFull) {
		t.Fatalf("the write that flushed: got %v, want the sink's refusal", err)
	}
	if got, want := inner.entries, entries(1, 2); !slices.Equal(got, want) {
		t.Fatalf("entries the sink took: %q, want %q", got, want)
	}

	inner.failOn = 0
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := inner.entries, entries(1, 4); !slices.Equal(got, want) {
		t.Errorf("entries the sink took: %q, want %q", got, want)
	}
}

// A write cut just before an entry's newline leaves the whole entry in the
// file. It is written: the newline is added before anything follows, and the
// entry is not written a second time.
func TestBufferedSink_WriteCutBeforeTheNewline(t *testing.T) {
	sink, file := newFlakySink(t, 3)
	ctx := context.Background()

	file.accept(len(sinkLines(1, 2)) - len("\n"))
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
	if got, want := file.content(), sinkLines(1, 3); got != want {
		t.Errorf("file after recovery:\n got %q\nwant %q", got, want)
	}
}

// appendingSink is a sink that frames an entry by appending to it, as the
// file and socket sinks do, and keeps what it would send.
type appendingSink struct {
	discardSink
	sent []string
}

func (s *appendingSink) Write(_ context.Context, entry []byte) error {
	s.sent = append(s.sent, string(append(entry, "\r\n"...)))
	return nil
}

// A sink written one entry at a time may append to the entry it is handed.
// The entry lies in the buffer, with the next one after it: the sink is given
// no room to write over that one.
func TestBufferedSink_SinkThatAppendsToItsEntry(t *testing.T) {
	inner := &appendingSink{}
	sink, err := NewBufferedSink(BufferedSinkConfig{Sink: inner, BufferSize: 3, FlushPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	for n := 1; n <= 3; n++ {
		if err := sink.Write(context.Background(), sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	want := []string{string(sinkEntry(1)) + "\r\n", string(sinkEntry(2)) + "\r\n", string(sinkEntry(3)) + "\r\n"}
	if !slices.Equal(inner.sent, want) {
		t.Errorf("the sink was handed %q, want %q", inner.sent, want)
	}
}

// batchDiscardSink is a sink that takes batches and keeps nothing.
type batchDiscardSink struct{ discardSink }

func (batchDiscardSink) WriteBatch(_ context.Context, batch []byte) (int, error) {
	return len(batch), nil
}

// Accepting an entry allocates nothing once the buffer has grown to its size:
// the entry is copied into it, and a flush empties it without letting it go.
func TestBufferedSink_AllocatesNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	sink, err := NewBufferedSink(BufferedSinkConfig{Sink: batchDiscardSink{}, BufferSize: 10, FlushPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	ctx := context.Background()
	entry := sinkEntry(1)

	// Fifteen entries a run: every run flushes, and starts with the buffer at
	// a different level.
	got := testing.AllocsPerRun(100, func() {
		for range 15 {
			sink.Write(ctx, entry)
		}
	})
	if got != 0 {
		t.Errorf("%v allocations for 15 entries, want none", got)
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
