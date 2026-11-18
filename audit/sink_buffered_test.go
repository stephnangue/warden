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

// gate is what a gatedSink is told to do with the write it holds: take the
// whole batch, or only its first take bytes and fail with err.
type gate struct {
	take int
	err  error
}

// gatedSink is a batch sink that holds each write until it is told what to do
// with it, and keeps what it wrote. It says on started when a write begins.
type gatedSink struct {
	discardSink
	started chan struct{}
	gates   chan gate

	mu  sync.Mutex
	out bytes.Buffer
}

func newGatedSink() *gatedSink {
	return &gatedSink{started: make(chan struct{}, 16), gates: make(chan gate, 16)}
}

func (s *gatedSink) WriteBatch(_ context.Context, batch []byte) (int, error) {
	s.started <- struct{}{}
	g := <-s.gates
	n := len(batch)
	if g.err != nil {
		n = g.take
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(batch[:n])
	return n, g.err
}

func (s *gatedSink) content() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.String()
}

// newGatedBufferedSink is a buffered sink of bufferSize entries over a gated
// sink.
func newGatedBufferedSink(t *testing.T, bufferSize int) (*BufferedSink, *gatedSink) {
	t.Helper()
	inner := newGatedSink()
	sink, err := NewBufferedSink(BufferedSinkConfig{
		Sink: inner, BufferSize: bufferSize, FlushPeriod: time.Hour, CloseTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Let through whatever the test left held or buffered.
		for range cap(inner.gates) - len(inner.gates) {
			inner.gates <- gate{}
		}
		sink.Close()
	})
	return sink, inner
}

// attempt waits for the sink to begin a write, which it holds until told what
// to do with it.
func (s *gatedSink) attempt(t *testing.T, what string) {
	t.Helper()
	select {
	case <-s.started:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: the sink was not written to", what)
	}
}

// writeInBackground writes entry n and returns where its result will come.
func writeInBackground(sink *BufferedSink, n int) <-chan error {
	done := make(chan error, 1)
	go func() { done <- sink.Write(context.Background(), sinkEntry(n)) }()
	return done
}

// within returns what comes on done, or fails the test if nothing does: the
// write is stuck behind something it should not wait for.
func within(t *testing.T, done <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
		return nil
	}
}

// Entries are accepted while a flush writes to the file: a request's entry
// waits for the copy of another, not for the disk.
func TestBufferedSink_AcceptsEntriesWhileFlushing(t *testing.T) {
	sink, file := newGatedBufferedSink(t, 3)
	ctx := context.Background()

	for n := 1; n <= 2; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	flushing := writeInBackground(sink, 3)
	<-file.started

	// The file has the first three entries and has not returned.
	for n := 4; n <= 5; n++ {
		if err := within(t, writeInBackground(sink, n), "a write during the flush"); err != nil {
			t.Fatalf("entry %d, written during the flush: %v", n, err)
		}
	}

	file.gates <- gate{}
	if err := within(t, flushing, "the write that flushed"); err != nil {
		t.Fatalf("the write that flushed: %v", err)
	}
	file.gates <- gate{}
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := file.content(), sinkLines(1, 5); got != want {
		t.Errorf("file:\n got %q\nwant %q", got, want)
	}
}

// A file slower than its writers holds them back: the writer that fills the
// buffer again waits for the flush in progress, then flushes in its turn. The
// buffer does not grow without limit behind a slow disk.
func TestBufferedSink_SlowFileHoldsWritersBack(t *testing.T) {
	sink, file := newGatedBufferedSink(t, 2)
	ctx := context.Background()

	if err := sink.Write(ctx, sinkEntry(1)); err != nil {
		t.Fatal(err)
	}
	first := writeInBackground(sink, 2)
	<-file.started

	if err := within(t, writeInBackground(sink, 3), "a write below the buffer size, during the flush"); err != nil {
		t.Fatalf("entry 3, below the buffer size: %v", err)
	}
	second := writeInBackground(sink, 4)

	file.gates <- gate{}
	if err := within(t, first, "the first flush"); err != nil {
		t.Fatalf("the first flush: %v", err)
	}
	// The writer that filled the buffer again flushes in its turn: its write
	// is the one the file now holds, and it has not returned.
	file.attempt(t, "the second flush")
	select {
	case err := <-second:
		t.Fatalf("the write that filled the buffer again returned (%v) while the file held its flush", err)
	default:
	}
	file.gates <- gate{}
	if err := within(t, second, "the second flush"); err != nil {
		t.Fatalf("the second flush: %v", err)
	}
	if got, want := file.content(), sinkLines(1, 4); got != want {
		t.Errorf("file:\n got %q\nwant %q", got, want)
	}
}

// Entries a failed flush could not write go back in front of those accepted
// while it was writing: the file holds them in the order they were accepted,
// whether the flush wrote nothing or part of its batch.
func TestBufferedSink_FailedFlushKeepsOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		taken int // entries the failing write takes before it fails
	}{
		{"nothing written", 0},
		{"one entry written", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink, file := newGatedBufferedSink(t, 3)
			ctx := context.Background()

			for n := 1; n <= 2; n++ {
				if err := sink.Write(ctx, sinkEntry(n)); err != nil {
					t.Fatalf("entry %d: %v", n, err)
				}
			}
			flushing := writeInBackground(sink, 3)
			<-file.started
			if err := within(t, writeInBackground(sink, 4), "a write during the flush"); err != nil {
				t.Fatalf("entry 4, written during the flush: %v", err)
			}

			file.gates <- gate{take: len(sinkLines(1, tc.taken)), err: errDiskFull}
			if err := within(t, flushing, "the write that flushed"); !errors.Is(err, errDiskFull) {
				t.Fatalf("the write that flushed: got %v, want the failure", err)
			}
			if got, want := file.content(), sinkLines(1, tc.taken); got != want {
				t.Fatalf("file after the failed flush:\n got %q\nwant %q", got, want)
			}

			file.gates <- gate{}
			if err := sink.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			if got, want := file.content(), sinkLines(1, 4); got != want {
				t.Errorf("file:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// While its file fails, a sink keeps the entries it could not write, up to
// twice its buffer size; past that an entry is dropped, and the write refused
// as the ones before it were. A file that fails for long no longer takes the
// memory of the process. What was kept is written when the file recovers, in
// order; the server log says when entries started to be dropped and how many
// were.
func TestBufferedSink_BoundWhileFailing(t *testing.T) {
	fileSink, err := NewFileSink(FileSinkConfig{Path: filepath.Join(t.TempDir(), "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	file := &flakyFile{}
	fileSink.writer = file
	log, serverLog := serverLogger()
	sink, err := NewBufferedSink(BufferedSinkConfig{Sink: fileSink, BufferSize: 3, FlushPeriod: time.Hour, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	ctx := context.Background()

	file.accept(0)
	for n := 1; n <= 2; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d, below the buffer size: %v", n, err)
		}
	}
	// Refused and kept: the buffer holds up to six entries.
	for n := 3; n <= 6; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); !errors.Is(err, errDiskFull) || strings.Contains(err.Error(), "dropped") {
			t.Fatalf("entry %d: got %v, want the flush failure, the entry kept", n, err)
		}
	}
	// Refused and dropped.
	for n := 7; n <= 9; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); !errors.Is(err, errDiskFull) || !strings.Contains(err.Error(), "dropped") {
			t.Fatalf("entry %d: got %v, want the entry dropped", n, err)
		}
	}
	if got := strings.Count(serverLog.String(), "entries are dropped"); got != 1 {
		t.Errorf("dropping was reported %d times for 3 entries, want once: %s", got, serverLog)
	}

	file.recover()
	if err := sink.Write(ctx, sinkEntry(10)); err != nil {
		t.Fatalf("first write after recovery: %v", err)
	}
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := file.content(), sinkLines(1, 6)+sinkLines(10, 10); got != want {
		t.Errorf("file after recovery:\n got %q\nwant %q", got, want)
	}
	plain := terminalColours.ReplaceAllString(serverLog.String(), "")
	if strings.Count(plain, "audit sink recovered") != 1 || !strings.Contains(plain, "entries_dropped=3") {
		t.Errorf("want one report of the recovery, with 3 entries dropped: %s", plain)
	}
}

// A buffer at its bound behind a file that is only slow drops nothing: the
// writers wait for the file. A device with a buffer of one entry reaches its
// bound with three requests at once.
func TestBufferedSink_BoundDoesNotDropBehindASlowFile(t *testing.T) {
	sink, file := newGatedBufferedSink(t, 1)
	defer sink.Close()

	const writers = 6
	results := make([]<-chan error, 0, writers)
	results = append(results, writeInBackground(sink, 1))
	<-file.started
	for n := 2; n <= writers; n++ {
		results = append(results, writeInBackground(sink, n))
	}
	// Wait for the sink to hold as many entries as it may behind the held
	// write: the writers after that are at the bound.
	for deadline := time.Now().Add(5 * time.Second); sink.held() < maxBufferedFactor*1; {
		if time.Now().After(deadline) {
			t.Fatalf("the sink holds %d entries, the bound was not reached", sink.held())
		}
		time.Sleep(time.Millisecond)
	}

	// Every write goes through, however the entries were shared out.
	for range writers {
		file.gates <- gate{}
	}
	for n, result := range results {
		if err := within(t, result, "a write behind the slow file"); err != nil {
			t.Errorf("entry %d: %v", n+1, err)
		}
	}
	got := strings.Split(strings.TrimSuffix(file.content(), "\n"), "\n")
	slices.Sort(got)
	want := strings.Split(strings.TrimSuffix(sinkLines(1, writers), "\n"), "\n")
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("entries in the file: %q, want each of %q once", got, want)
	}
}

// While its file fails with the buffer full, a sink refuses every writer and
// holds no more than its bound, however the writers overlap. A writer that
// comes while another's attempt is in progress finds the buffer empty, the
// entries being with the file for as long as the attempt lasts: it is not let
// through for that, it makes its own attempt and is told. Counting only what
// was buffered, a sink accepted such writers for the whole outage, and grew
// without limit.
func TestBufferedSink_FailingSinkRefusesOverlappingWriters(t *testing.T) {
	sink, file := newGatedBufferedSink(t, 3)
	ctx := context.Background()
	const bound = maxBufferedFactor * 3
	failed := gate{err: errDiskFull}
	holds := func(want int) {
		t.Helper()
		if got := sink.held(); got != want {
			t.Fatalf("the sink holds %d entries, want %d", got, want)
		}
	}

	for n := 1; n <= 2; n++ {
		if err := sink.Write(ctx, sinkEntry(n)); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
	// The first flush to fail. Nothing says yet that the file fails: a writer
	// that comes meanwhile is accepted, its entry kept.
	third := writeInBackground(sink, 3)
	file.attempt(t, "the first flush")
	if err := within(t, writeInBackground(sink, 4), "a write during the first flush"); err != nil {
		t.Fatalf("entry 4, written before any flush had failed: %v", err)
	}
	file.gates <- failed
	if err := within(t, third, "the write that flushed"); !errors.Is(err, errDiskFull) {
		t.Fatalf("entry 3: got %v, want the flush failure", err)
	}
	holds(4)

	// From here the file is known to fail. Entry 5's attempt is in progress,
	// the buffer empty, when entry 6 comes: it waits, makes its own attempt,
	// and is refused. Both entries are kept.
	fifth := writeInBackground(sink, 5)
	file.attempt(t, "entry 5's flush")
	sixth := writeInBackground(sink, 6)
	// Entry 6 is in the buffer, entry 5's attempt still held.
	for deadline := time.Now().Add(5 * time.Second); sink.held() < bound; {
		if time.Now().After(deadline) {
			t.Fatalf("the sink holds %d entries: entry 6 was not accepted during entry 5's flush", sink.held())
		}
		time.Sleep(time.Millisecond)
	}
	file.gates <- failed
	if err := within(t, fifth, "entry 5"); !errors.Is(err, errDiskFull) {
		t.Fatalf("entry 5: got %v, want the flush failure", err)
	}
	file.attempt(t, "entry 6's own flush")
	file.gates <- failed
	if err := within(t, sixth, "entry 6"); !errors.Is(err, errDiskFull) || strings.Contains(err.Error(), "dropped") {
		t.Fatalf("entry 6: got %v, want the flush failure, the entry kept", err)
	}
	holds(bound)

	// At the bound, the same overlap: entry 8 comes while entry 7's attempt
	// holds every entry. Both are dropped, and the sink holds no more.
	seventh := writeInBackground(sink, 7)
	file.attempt(t, "entry 7's flush")
	eighth := writeInBackground(sink, 8)
	// Nothing shows that entry 8 has reached the sink: a writer at the bound
	// waits without changing it. The pause makes the overlap likely; without
	// it the test still passes, having shown less.
	time.Sleep(20 * time.Millisecond)
	holds(bound)
	file.gates <- failed
	if err := within(t, seventh, "entry 7"); !errors.Is(err, errDiskFull) || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("entry 7: got %v, want the entry dropped", err)
	}
	file.attempt(t, "entry 8's own flush")
	file.gates <- failed
	if err := within(t, eighth, "entry 8"); !errors.Is(err, errDiskFull) || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("entry 8: got %v, want the entry dropped", err)
	}
	holds(bound)
	if got := file.content(); got != "" {
		t.Fatalf("written while the file was failing: %q", got)
	}

	// The file recovers: what was kept is written, in order, and the entry
	// that found it so is accepted.
	file.gates <- gate{}
	if err := within(t, writeInBackground(sink, 9), "the first write after recovery"); err != nil {
		t.Fatalf("entry 9: %v", err)
	}
	file.gates <- gate{}
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := file.content(), sinkLines(1, 6)+sinkLines(9, 9); got != want {
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

// A sink whose file no longer answers does not keep Close waiting: a seal
// closes its devices, and would never complete.
func TestBufferedSink_CloseDoesNotWaitForAStuckWrite(t *testing.T) {
	sink, file := newGatedBufferedSink(t, 1)

	stuck := writeInBackground(sink, 1)
	file.attempt(t, "the flush")

	closed := make(chan error, 1)
	go func() { closed <- sink.Close() }()
	err := within(t, closed, "Close, behind a write that does not return")
	if err == nil || !strings.Contains(err.Error(), "1 entries are not written") {
		t.Errorf("Close: got %v, want it to give up and say what it leaves", err)
	}

	file.gates <- gate{}
	if err := within(t, stuck, "the write, once the file answers"); err != nil {
		t.Errorf("the write that was stuck: %v", err)
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
