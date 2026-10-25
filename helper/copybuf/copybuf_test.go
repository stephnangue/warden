package copybuf

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"testing"
)

func TestProxyPool_GetPut(t *testing.T) {
	b := ProxyPool.Get()
	if len(b) != Size || cap(b) != Size {
		t.Fatalf("Get returned len %d cap %d, want %d", len(b), cap(b), Size)
	}
	ProxyPool.Put(b)

	// A buffer of the right capacity but re-sliced short is taken back whole;
	// one of any other capacity is ignored. Neither panics.
	ProxyPool.Put(ProxyPool.Get()[:10])
	ProxyPool.Put(make([]byte, 100))
	ProxyPool.Put(make([]byte, Size, 2*Size))
	ProxyPool.Put(nil)
}

func TestProxyPool_NoAllocation(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops put buffers on purpose under the race detector")
	}
	ProxyPool.Put(ProxyPool.Get())
	if n := testing.AllocsPerRun(100, func() { ProxyPool.Put(ProxyPool.Get()) }); n != 0 {
		t.Errorf("Get and Put allocate %v times, want 0", n)
	}
	src := bytes.NewReader(make([]byte, 3*Size))
	if n := testing.AllocsPerRun(100, func() {
		src.Seek(0, io.SeekStart)
		Copy(io.Discard, src)
	}); n != 0 {
		t.Errorf("Copy allocates %v times, want 0", n)
	}
}

func TestCopy_RoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, Size, 3*Size + 7} {
		in := bytes.Repeat([]byte("x"), n)
		var out bytes.Buffer
		written, err := Copy(&out, bytes.NewReader(in))
		if err != nil || written != int64(n) || !bytes.Equal(out.Bytes(), in) {
			t.Errorf("n=%d: written %d, err %v, equal %v", n, written, err, bytes.Equal(out.Bytes(), in))
		}
	}
}

// readerFromWriter fails the test if Copy hands the copy to it: a ReaderFrom
// allocates a buffer of its own.
type readerFromWriter struct {
	t *testing.T
	bytes.Buffer
}

func (w *readerFromWriter) ReadFrom(io.Reader) (int64, error) {
	w.t.Error("Copy used ReadFrom")
	return 0, nil
}

func TestCopy_NeverHandsOffToReaderFrom(t *testing.T) {
	w := &readerFromWriter{t: t}
	if _, err := Copy(w, bytes.NewReader([]byte("payload"))); err != nil {
		t.Fatal(err)
	}
	if w.String() != "payload" {
		t.Errorf("copied %q", w.String())
	}
}

// chunks returns one chunk per Read.
type chunks struct {
	parts [][]byte
	reads int
}

func (c *chunks) Read(p []byte) (int, error) {
	c.reads++
	if len(c.parts) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.parts[0])
	c.parts = c.parts[1:]
	return n, nil
}

// flushRecorder counts flushes.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func (f *flushRecorder) Flush() { f.flushes++ }

// A streamed response is flushed after every write, so each chunk reaches the
// client as it arrives.
func TestCopyResponse_FlushesEachWrite(t *testing.T) {
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	src := &chunks{parts: [][]byte{[]byte("data: 1\n\n"), []byte("data: 2\n\n"), []byte("data: 3\n\n")}}
	written, err := CopyResponse(w, src)
	if err != nil || written != 27 {
		t.Fatalf("written %d, err %v", written, err)
	}
	if w.flushes != 3 || w.Body.String() != "data: 1\n\ndata: 2\n\ndata: 3\n\n" {
		t.Errorf("flushes %d, body %q", w.flushes, w.Body.String())
	}
}

// failingWriter fails every write after the first.
type failingWriter struct {
	*httptest.ResponseRecorder
	writes int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > 1 {
		return 0, errors.New("client gone")
	}
	return f.ResponseRecorder.Write(p)
}

// Once the client is gone the copy stops: the rest of the body is not read.
func TestCopyResponse_StopsAtWriteError(t *testing.T) {
	w := &failingWriter{ResponseRecorder: httptest.NewRecorder()}
	src := &chunks{parts: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}}
	if _, err := CopyResponse(w, src); err == nil {
		t.Fatal("want the write error")
	}
	if src.reads != 2 {
		t.Errorf("read %d times after the client went away, want 2", src.reads)
	}
}
