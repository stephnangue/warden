// Package copybuf pools the buffers that copy a proxied response to its
// client. Every proxied response needs one, and without the pool each one
// allocates its own 32 KiB, which was close to half of what a gateway request
// allocated.
//
// A pooled buffer still holds bytes of the last response it copied. That is
// safe because a copy only ever writes what its latest Read put in the buffer,
// buf[:n] (Copy, CopyResponse and httputil.ReverseProxy alike), and a writer
// may not keep the slice it is handed (io.Writer's contract), so no buffer is
// shared by two copies.
//
// The HTTP/2 server keeps that contract too, although it writes frames on a
// goroutine of its own: it copies a handler's data into the frame before that
// goroutine starts (go.dev/issue/58446), and drops the frames still queued for
// a stream that closes, so a Write that returns early leaves no reference to
// the buffer behind.
package copybuf

import (
	"io"
	"net/http"
	"net/http/httputil"
	"sync"
)

// Size is the size of every pooled buffer, the size httputil.ReverseProxy and
// io.Copy use on their own.
const Size = 32 << 10

// pool holds array pointers rather than slices: putting a slice in a
// sync.Pool allocates to box its header, an array pointer does not.
var pool = sync.Pool{New: func() any { return new([Size]byte) }}

// ProxyPool is an httputil.BufferPool backed by this package's pool, for a
// ReverseProxy's BufferPool field.
var ProxyPool httputil.BufferPool = proxyPool{}

type proxyPool struct{}

func (proxyPool) Get() []byte {
	return pool.Get().(*[Size]byte)[:]
}

// Put takes back a buffer of Size bytes of capacity, the only kind Get hands
// out; anything else is left to the collector, as converting a shorter slice
// to an array pointer would panic.
func (proxyPool) Put(b []byte) {
	if cap(b) != Size {
		return
	}
	pool.Put((*[Size]byte)(b[:Size]))
}

// Copy copies src to dst through a pooled buffer. It is an explicit loop, not
// io.CopyBuffer, which hands the copy to a ReaderFrom or WriterTo when either
// side has one, and those allocate a buffer of their own.
func Copy(dst io.Writer, src io.Reader) (int64, error) {
	buf := pool.Get().(*[Size]byte)
	defer pool.Put(buf)
	return copyLoop(dst, src, buf[:], nil)
}

// CopyResponse copies an upstream response body to the client through a
// pooled buffer, flushing after every write when w can flush, so a streamed
// response reaches the client as it arrives. It stops at the first write
// error: the client is gone, so the rest of the body is not read.
func CopyResponse(w http.ResponseWriter, body io.Reader) (int64, error) {
	flusher, _ := w.(http.Flusher)
	buf := pool.Get().(*[Size]byte)
	defer pool.Put(buf)
	return copyLoop(w, body, buf[:], flusher)
}

func copyLoop(dst io.Writer, src io.Reader, buf []byte, flusher http.Flusher) (int64, error) {
	var written int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			nw, werr := dst.Write(buf[:n])
			written += int64(nw)
			if werr != nil {
				return written, werr
			}
			if nw != n {
				return written, io.ErrShortWrite
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr == io.EOF {
			return written, nil
		}
		if rerr != nil {
			return written, rerr
		}
	}
}
