package logical

import (
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

// StatusRecordingWriter wraps http.ResponseWriter to capture the status code
// written during streaming responses. This enables accurate audit logging of
// the real HTTP status code returned by upstream services.
type StatusRecordingWriter struct {
	http.ResponseWriter
	statusCode int32 // 0 means not yet written; use atomic for thread safety
	written    int32 // Whether WriteHeader/Write was called
}

// NewStatusRecordingWriter creates a new status recording wrapper
func NewStatusRecordingWriter(w http.ResponseWriter) *StatusRecordingWriter {
	return &StatusRecordingWriter{
		ResponseWriter: w,
		statusCode:     0, // 0 = not yet captured
	}
}

// WriteHeader captures the status code before writing
func (w *StatusRecordingWriter) WriteHeader(code int) {
	if atomic.CompareAndSwapInt32(&w.written, 0, 1) {
		atomic.StoreInt32(&w.statusCode, int32(code))
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write ensures status code is captured even if WriteHeader wasn't called.
// Per HTTP spec, Write() without WriteHeader() implies 200 OK.
func (w *StatusRecordingWriter) Write(b []byte) (int, error) {
	if atomic.CompareAndSwapInt32(&w.written, 0, 1) {
		atomic.StoreInt32(&w.statusCode, http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// StatusCode returns the captured status code (0 if nothing written yet)
func (w *StatusRecordingWriter) StatusCode() int {
	return int(atomic.LoadInt32(&w.statusCode))
}

// Unwrap returns the underlying ResponseWriter (for http.ResponseController)
func (w *StatusRecordingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Flush implements http.Flusher for streaming responses
func (w *StatusRecordingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ClearStreamDeadlines removes both per-connection deadlines the HTTP server
// armed when it read this request's headers. See SetStreamReadDeadline and
// ClearStreamWriteDeadline for what each one does and why streaming traffic
// cannot live under them.
//
// Callers that still have an unread request body should prefer clearing the
// write deadline alone and holding a bounded read window over the read, so a
// dribbling client stays bounded.
func ClearStreamDeadlines(w http.ResponseWriter) error {
	if err := SetStreamReadDeadline(w, time.Time{}); err != nil {
		return err
	}
	return ClearStreamWriteDeadline(w)
}

// ClearStreamWriteDeadline removes the per-connection write deadline.
//
// It is absolute from the moment request headers were read, so it bounds the
// whole handler rather than the write of a response: a proxied call that runs
// longer than it dies with a bare EOF — no status, no body — and a response
// that streams past it is truncated mid-flight. Neither is meaningful for
// traffic Warden forwards to an upstream, whose real ceiling is the mount's
// own timeout.
//
// Returns nil both when the deadline was cleared and when the writer does not
// support deadlines at all (httptest.ResponseRecorder in tests) — a writer
// with no connection behind it has none to shed. Any other error is the
// caller's to log.
func ClearStreamWriteDeadline(w http.ResponseWriter) error {
	if w == nil {
		return nil
	}
	err := http.NewResponseController(w).SetWriteDeadline(time.Time{})
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

// SetStreamReadDeadline moves the per-connection read deadline; the zero time
// removes it.
//
// The read deadline severs a slow upload mid-body — a large tools/call over a
// slow link, a git push — and it does more than that on a long-lived
// response: once the handler has drained the body, net/http reads the
// connection in the background and cancels the request context when that read
// fails, so an armed read deadline tears down an idle SSE stream even though
// nothing is being read. Both are reasons a stream cannot keep it.
//
// Removing it outright is not free either: it is what bounds a client that
// dribbles a request body, and on a streaming path that body is buffered
// before the caller is authenticated. Hold a finite window across that
// buffering and clear it afterwards, rather than clearing it up front.
//
// Errors are reported on the same terms as ClearStreamWriteDeadline.
func SetStreamReadDeadline(w http.ResponseWriter, deadline time.Time) error {
	if w == nil {
		return nil
	}
	err := http.NewResponseController(w).SetReadDeadline(deadline)
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}
