package logical

import (
	"net/http"
	"sync/atomic"
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
