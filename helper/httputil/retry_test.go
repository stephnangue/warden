package httputil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExecuteWithRetry_SuccessFirstAttempt(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	body, status, err := ExecuteWithRetry(context.Background(), srv.Client(),
		HTTPRequest{Method: http.MethodGet, URL: srv.URL},
		DefaultHTTPRetryConfig(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status: got %d", status)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body: got %s", body)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call, got %d", got)
	}
}

func TestExecuteWithRetry_RetriesOn429ThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultHTTPRetryConfig()
	cfg.BaseBackoff = 1 * time.Millisecond // keep test fast
	cfg.JitterPercent = 1
	_, status, err := ExecuteWithRetry(context.Background(), srv.Client(),
		HTTPRequest{Method: http.MethodGet, URL: srv.URL}, cfg,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200", status)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 calls (one retry), got %d", got)
	}
}

func TestExecuteWithRetry_NoRetryOnNonRetryableStatus(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	_, status, err := ExecuteWithRetry(context.Background(), srv.Client(),
		HTTPRequest{Method: http.MethodGet, URL: srv.URL},
		DefaultHTTPRetryConfig(),
	)
	if err == nil {
		t.Fatal("expected error for 400 status")
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status: got %d", status)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call (no retry on 4xx), got %d", got)
	}
	// The status survives the caller wrapping the error, with the same text.
	var statusErr *StatusError
	if wrapped := fmt.Errorf("token request: %w", err); !errors.As(wrapped, &statusErr) || statusErr.HTTPStatus() != http.StatusBadRequest {
		t.Fatalf("want a StatusError with 400 through wrapping, got %T %v", err, err)
	}
	if err.Error() != "status 400: " {
		t.Fatalf("error text changed: %q", err.Error())
	}
}

func TestExecuteWithRetry_5xxRetryWithSpecialValue500(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway) // 502 — should retry under {500}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultHTTPRetryConfig()
	cfg.BaseBackoff = 1 * time.Millisecond
	cfg.JitterPercent = 1
	cfg.RetryableStatuses = []int{500} // special value means all 5xx
	_, status, err := ExecuteWithRetry(context.Background(), srv.Client(),
		HTTPRequest{Method: http.MethodGet, URL: srv.URL}, cfg,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200", status)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 calls (two retries), got %d", got)
	}
}

func TestExecuteWithRetry_ExplicitOKStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`created`))
	}))
	defer srv.Close()

	body, status, err := ExecuteWithRetry(context.Background(), srv.Client(),
		HTTPRequest{
			Method:     http.MethodPost,
			URL:        srv.URL,
			OKStatuses: []int{http.StatusOK, http.StatusCreated},
		},
		DefaultHTTPRetryConfig(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("status: got %d", status)
	}
	if string(body) != "created" {
		t.Fatalf("body: got %s", body)
	}
}

func TestExecuteWithRetry_RespectsContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	cfg := DefaultHTTPRetryConfig()
	cfg.BaseBackoff = 1 * time.Second
	_, _, err := ExecuteWithRetry(ctx, srv.Client(),
		HTTPRequest{Method: http.MethodGet, URL: srv.URL}, cfg,
	)
	if err == nil {
		t.Fatal("expected error when context already cancelled before second attempt")
	}
}

func TestExecuteWithRetry_HeadersAreSent(t *testing.T) {
	gotHeader := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Test-Header")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, _, err := ExecuteWithRetry(context.Background(), srv.Client(),
		HTTPRequest{
			Method:  http.MethodGet,
			URL:     srv.URL,
			Headers: map[string]string{"X-Test-Header": "abc"},
		},
		DefaultHTTPRetryConfig(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotHeader != "abc" {
		t.Fatalf("expected header sent, got %q", gotHeader)
	}
}

// A body that may be sent only once is built afresh for every attempt, so a retry
// presents a new one rather than replaying the first.
func TestExecuteWithRetry_BodyFuncBuildsEachAttempt(t *testing.T) {
	var (
		calls  int32
		mu     sync.Mutex
		bodies []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var built []int
	cfg := HTTPRetryConfig{MaxAttempts: 3, MaxBodySize: DefaultMaxBodySize, RetryableStatuses: []int{500}, BaseBackoff: time.Millisecond, JitterPercent: 10}
	_, status, err := ExecuteWithRetry(context.Background(), srv.Client(), HTTPRequest{
		Method: http.MethodPost,
		URL:    srv.URL,
		BodyFunc: func(attempt int) ([]byte, error) {
			built = append(built, attempt)
			return []byte(fmt.Sprintf("attempt-%d", attempt)), nil
		},
	}, cfg)
	if err != nil || status != http.StatusOK {
		t.Fatalf("got status %d, err %v", status, err)
	}
	if fmt.Sprint(built) != "[0 1 2]" {
		t.Errorf("BodyFunc called for attempts %v, want [0 1 2]", built)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(bodies) != "[attempt-0 attempt-1 attempt-2]" {
		t.Errorf("server received %v, want one fresh body per attempt", bodies)
	}
}

// The body is built after the backoff, not before it, so a time-bound body (an
// assertion's iat, a capability's expiry check) reflects when it is actually sent.
func TestExecuteWithRetry_BodyFuncRunsAfterBackoff(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const backoff = 50 * time.Millisecond
	var at []time.Time
	cfg := HTTPRetryConfig{MaxAttempts: 2, MaxBodySize: DefaultMaxBodySize, RetryableStatuses: []int{429}, BaseBackoff: backoff, JitterPercent: 10}
	_, _, err := ExecuteWithRetry(context.Background(), srv.Client(), HTTPRequest{
		Method:   http.MethodPost,
		URL:      srv.URL,
		BodyFunc: func(int) ([]byte, error) { at = append(at, time.Now()); return []byte("x"), nil },
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(at) != 2 {
		t.Fatalf("BodyFunc called %d times, want 2", len(at))
	}
	if gap := at[1].Sub(at[0]); gap < backoff {
		t.Errorf("the second body was built %v after the first, before the %v backoff elapsed", gap, backoff)
	}
}

// A body that cannot be built was never sent: it is reported as itself, wrapped so a
// caller can tell it from an upstream failure, and not retried.
func TestExecuteWithRetry_BodyFuncErrorIsNotRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	sentinel := errors.New("signing failed")
	built := 0
	cfg := HTTPRetryConfig{MaxAttempts: 3, MaxBodySize: DefaultMaxBodySize, RetryableStatuses: []int{500}, BaseBackoff: time.Millisecond, JitterPercent: 10}
	_, _, err := ExecuteWithRetry(context.Background(), srv.Client(), HTTPRequest{
		Method: http.MethodPost,
		URL:    srv.URL,
		BodyFunc: func(attempt int) ([]byte, error) {
			built++
			if attempt == 1 {
				return nil, sentinel
			}
			return []byte("x"), nil
		},
	}, cfg)
	var be *BodyError
	if !errors.As(err, &be) {
		t.Fatalf("got %v (%T), want a *BodyError", err, err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("the builder's error is not in the chain: %v", err)
	}
	if built != 2 || atomic.LoadInt32(&calls) != 1 {
		t.Errorf("built %d bodies and sent %d requests, want 2 and 1 — a failed build ends the call", built, calls)
	}
}

func TestExecuteWithRetry_BodyAndBodyFuncAreExclusive(t *testing.T) {
	_, _, err := ExecuteWithRetry(context.Background(), http.DefaultClient, HTTPRequest{
		Method:   http.MethodPost,
		URL:      "http://127.0.0.1:0",
		Body:     []byte("x"),
		BodyFunc: func(int) ([]byte, error) { return []byte("y"), nil },
	}, DefaultHTTPRetryConfig())
	if err == nil {
		t.Fatal("a request setting both Body and BodyFunc was accepted")
	}
}

func TestDefaultHTTPRetryConfig(t *testing.T) {
	cfg := DefaultHTTPRetryConfig()
	if cfg.MaxAttempts != 3 {
		t.Errorf("MaxAttempts: got %d, want 3", cfg.MaxAttempts)
	}
	if cfg.MaxBodySize != DefaultMaxBodySize {
		t.Errorf("MaxBodySize: got %d, want %d", cfg.MaxBodySize, DefaultMaxBodySize)
	}
	if len(cfg.RetryableStatuses) != 1 || cfg.RetryableStatuses[0] != 429 {
		t.Errorf("RetryableStatuses: got %v, want [429]", cfg.RetryableStatuses)
	}
}
