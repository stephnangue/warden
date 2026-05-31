package httputil

import (
	"context"
	"net/http"
	"net/http/httptest"
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
