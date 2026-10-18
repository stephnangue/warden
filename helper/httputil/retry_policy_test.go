package httputil

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fastConfig retries everything RetryIdempotent would, quickly.
func fastConfig(policy RetryPolicy) HTTPRetryConfig {
	return HTTPRetryConfig{
		Policy:            policy,
		MaxAttempts:       3,
		MaxBodySize:       DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       time.Millisecond,
		JitterPercent:     1,
	}
}

// answerLostServer reads each request in full, as if it acted on it, then drops
// the connection without answering: the way a create's acknowledgement is lost.
func answerLostServer(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(hits, 1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A request whose answer was lost may have been acted on: an idempotent one is
// re-sent, a create is not.
func TestExecuteWithRetry_LostAnswer(t *testing.T) {
	for _, tc := range []struct {
		policy RetryPolicy
		want   int32
	}{
		{RetryIdempotent, 3},
		{RetryCreate, 1},
	} {
		var hits int32
		srv := answerLostServer(t, &hits)
		_, _, err := ExecuteWithRetry(context.Background(), srv.Client(),
			HTTPRequest{Method: http.MethodPost, URL: srv.URL, Body: []byte(`{"create":true}`)}, fastConfig(tc.policy))
		if err == nil {
			t.Fatalf("policy %d: a dropped connection was reported as success", tc.policy)
		}
		if got := atomic.LoadInt32(&hits); got != tc.want {
			t.Errorf("policy %d: the server saw %d requests, want %d", tc.policy, got, tc.want)
		}
		if !OutcomeUnknown(err) {
			t.Errorf("policy %d: a lost answer must read as an unknown outcome: %v", tc.policy, err)
		}
	}
}

// A 5xx can follow work the upstream did; a 429 is a refusal and is retried.
func TestExecuteWithRetry_CreateRetriesOnlyARateLimit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, status, err := ExecuteWithRetry(context.Background(), srv.Client(),
		HTTPRequest{Method: http.MethodPost, URL: srv.URL}, fastConfig(RetryCreate))
	if err == nil || status != http.StatusBadGateway {
		t.Fatalf("got status %d, err %v; want the 502", status, err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("a 502 was retried: the server saw %d requests", got)
	}
	if !OutcomeUnknown(err) {
		t.Errorf("a 5xx must read as an unknown outcome: %v", err)
	}

	hits = 0
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer limited.Close()

	cfg := fastConfig(RetryCreate)
	cfg.RetryableStatuses = nil // ignored under RetryCreate
	if _, _, err := ExecuteWithRetry(context.Background(), limited.Client(),
		HTTPRequest{Method: http.MethodPost, URL: limited.URL}, cfg); err != nil {
		t.Fatalf("a rate-limited create was not retried: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("the server saw %d requests, want 2", got)
	}
}

// dialFailing is a client whose every dial fails with err, counting attempts.
func dialFailing(dials *int32, err error) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			atomic.AddInt32(dials, 1)
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
		},
	}}
}

// A request that could not be dialled never left, so even a create retries it —
// unless the name does not exist, which no retry will change.
func TestExecuteWithRetry_CreateRetriesADialFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int32
	}{
		{"connection refused", syscall.ECONNREFUSED, 3},
		{"name not resolved in time", &net.DNSError{Err: "i/o timeout", Name: "iam.example.com", IsTimeout: true}, 3},
		{"name does not exist", &net.DNSError{Err: "no such host", Name: "iam.example.invalid", IsNotFound: true}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dials int32
			_, _, err := ExecuteWithRetry(context.Background(), dialFailing(&dials, tc.err),
				HTTPRequest{Method: http.MethodPost, URL: "http://iam.example.com/keys"}, fastConfig(RetryCreate))
			if err == nil {
				t.Fatal("a failed dial was reported as success")
			}
			if got := atomic.LoadInt32(&dials); got != tc.want {
				t.Errorf("dialled %d times, want %d", got, tc.want)
			}
			if OutcomeUnknown(err) {
				t.Errorf("a request that was never sent has a known outcome: %v", err)
			}
		})
	}
}

// closedPort returns a loopback address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// The shapes net/http really returns, not fabricated ones: a refused connection,
// a proxy that refuses the tunnel, and a certificate the client rejects all fail
// before the request is written. The first two may pass on the next attempt; a
// rejected certificate will not.
func TestExecuteWithRetry_CreateOnRealPreSendFailures(t *testing.T) {
	var hits int32
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer tlsSrv.Close()

	proxyURL, _ := url.Parse("http://" + closedPort(t))
	for _, tc := range []struct {
		name     string
		client   *http.Client
		url      string
		attempts int32 // dials or hits, as counted below
		retried  bool
	}{
		{"connection refused", &http.Client{}, "http://" + closedPort(t) + "/keys", 3, true},
		{"proxy refuses the tunnel", &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}},
			"https://iam.example.com/keys", 3, true},
		{"certificate not trusted", &http.Client{}, tlsSrv.URL + "/keys", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dials int32
			base := tc.client.Transport
			if base == nil {
				base = &http.Transport{}
			}
			tr := base.(*http.Transport).Clone()
			dialer := &net.Dialer{}
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				atomic.AddInt32(&dials, 1)
				return dialer.DialContext(ctx, network, addr)
			}
			tc.client.Transport = tr

			_, _, err := ExecuteWithRetry(context.Background(), tc.client,
				HTTPRequest{Method: http.MethodPost, URL: tc.url}, fastConfig(RetryCreate))
			if err == nil {
				t.Fatal("the request was reported as sent")
			}
			if OutcomeUnknown(err) {
				t.Errorf("a request that was never written has a known outcome: %v", err)
			}
			if got := atomic.LoadInt32(&dials); tc.retried && got != tc.attempts {
				t.Errorf("dialled %d times, want %d: %v", got, tc.attempts, err)
			}
			if !tc.retried && atomic.LoadInt32(&dials) != 1 {
				t.Errorf("a rejected certificate was retried: %d dials", dials)
			}
		})
	}
	if hits != 0 {
		t.Errorf("a request reached the server behind a rejected certificate")
	}
}

// A success whose body is lost is the one failure where the work was certainly
// done: the create must not be retried, and the outcome must read as unknown.
func TestExecuteWithRetry_SuccessWithLostBodyIsAnUnknownOutcome(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"key":`))
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	_, _, err := ExecuteWithRetry(context.Background(), srv.Client(),
		HTTPRequest{Method: http.MethodPost, URL: srv.URL}, fastConfig(RetryCreate))
	if err == nil {
		t.Fatal("a truncated body was reported as success")
	}
	if !OutcomeUnknown(err) {
		t.Errorf("the key was created and its answer lost, so the outcome is unknown: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("the server saw %d requests, want 1", got)
	}
}

func TestOutcomeUnknown(t *testing.T) {
	reset := &url.Error{Op: "Post", URL: "https://iam.example.com", Err: &net.OpError{Op: "read", Err: syscall.ECONNRESET}}
	refused := &url.Error{Op: "Post", URL: "https://iam.example.com", Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"5xx", &StatusError{Status: http.StatusServiceUnavailable}, true},
		{"4xx", &StatusError{Status: http.StatusConflict}, false},
		{"429", &StatusError{Status: http.StatusTooManyRequests}, false},
		{"reset after sending", reset, true},
		{"wrapped reset", errors.Join(errors.New("createKey"), reset), true},
		{"never dialled", refused, false},
		{"body never built", &BodyError{Err: errors.New("no key")}, false},
		{"plain error", errors.New("bad request URL"), false},
	} {
		if got := OutcomeUnknown(tc.err); got != tc.want {
			t.Errorf("%s: OutcomeUnknown = %v, want %v", tc.name, got, tc.want)
		}
	}
}
