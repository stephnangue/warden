package drivers

import (
	"testing"

	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"time"
)

func TestDefaultPortForEngine(t *testing.T) {
	assert.Equal(t, "5432", defaultPortForEngine("postgres"))
	assert.Equal(t, "3306", defaultPortForEngine("mysql"))
	assert.Equal(t, "5432", defaultPortForEngine(""))
	assert.Equal(t, "5432", defaultPortForEngine("unknown"))
}

func TestReadLimitedBody(t *testing.T) {
	t.Run("small body", func(t *testing.T) {
		body := httptest.NewRequest("GET", "/", nil).Body
		data, err := readLimitedBody(body)
		require.NoError(t, err)
		assert.Empty(t, data)
	})
}

// =============================================================================
// HTTPRetryConfig Tests
// =============================================================================

func TestDefaultHTTPRetryConfig(t *testing.T) {
	cfg := DefaultHTTPRetryConfig()
	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, int64(DefaultMaxBodySize), cfg.MaxBodySize)
	assert.Contains(t, cfg.RetryableStatuses, 429)
	assert.Equal(t, 1*time.Second, cfg.BaseBackoff)
	assert.Equal(t, 20, cfg.JitterPercent)
}

// =============================================================================
// ExecuteWithRetry Tests
// =============================================================================

func TestExecuteWithRetry_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	body, status, err := ExecuteWithRetry(
		context.Background(),
		srv.Client(),
		HTTPRequest{Method: "GET", URL: srv.URL},
		DefaultHTTPRetryConfig(),
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, string(body), "ok")
}

func TestExecuteWithRetry_NonRetryableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	_, status, err := ExecuteWithRetry(
		context.Background(),
		srv.Client(),
		HTTPRequest{Method: "GET", URL: srv.URL},
		DefaultHTTPRetryConfig(),
	)
	assert.Error(t, err)
	assert.Equal(t, http.StatusForbidden, status)
}

func TestExecuteWithRetry_WithExplicitOKStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}))
	defer srv.Close()

	body, status, err := ExecuteWithRetry(
		context.Background(),
		srv.Client(),
		HTTPRequest{
			Method:     "POST",
			URL:        srv.URL,
			OKStatuses: []int{http.StatusCreated},
		},
		DefaultHTTPRetryConfig(),
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, status)
	assert.Equal(t, "created", string(body))
}

func TestExecuteWithRetry_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, err := ExecuteWithRetry(
		ctx,
		&http.Client{},
		HTTPRequest{Method: "GET", URL: "http://localhost:1"},
		HTTPRetryConfig{
			MaxAttempts:       3,
			MaxBodySize:       DefaultMaxBodySize,
			RetryableStatuses: []int{429},
			BaseBackoff:       1 * time.Millisecond,
			JitterPercent:     20,
		},
	)
	assert.Error(t, err)
}

func TestExecuteWithRetry_RetryOn5xx(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	body, status, err := ExecuteWithRetry(
		context.Background(),
		srv.Client(),
		HTTPRequest{Method: "GET", URL: srv.URL},
		HTTPRetryConfig{
			MaxAttempts:       3,
			MaxBodySize:       DefaultMaxBodySize,
			RetryableStatuses: []int{500}, // 500 means all 5xx
			BaseBackoff:       1 * time.Millisecond,
			JitterPercent:     10,
		},
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "ok", string(body))
	assert.Equal(t, 2, attempts)
}

func TestExecuteWithRetry_WithHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	_, status, err := ExecuteWithRetry(
		context.Background(),
		srv.Client(),
		HTTPRequest{
			Method: "GET",
			URL:    srv.URL,
			Headers: map[string]string{
				"Authorization": "Bearer test-token",
			},
		},
		DefaultHTTPRetryConfig(),
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
}

func TestExecuteWithRetry_WithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, status, err := ExecuteWithRetry(
		context.Background(),
		srv.Client(),
		HTTPRequest{
			Method: "POST",
			URL:    srv.URL,
			Body:   []byte(`{"key":"value"}`),
		},
		DefaultHTTPRetryConfig(),
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
}

// =============================================================================
// AWSDriver additional tests
// =============================================================================
