package httputil

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

const (
	// DefaultMaxBodySize is the default maximum response body size (1MB).
	DefaultMaxBodySize = 1 << 20
)

// StatusError is an upstream's answer with a status the caller does not
// accept. It keeps the status inspectable after the error is wrapped, so a
// caller further up can tell an upstream that refused a request (a 4xx) from
// one that was briefly unable to serve it (a 5xx), without matching text. Err
// carries the message, worded as the code that saw the response wants it.
type StatusError struct {
	Status int
	Err    error
}

func (e *StatusError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("status %d", e.Status)
	}
	return e.Err.Error()
}

func (e *StatusError) Unwrap() error { return e.Err }

// HTTPStatus is the status the upstream answered with.
func (e *StatusError) HTTPStatus() int { return e.Status }

// HTTPRetryConfig configures HTTP retry behavior.
type HTTPRetryConfig struct {
	// MaxAttempts is the maximum number of attempts (including the initial request)
	MaxAttempts int

	// MaxBodySize is the maximum response body size to read
	MaxBodySize int64

	// RetryableStatuses are HTTP status codes that should be retried.
	// Special value 500 matches all 5xx errors (500-599).
	RetryableStatuses []int

	// BaseBackoff is the base backoff duration (exponential: 1s, 2s, 4s, 8s...)
	BaseBackoff time.Duration

	// JitterPercent is the percentage of jitter to add to backoff (0-100)
	JitterPercent int
}

// DefaultHTTPRetryConfig returns sensible defaults for API calls.
// Retries only on rate limiting (429).
func DefaultHTTPRetryConfig() HTTPRetryConfig {
	return HTTPRetryConfig{
		MaxAttempts:       3,
		MaxBodySize:       DefaultMaxBodySize,
		RetryableStatuses: []int{429}, // Rate limiting only
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
}

// HTTPRequest represents a prepared HTTP request.
type HTTPRequest struct {
	// Method is the HTTP method (GET, POST, etc.)
	Method string

	// URL is the request URL
	URL string

	// Body is the request body (optional)
	Body []byte

	// Headers are request headers
	Headers map[string]string

	// OKStatuses are status codes considered successful (default: 200-299)
	OKStatuses []int
}

// ExecuteWithRetry executes an HTTP request with exponential backoff retry.
// Returns response body, status code, and error.
func ExecuteWithRetry(
	ctx context.Context,
	client *http.Client,
	req HTTPRequest,
	config HTTPRetryConfig,
) ([]byte, int, error) {
	var lastErr error
	var lastStatus int

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff with jitter
			backoff := config.BaseBackoff * time.Duration(1<<uint(attempt-1))
			jitter := time.Duration(rand.Int63n(int64(backoff) * int64(config.JitterPercent) / 100))
			delay := backoff + jitter

			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(delay):
			}
		}

		// Build HTTP request
		var bodyReader io.Reader
		if req.Body != nil {
			bodyReader = bytes.NewReader(req.Body)
		}

		httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create request: %w", err)
		}

		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}

		// Execute request
		resp, err := client.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		respBody, bodyErr := io.ReadAll(io.LimitReader(resp.Body, config.MaxBodySize))
		resp.Body.Close()
		lastStatus = resp.StatusCode

		// Check if status is successful
		okStatuses := req.OKStatuses
		if len(okStatuses) == 0 {
			// Default: any 2xx status
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if bodyErr != nil {
					return nil, resp.StatusCode, fmt.Errorf("status %d but failed to read body: %w", resp.StatusCode, bodyErr)
				}
				return respBody, resp.StatusCode, nil
			}
		} else {
			// Check explicit OK statuses
			for _, ok := range okStatuses {
				if resp.StatusCode == ok {
					if bodyErr != nil {
						return nil, resp.StatusCode, fmt.Errorf("status %d but failed to read body: %w", resp.StatusCode, bodyErr)
					}
					return respBody, resp.StatusCode, nil
				}
			}
		}

		// Build error message
		bodyStr := string(respBody)
		if bodyErr != nil {
			bodyStr = fmt.Sprintf("[body read error: %v]", bodyErr)
		}
		lastErr = &StatusError{Status: resp.StatusCode, Err: fmt.Errorf("status %d: %s", resp.StatusCode, bodyStr)}

		// Check if status is retryable
		shouldRetry := false
		for _, retryStatus := range config.RetryableStatuses {
			if retryStatus == 500 && resp.StatusCode >= 500 && resp.StatusCode < 600 {
				// Special case: 500 means all 5xx errors
				shouldRetry = true
				break
			}
			if resp.StatusCode == retryStatus {
				shouldRetry = true
				break
			}
		}

		if !shouldRetry {
			return nil, resp.StatusCode, lastErr
		}
	}

	return nil, lastStatus, lastErr
}
