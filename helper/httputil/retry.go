package httputil

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
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

// BodyError is a failure of an HTTPRequest's BodyFunc: the request was never sent, so
// it is not a transport failure and is never retried. A caller unwraps it to report
// the builder's own error rather than one about the upstream.
type BodyError struct {
	Err error
}

func (e *BodyError) Error() string { return e.Err.Error() }

func (e *BodyError) Unwrap() error { return e.Err }

// RetryPolicy says which failures a request may be re-sent after.
type RetryPolicy int

const (
	// RetryIdempotent re-sends after any transport error and after the statuses
	// in RetryableStatuses. It suits a request whose replay changes nothing: a
	// read, or a mint whose duplicate simply expires.
	RetryIdempotent RetryPolicy = iota

	// RetryCreate re-sends only what cannot have been acted on: a 429, and a
	// request that never left because the connection, or the proxy tunnel, could
	// not be established. RetryableStatuses is ignored. After any other failure —
	// a 5xx, a reset, a timeout once the request was written — the upstream may
	// have done the work and lost only the answer, and a replay would do it twice:
	// a second key, a second credential. It suits a request that creates something
	// durable.
	RetryCreate
)

// HTTPRetryConfig configures HTTP retry behavior.
type HTTPRetryConfig struct {
	// Policy decides which failures are retried. The zero value is
	// RetryIdempotent.
	Policy RetryPolicy

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

	// BodyFunc, when set, builds the body afresh for each attempt instead of Body,
	// which must then be nil. It is for a body that may be sent only once — one
	// carrying a single-use client assertion, say — so a retry presents a new one
	// rather than a replay. It runs after any backoff, immediately before the request
	// is built, so anything time-bound in it reflects when it is sent. attempt counts
	// from 0. An error is returned as a *BodyError and ends the call without a retry.
	BodyFunc func(attempt int) ([]byte, error)

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
	if req.Body != nil && req.BodyFunc != nil {
		return nil, 0, errors.New("request sets both Body and BodyFunc")
	}

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
		body := req.Body
		if req.BodyFunc != nil {
			var err error
			if body, err = req.BodyFunc(attempt); err != nil {
				return nil, 0, &BodyError{Err: err}
			}
		}
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
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
			// A name that does not exist, or a certificate refused, will be the same
			// on the next attempt.
			if config.Policy == RetryCreate && (!neverSent(err) || nameNotFound(err) || certificateRefused(err)) {
				return nil, 0, lastErr
			}
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
					return nil, resp.StatusCode, &answerLostError{status: resp.StatusCode, err: bodyErr}
				}
				return respBody, resp.StatusCode, nil
			}
		} else {
			// Check explicit OK statuses
			for _, ok := range okStatuses {
				if resp.StatusCode == ok {
					if bodyErr != nil {
						return nil, resp.StatusCode, &answerLostError{status: resp.StatusCode, err: bodyErr}
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
		if config.Policy == RetryCreate {
			if resp.StatusCode != http.StatusTooManyRequests {
				return nil, resp.StatusCode, lastErr
			}
			continue
		}
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

// answerLostError is a success status whose body could not be read: the upstream
// did the work, and the answer saying what it made was lost on the way back.
type answerLostError struct {
	status int
	err    error
}

func (e *answerLostError) Error() string {
	return fmt.Sprintf("status %d but failed to read body: %v", e.status, e.err)
}

func (e *answerLostError) Unwrap() error { return e.err }

// OutcomeUnknown reports whether a request that failed may still have been acted
// on: the upstream answered with a 5xx, or with a success whose body was lost, or
// the request may have left and no answer came back. A caller that created
// something durable uses it to say the object may exist despite the error. A
// refusal (a 4xx), a request that was never sent and a body that could not be
// built are known outcomes: nothing was done.
func OutcomeUnknown(err error) bool {
	if err == nil {
		return false
	}
	var lost *answerLostError
	if errors.As(err, &lost) {
		return true
	}
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.Status >= 500
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return !neverSent(err)
	}
	return false
}

// neverSent reports whether a transport error happened before the request could
// leave: the connection could not be dialled (the host refused, unreachable or
// not resolved), the proxy tunnel could not be established, or the server's
// certificate was refused. net/http already re-sends, by itself, a request it
// knows it never wrote on a reused connection.
//
// It errs towards "may have been sent". A deadline that expires while dialling,
// and a request net/http knows it never wrote on a fresh connection, reach the
// caller in shapes that cannot be told from a request that left, and are treated
// as such: not retried, and reported as an unknown outcome.
func neverSent(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && (op.Op == "dial" || op.Op == "proxyconnect") {
		return true
	}
	return certificateRefused(err)
}

// certificateRefused reports whether the TLS handshake failed on the server's
// certificate, which happens before any byte of the request is written.
func certificateRefused(err error) bool {
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr)
}

// nameNotFound reports whether the upstream's host name does not exist.
func nameNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
