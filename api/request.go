package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

// Request is a raw request configuration structure used to initiate
// API requests to the Warden server.
type Request struct {
	Method        string
	URL           *url.URL
	Host          string
	Params        url.Values
	Headers       http.Header
	ClientToken   string
	Obj           interface{}

	// When possible, use BodyBytes as it is more efficient due to how the
	// retry logic works
	BodyBytes []byte

	// Fallback
	Body     io.Reader
	BodySize int64
}

// SetJSONBody is used to set a request body that is a JSON-encoded value.
func (r *Request) SetJSONBody(val interface{}) error {
	if val == nil {
		return nil
	}

	buf, err := json.Marshal(val)
	if err != nil {
		return err
	}

	r.Obj = val
	r.BodyBytes = buf
	return nil
}

// ResetJSONBody is used to reset the body for a redirect
func (r *Request) ResetJSONBody() error {
	if r.BodyBytes == nil {
		return nil
	}
	return r.SetJSONBody(r.Obj)
}

func (r *Request) toRetryableHTTP() (*retryablehttp.Request, error) {
	// Encode the query parameters
	r.URL.RawQuery = r.Params.Encode()

	// Create the HTTP request, defaulting to retryable
	var req *retryablehttp.Request

	var err error
	var body interface{}

	switch {
	case r.BodyBytes == nil && r.Body == nil:
		// No body

	case r.BodyBytes != nil:
		// Use bytes, it's more efficient
		body = r.BodyBytes

	default:
		body = r.Body
	}

	req, err = retryablehttp.NewRequest(r.Method, r.URL.RequestURI(), body)
	if err != nil {
		return nil, err
	}

	req.URL.User = r.URL.User
	req.URL.Scheme = r.URL.Scheme
	req.URL.Host = r.URL.Host
	req.Host = r.Host

	// Set custom headers first
	if r.Headers != nil {
		for header, vals := range r.Headers {
			for _, val := range vals {
				req.Header.Add(header, val)
			}
		}
	}

	// Set authorization header (may override custom headers if provided)
	if len(r.ClientToken) != 0 {
		req.Header.Set("Authorization", "Bearer "+r.ClientToken)
	}

	return req, nil
}