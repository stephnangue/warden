package logical

import (
	"net/http"
)

// Response is a struct that holds the response from a logical backend.
// It contains all the data needed to construct an HTTP response.
type Response struct {

	// Auth, if not nil, contains the authentication information for
	// this response.
	Auth *Auth `json:"auth" structs:"auth" mapstructure:"auth"`

	// StatusCode is the HTTP status code for the response.
	StatusCode int

	// Headers contains HTTP headers to be sent with the response.
	Headers http.Header

	// Body contains the raw response body.
	Body []byte

	// Data contains structured response data (optional, for internal use).
	// Backends can populate this for post-processing.
	Data map[string]any

	// Err is set if an error occurred during processing.
	Err error

	// The mount class of the backend which generated the response
	MountClass string

	// Streamed indicates the response was already written to ResponseWriter
	Streamed bool

	// Warnings contains any warnings generated during processing
	Warnings []string
}

// NewResponse creates a new Response with default values.
func NewResponse() *Response {
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    make(http.Header),
	}
}

// IsError returns true if the response represents an error.
func (r *Response) IsError() bool {
	return r.Err != nil || (r.StatusCode >= 400 && r.StatusCode < 600)
}

// Error returns the error associated with this response.
func (r *Response) Error() error {
	return r.Err
}

// SetHeader sets a header value on the response.
func (r *Response) SetHeader(key, value string) {
	if r.Headers == nil {
		r.Headers = make(http.Header)
	}
	r.Headers.Set(key, value)
}

// AddHeader adds a header value to the response.
func (r *Response) AddHeader(key, value string) {
	if r.Headers == nil {
		r.Headers = make(http.Header)
	}
	r.Headers.Add(key, value)
}

// AddWarning adds a warning message to the response.
func (r *Response) AddWarning(warning string) {
	r.Warnings = append(r.Warnings, warning)
}

