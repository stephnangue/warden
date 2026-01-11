// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"fmt"
	"net/http"
)

// CodedError is an error that carries an HTTP status code.
// This allows backends to return errors with appropriate status codes
// without relying on string matching.
type CodedError struct {
	Status  int
	Message string
	Err     error
}

// Error implements the error interface.
func (e *CodedError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the underlying error.
func (e *CodedError) Unwrap() error {
	return e.Err
}

// Code returns the HTTP status code.
func (e *CodedError) Code() int {
	return e.Status
}

// ErrBadRequest creates a 400 Bad Request error.
func ErrBadRequest(message string) *CodedError {
	return &CodedError{Status: http.StatusBadRequest, Message: message}
}

// ErrBadRequestf creates a formatted 400 Bad Request error.
func ErrBadRequestf(format string, args ...any) *CodedError {
	return &CodedError{Status: http.StatusBadRequest, Message: fmt.Sprintf(format, args...)}
}

// ErrNotFound creates a 404 Not Found error.
func ErrNotFound(message string) *CodedError {
	return &CodedError{Status: http.StatusNotFound, Message: message}
}

// ErrNotFoundf creates a formatted 404 Not Found error.
func ErrNotFoundf(format string, args ...any) *CodedError {
	return &CodedError{Status: http.StatusNotFound, Message: fmt.Sprintf(format, args...)}
}

// ErrConflict creates a 409 Conflict error.
func ErrConflict(message string) *CodedError {
	return &CodedError{Status: http.StatusConflict, Message: message}
}

// ErrConflictf creates a formatted 409 Conflict error.
func ErrConflictf(format string, args ...any) *CodedError {
	return &CodedError{Status: http.StatusConflict, Message: fmt.Sprintf(format, args...)}
}

// ErrForbidden creates a 403 Forbidden error.
func ErrForbidden(message string) *CodedError {
	return &CodedError{Status: http.StatusForbidden, Message: message}
}

// ErrForbiddenf creates a formatted 403 Forbidden error.
func ErrForbiddenf(format string, args ...any) *CodedError {
	return &CodedError{Status: http.StatusForbidden, Message: fmt.Sprintf(format, args...)}
}

// ErrInternal creates a 500 Internal Server Error.
func ErrInternal(message string) *CodedError {
	return &CodedError{Status: http.StatusInternalServerError, Message: message}
}

// ErrInternalf creates a formatted 500 Internal Server Error.
func ErrInternalf(format string, args ...any) *CodedError {
	return &CodedError{Status: http.StatusInternalServerError, Message: fmt.Sprintf(format, args...)}
}

// ErrServiceUnavailable creates a 503 Service Unavailable error.
func ErrServiceUnavailable(message string) *CodedError {
	return &CodedError{Status: http.StatusServiceUnavailable, Message: message}
}

// ErrServiceUnavailablef creates a formatted 503 Service Unavailable error.
func ErrServiceUnavailablef(format string, args ...any) *CodedError {
	return &CodedError{Status: http.StatusServiceUnavailable, Message: fmt.Sprintf(format, args...)}
}

// WrapWithCode wraps an existing error with an HTTP status code.
func WrapWithCode(status int, err error) *CodedError {
	return &CodedError{Status: status, Message: err.Error(), Err: err}
}

// GetErrorCode extracts the HTTP status code from an error.
// If the error is a CodedError, it returns the status code.
// Otherwise, it returns 500 Internal Server Error.
func GetErrorCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if coded, ok := err.(*CodedError); ok {
		return coded.Status
	}
	// Check if the error wraps a CodedError
	if unwrapped, ok := err.(interface{ Unwrap() error }); ok {
		return GetErrorCode(unwrapped.Unwrap())
	}
	return http.StatusInternalServerError
}

// ErrorResponse creates a Response from a CodedError.
func ErrorResponse(err error) *Response {
	code := GetErrorCode(err)
	return &Response{
		StatusCode: code,
		Err:        err,
	}
}
