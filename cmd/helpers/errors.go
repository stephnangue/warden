package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/stephnangue/warden/api"
)

// ExitCode is the typed enum of exit codes warden emits.
type ExitCode int

const (
	ExitOK           ExitCode = 0
	ExitUnknown      ExitCode = 1
	ExitUsage        ExitCode = 2
	ExitInvalidInput ExitCode = 3
	ExitAuth         ExitCode = 4
	ExitForbidden    ExitCode = 5
	ExitNotFound     ExitCode = 6
	ExitNetwork      ExitCode = 7
	ExitServer       ExitCode = 8
	ExitConflict     ExitCode = 9
	ExitSealed       ExitCode = 10
)

// ErrorCode is the stable string identifier surfaced in JSON envelopes.
// Agents branch on this value to choose recovery strategies.
type ErrorCode string

const (
	CodeUnknown      ErrorCode = "unknown"
	CodeUsage        ErrorCode = "usage"
	CodeInvalidInput ErrorCode = "invalid_input"
	CodeAuth         ErrorCode = "auth_required"
	CodeForbidden    ErrorCode = "forbidden"
	CodeNotFound     ErrorCode = "not_found"
	CodeNetwork      ErrorCode = "network"
	CodeServer       ErrorCode = "server"
	CodeConflict     ErrorCode = "conflict"
	CodeSealed       ErrorCode = "sealed"
)

// Sentinel errors. Wrap with fmt.Errorf("context: %w", helpers.ErrXxx) so the
// central renderer can classify the error without string-matching.
var (
	ErrUsage        = errors.New("usage error")
	ErrInvalidInput = errors.New("invalid input")
	ErrAuth         = errors.New("authentication required")
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
	ErrNetwork      = errors.New("network error")
	ErrServer       = errors.New("server error")
	ErrConflict     = errors.New("conflict")
	ErrSealed       = errors.New("warden is sealed or uninitialized")
)

// WardenError is the JSON envelope emitted on stderr when -output is json or
// ndjson. Agents key off Code (stable string) for branching; Message is
// human-readable; Hint is an optional recovery suggestion.
type WardenError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id,omitempty"`
	Hint      string    `json:"hint,omitempty"`
}

// RenderError classifies err, emits the appropriate stderr representation, and
// returns the corresponding ExitCode. Returns ExitOK for nil. JSON/NDJSON mode
// emits a {"error": {...}} envelope; table/text mode emits the human message.
func RenderError(err error) ExitCode {
	if err == nil {
		return ExitOK
	}
	code, exit := classify(err)

	format := ResolveFormat()
	switch format {
	case FormatJSON, FormatNDJSON:
		emitJSONError(code, err, format == FormatJSON)
	default:
		fmt.Fprintln(errWriter, err.Error())
	}
	return exit
}

// classify maps any Go error to a (code, exit) pair.
func classify(err error) (ErrorCode, ExitCode) {
	// 1. API response errors (the common path for any HTTP failure).
	var apiErr *api.ResponseError
	if errors.As(err, &apiErr) {
		return classifyHTTPStatus(apiErr.StatusCode)
	}

	// 2. Wrapped sentinel errors (callers signal category explicitly).
	switch {
	case errors.Is(err, ErrUsage):
		return CodeUsage, ExitUsage
	case errors.Is(err, ErrInvalidInput):
		return CodeInvalidInput, ExitInvalidInput
	case errors.Is(err, ErrAuth):
		return CodeAuth, ExitAuth
	case errors.Is(err, ErrForbidden):
		return CodeForbidden, ExitForbidden
	case errors.Is(err, ErrNotFound):
		return CodeNotFound, ExitNotFound
	case errors.Is(err, ErrNetwork):
		return CodeNetwork, ExitNetwork
	case errors.Is(err, ErrServer):
		return CodeServer, ExitServer
	case errors.Is(err, ErrConflict):
		return CodeConflict, ExitConflict
	case errors.Is(err, ErrSealed):
		return CodeSealed, ExitSealed
	}

	// 3. Network/transport errors (DNS, connection refused, timeout, TLS).
	if isNetworkError(err) {
		return CodeNetwork, ExitNetwork
	}

	// 4. Cobra usage errors (unknown flag, missing required flag, arg count).
	if isCobraUsageError(err) {
		return CodeUsage, ExitUsage
	}

	return CodeUnknown, ExitUnknown
}

func classifyHTTPStatus(status int) (ErrorCode, ExitCode) {
	switch {
	case status == 401:
		return CodeAuth, ExitAuth
	case status == 403:
		return CodeForbidden, ExitForbidden
	case status == 404:
		return CodeNotFound, ExitNotFound
	case status == 409:
		return CodeConflict, ExitConflict
	case status >= 500:
		return CodeServer, ExitServer
	case status >= 400:
		// 400, 422, and other 4xx that aren't specifically classified above.
		return CodeInvalidInput, ExitInvalidInput
	default:
		return CodeUnknown, ExitUnknown
	}
}

// isNetworkError reports whether err originates from the network layer.
// `net.Error` covers both `*url.Error` (which implements the interface) and
// lower-level types like `*net.OpError` and `*net.DNSError`.
func isNetworkError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr)
}

// cobraUsageErrorPrefixes are the leading substrings of error messages emitted
// by Cobra/pflag when the user mis-invokes the CLI (unknown flag, missing
// required flag, wrong arg count). Pattern matching is the only reliable way
// to detect these — Cobra/pflag don't expose typed error values.
var cobraUsageErrorPrefixes = []string{
	"unknown flag",
	"unknown shorthand flag",
	"unknown command",
	"required flag",
	"flag accessed but not defined",
	"flag needs an argument",
	"accepts at most",
	"accepts at least",
	"accepts between",
	"requires at least",
	"accepts ",
	"invalid argument",
}

func isCobraUsageError(err error) bool {
	msg := err.Error()
	for _, p := range cobraUsageErrorPrefixes {
		if strings.HasPrefix(msg, p) {
			return true
		}
	}
	return false
}

func emitJSONError(code ErrorCode, err error, pretty bool) {
	we := WardenError{
		Code:    code,
		Message: humanMessage(err),
		Hint:    DefaultHint(code),
	}
	envelope := map[string]any{"error": we}
	var b []byte
	if pretty {
		b, _ = json.MarshalIndent(envelope, "", "  ")
	} else {
		b, _ = json.Marshal(envelope)
	}
	fmt.Fprintln(errWriter, string(b))
}

// humanMessage returns the cleanest human-readable string for err, preferring
// the API-returned error list when available over the verbose ResponseError
// "Error making API request..." default.
func humanMessage(err error) string {
	var apiErr *api.ResponseError
	if errors.As(err, &apiErr) && len(apiErr.Errors) > 0 {
		return strings.Join(apiErr.Errors, "; ")
	}
	return err.Error()
}

// DefaultHint returns a short recovery suggestion for a category, or "" if
// there's no generic hint that fits. Auth hint references the implicit auth
// surfaces (env-var token, mTLS cert, bearer JWT).
func DefaultHint(code ErrorCode) string {
	switch code {
	case CodeAuth:
		return "Set WARDEN_TOKEN, configure WARDEN_CLIENT_CERT/WARDEN_CLIENT_KEY for mTLS, or pass an Authorization: Bearer JWT"
	case CodeForbidden:
		return "Your identity does not have permission for this operation; check your role or policy"
	case CodeNetwork:
		return "Check that the warden server is reachable (WARDEN_ADDR)"
	case CodeServer:
		return "The warden server returned an internal error; check server logs"
	case CodeConflict:
		return "The resource already exists or has been modified concurrently"
	case CodeSealed:
		return "Unseal warden with `warden operator unseal` (or initialize it with `warden operator init`)"
	case CodeUsage:
		return "Run with --help for usage"
	default:
		return ""
	}
}
