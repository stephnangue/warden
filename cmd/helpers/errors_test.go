package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/stephnangue/warden/api"
)

func TestClassifyHTTPStatus(t *testing.T) {
	tests := []struct {
		status   int
		wantCode ErrorCode
		wantExit ExitCode
	}{
		{401, CodeAuth, ExitAuth},
		{403, CodeForbidden, ExitForbidden},
		{404, CodeNotFound, ExitNotFound},
		{409, CodeConflict, ExitConflict},
		{400, CodeInvalidInput, ExitInvalidInput},
		{422, CodeInvalidInput, ExitInvalidInput},
		{500, CodeServer, ExitServer},
		{502, CodeServer, ExitServer},
		{503, CodeServer, ExitServer},
		{200, CodeUnknown, ExitUnknown},
	}
	for _, tt := range tests {
		gotCode, gotExit := classifyHTTPStatus(tt.status)
		if gotCode != tt.wantCode || gotExit != tt.wantExit {
			t.Errorf("classifyHTTPStatus(%d) = (%q, %d); want (%q, %d)",
				tt.status, gotCode, gotExit, tt.wantCode, tt.wantExit)
		}
	}
}

func TestClassify_APIResponseErrorWrapped(t *testing.T) {
	apiErr := &api.ResponseError{
		StatusCode: 404,
		Errors:     []string{"path not found"},
	}
	wrapped := fmt.Errorf("failed to read from foo: %w", apiErr)

	code, exit := classify(wrapped)
	if code != CodeNotFound || exit != ExitNotFound {
		t.Fatalf("classify(wrapped 404) = (%q, %d); want (not_found, 6)", code, exit)
	}
}

func TestClassify_Sentinels(t *testing.T) {
	tests := []struct {
		name     string
		sentinel error
		wantCode ErrorCode
		wantExit ExitCode
	}{
		{"usage", ErrUsage, CodeUsage, ExitUsage},
		{"invalid_input", ErrInvalidInput, CodeInvalidInput, ExitInvalidInput},
		{"auth", ErrAuth, CodeAuth, ExitAuth},
		{"forbidden", ErrForbidden, CodeForbidden, ExitForbidden},
		{"not_found", ErrNotFound, CodeNotFound, ExitNotFound},
		{"network", ErrNetwork, CodeNetwork, ExitNetwork},
		{"server", ErrServer, CodeServer, ExitServer},
		{"conflict", ErrConflict, CodeConflict, ExitConflict},
		{"sealed", ErrSealed, CodeSealed, ExitSealed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := fmt.Errorf("context: %w", tt.sentinel)
			code, exit := classify(wrapped)
			if code != tt.wantCode || exit != tt.wantExit {
				t.Errorf("classify(wrap %v) = (%q, %d); want (%q, %d)",
					tt.sentinel, code, exit, tt.wantCode, tt.wantExit)
			}
		})
	}
}

func TestClassify_NetworkError_URL(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://warden.example", Err: errors.New("dial tcp: connection refused")}
	code, exit := classify(err)
	if code != CodeNetwork || exit != ExitNetwork {
		t.Fatalf("classify(*url.Error) = (%q, %d); want (network, 7)", code, exit)
	}
}

func TestClassify_NetworkError_NetOpError(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	code, exit := classify(err)
	if code != CodeNetwork || exit != ExitNetwork {
		t.Fatalf("classify(*net.OpError) = (%q, %d); want (network, 7)", code, exit)
	}
}

func TestClassify_CobraUsagePrefixes(t *testing.T) {
	tests := []string{
		`unknown flag: --foo`,
		`unknown shorthand flag: 'q' in -q`,
		`unknown command "bar"`,
		`required flag(s) "type" not set`,
		`accepts at most 1 arg(s), received 3`,
		`accepts at least 1 arg(s), received 0`,
		`accepts 2 arg(s), received 1`,
		`flag needs an argument: --type`,
		`invalid argument "abc" for "--count"`,
	}
	for _, msg := range tests {
		t.Run(msg, func(t *testing.T) {
			err := errors.New(msg)
			code, exit := classify(err)
			if code != CodeUsage || exit != ExitUsage {
				t.Errorf("classify(%q) = (%q, %d); want (usage, 2)", msg, code, exit)
			}
		})
	}
}

func TestClassify_UnknownDefault(t *testing.T) {
	err := errors.New("something exploded")
	code, exit := classify(err)
	if code != CodeUnknown || exit != ExitUnknown {
		t.Errorf("classify(unknown) = (%q, %d); want (unknown, 1)", code, exit)
	}
}

// --- RenderError integration: exit code, JSON envelope, table mode ---

func TestRenderError_Nil(t *testing.T) {
	if got := RenderError(nil); got != ExitOK {
		t.Errorf("RenderError(nil) = %d; want 0", got)
	}
}

func TestRenderError_JSONEnvelope(t *testing.T) {
	_, stderr := setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("json")

	apiErr := &api.ResponseError{StatusCode: 404, Errors: []string{"path not found"}}
	wrapped := fmt.Errorf("failed to read from foo: %w", apiErr)

	exit := RenderError(wrapped)
	if exit != ExitNotFound {
		t.Fatalf("RenderError exit = %d; want %d", exit, ExitNotFound)
	}

	var envelope struct {
		Error WardenError `json:"error"`
	}
	if err := json.Unmarshal(stderr.Bytes(), &envelope); err != nil {
		t.Fatalf("stderr is not valid JSON: %v\noutput: %s", err, stderr.String())
	}
	if envelope.Error.Code != CodeNotFound {
		t.Errorf("envelope.Error.Code = %q; want %q", envelope.Error.Code, CodeNotFound)
	}
	if !strings.Contains(envelope.Error.Message, "path not found") {
		t.Errorf("envelope.Error.Message = %q; want to contain %q", envelope.Error.Message, "path not found")
	}
}

func TestRenderError_NDJSONIsCompactOneLine(t *testing.T) {
	_, stderr := setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("ndjson")

	exit := RenderError(fmt.Errorf("oops: %w", ErrInvalidInput))
	if exit != ExitInvalidInput {
		t.Fatalf("exit = %d; want %d", exit, ExitInvalidInput)
	}

	out := strings.TrimRight(stderr.String(), "\n")
	if strings.Count(out, "\n") != 0 {
		t.Errorf("ndjson error envelope should be one line, got %d newlines:\n%s", strings.Count(out, "\n"), out)
	}
	if !strings.Contains(out, `"code":"invalid_input"`) {
		t.Errorf("expected compact JSON with code field, got: %s", out)
	}
}

func TestRenderError_TableModeEmitsHumanMessage(t *testing.T) {
	_, stderr := setupCapture(t)
	t.Cleanup(func() { SetOutputFormat("") })
	SetOutputFormat("table")

	exit := RenderError(fmt.Errorf("path %q is not allowed: %w", "../etc/passwd", ErrInvalidInput))
	if exit != ExitInvalidInput {
		t.Fatalf("exit = %d; want %d", exit, ExitInvalidInput)
	}
	got := stderr.String()
	if !strings.Contains(got, "../etc/passwd") {
		t.Errorf("table-mode stderr should contain the human message, got: %s", got)
	}
	if strings.Contains(got, `"code":`) {
		t.Errorf("table-mode stderr should NOT contain JSON envelope, got: %s", got)
	}
}

func TestHumanMessage_PrefersAPIErrorList(t *testing.T) {
	apiErr := &api.ResponseError{
		StatusCode: 403,
		Errors:     []string{"permission denied", "policy 'reader' lacks update"},
	}
	wrapped := fmt.Errorf("failed to write to foo/config: %w", apiErr)

	got := humanMessage(wrapped)
	want := "permission denied; policy 'reader' lacks update"
	if got != want {
		t.Errorf("humanMessage = %q; want %q", got, want)
	}
}

func TestDefaultHint_PerCategory(t *testing.T) {
	// At minimum, the categories with non-empty defaults should produce text.
	for _, code := range []ErrorCode{CodeAuth, CodeForbidden, CodeNetwork, CodeServer, CodeConflict, CodeSealed, CodeUsage} {
		if DefaultHint(code) == "" {
			t.Errorf("DefaultHint(%q) returned empty; want non-empty hint", code)
		}
	}
	// Categories without a useful generic hint are empty.
	for _, code := range []ErrorCode{CodeInvalidInput, CodeNotFound, CodeUnknown} {
		if DefaultHint(code) != "" {
			t.Errorf("DefaultHint(%q) = %q; want empty (no generic hint fits)", code, DefaultHint(code))
		}
	}
}
