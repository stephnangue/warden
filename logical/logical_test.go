package logical

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	multierror "github.com/hashicorp/go-multierror"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Response tests ---

func TestNewResponse(t *testing.T) {
	r := NewResponse()
	assert.Equal(t, http.StatusOK, r.StatusCode)
	assert.NotNil(t, r.Headers)
}

func TestResponse_IsError(t *testing.T) {
	t.Run("no error", func(t *testing.T) {
		r := &Response{StatusCode: 200}
		assert.False(t, r.IsError())
	})

	t.Run("error status", func(t *testing.T) {
		r := &Response{StatusCode: 400}
		assert.True(t, r.IsError())
	})

	t.Run("500 error", func(t *testing.T) {
		r := &Response{StatusCode: 500}
		assert.True(t, r.IsError())
	})

	t.Run("with err set", func(t *testing.T) {
		r := &Response{Err: errors.New("fail")}
		assert.True(t, r.IsError())
	})
}

func TestResponse_Error(t *testing.T) {
	r := &Response{Err: errors.New("test error")}
	assert.Equal(t, "test error", r.Error().Error())

	r2 := &Response{}
	assert.Nil(t, r2.Error())
}

func TestResponse_SetHeader(t *testing.T) {
	r := &Response{}
	r.SetHeader("Content-Type", "application/json")
	assert.Equal(t, "application/json", r.Headers.Get("Content-Type"))
}

func TestResponse_AddHeader(t *testing.T) {
	r := &Response{}
	r.AddHeader("X-Custom", "val1")
	r.AddHeader("X-Custom", "val2")
	assert.Equal(t, []string{"val1", "val2"}, r.Headers.Values("X-Custom"))
}

func TestResponse_AddWarning(t *testing.T) {
	r := &Response{}
	r.AddWarning("warning 1")
	r.AddWarning("warning 2")
	assert.Len(t, r.Warnings, 2)
}

// --- CodedError tests ---

func TestCodedError_Error(t *testing.T) {
	t.Run("message only", func(t *testing.T) {
		e := &CodedError{Status: 400, Message: "bad request"}
		assert.Equal(t, "bad request", e.Error())
	})

	t.Run("with wrapped error", func(t *testing.T) {
		inner := errors.New("inner")
		e := &CodedError{Status: 500, Message: "outer", Err: inner}
		assert.Equal(t, "outer: inner", e.Error())
	})
}

func TestCodedError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	e := &CodedError{Status: 500, Message: "outer", Err: inner}
	assert.Equal(t, inner, e.Unwrap())
}

func TestCodedError_Code(t *testing.T) {
	e := &CodedError{Status: 404}
	assert.Equal(t, 404, e.Code())
}

func TestErrorConstructors(t *testing.T) {
	tests := []struct {
		name   string
		err    *CodedError
		status int
	}{
		{"BadRequest", ErrBadRequest("msg"), 400},
		{"BadRequestf", ErrBadRequestf("msg %d", 1), 400},
		{"NotFound", ErrNotFound("msg"), 404},
		{"NotFoundf", ErrNotFoundf("msg %d", 1), 404},
		{"Conflict", ErrConflict("msg"), 409},
		{"Conflictf", ErrConflictf("msg %d", 1), 409},
		{"Unauthorized", ErrUnauthorized("msg"), 401},
		{"Unauthorizedf", ErrUnauthorizedf("msg %d", 1), 401},
		{"Forbidden", ErrForbidden("msg"), 403},
		{"Forbiddenf", ErrForbiddenf("msg %d", 1), 403},
		{"Internal", ErrInternal("msg"), 500},
		{"Internalf", ErrInternalf("msg %d", 1), 500},
		{"ServiceUnavailable", ErrServiceUnavailable("msg"), 503},
		{"ServiceUnavailablef", ErrServiceUnavailablef("msg %d", 1), 503},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.status, tc.err.Code())
			assert.NotEmpty(t, tc.err.Error())
		})
	}
}

func TestWrapWithCode(t *testing.T) {
	inner := errors.New("original")
	wrapped := WrapWithCode(502, inner)
	assert.Equal(t, 502, wrapped.Code())
	assert.Equal(t, inner, wrapped.Unwrap())
}

// permDeniedWrapper mirrors core.ErrMCPPolicyDenied: a typed error that
// Unwraps to the permission-denied sentinel. Used to prove GetErrorCode
// traverses wrapping the same way the HTTP status mapping does.
type permDeniedWrapper struct{}

func (permDeniedWrapper) Error() string { return "boom" }
func (permDeniedWrapper) Unwrap() error { return sdklogical.ErrPermissionDenied }

// unwrapsToNil is a real error that implements Unwrap() but returns no inner
// error — like a token-endpoint error carrying only a parsed OAuth code.
type unwrapsToNil struct{}

func (unwrapsToNil) Error() string { return "boom" }
func (unwrapsToNil) Unwrap() error { return nil }

func TestGetErrorCode(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		assert.Equal(t, 200, GetErrorCode(nil))
	})

	t.Run("coded error", func(t *testing.T) {
		assert.Equal(t, 404, GetErrorCode(ErrNotFound("not found")))
	})

	t.Run("plain error", func(t *testing.T) {
		assert.Equal(t, 500, GetErrorCode(errors.New("fail")))
	})

	t.Run("wrapped coded error", func(t *testing.T) {
		inner := ErrNotFound("not found")
		wrapped := fmt.Errorf("wrap: %w", inner)
		assert.Equal(t, 404, GetErrorCode(wrapped))
	})

	t.Run("error whose Unwrap returns nil is 500, not 200", func(t *testing.T) {
		// A real failure that implements Unwrap() but has no inner error (e.g. an
		// OAuth token-endpoint error carrying only a parsed error code) must not
		// recurse into GetErrorCode(nil) and report success.
		assert.Equal(t, 500, GetErrorCode(unwrapsToNil{}))
		assert.Equal(t, 500, GetErrorCode(fmt.Errorf("wrap: %w", unwrapsToNil{})))
	})

	// SDK sentinel errors must map to their HTTP status even when wrapped or
	// appended into a multierror — otherwise the audit log records 500 for a
	// denial the client received as 403.
	t.Run("permission denied sentinel", func(t *testing.T) {
		assert.Equal(t, 403, GetErrorCode(sdklogical.ErrPermissionDenied))
	})

	t.Run("permission denied in multierror", func(t *testing.T) {
		assert.Equal(t, 403, GetErrorCode(multierror.Append(nil, sdklogical.ErrPermissionDenied)))
	})

	t.Run("permission denied via Unwrap in multierror", func(t *testing.T) {
		assert.Equal(t, 403, GetErrorCode(multierror.Append(nil, permDeniedWrapper{})))
	})

	t.Run("unsupported operation", func(t *testing.T) {
		assert.Equal(t, 405, GetErrorCode(sdklogical.ErrUnsupportedOperation))
	})

	t.Run("unsupported path", func(t *testing.T) {
		assert.Equal(t, 404, GetErrorCode(sdklogical.ErrUnsupportedPath))
	})

	t.Run("invalid request wrapped", func(t *testing.T) {
		assert.Equal(t, 400, GetErrorCode(fmt.Errorf("ctx: %w", sdklogical.ErrInvalidRequest)))
	})
}

// TestErrorResponse_PermissionDeniedStatus is the end-to-end assertion for the
// reported bug: an ErrorResponse built from a permission denial (as the request
// handler does on a failed token check) must carry 403 so the audit log records
// the same status the client received on the wire.
func TestErrorResponse_PermissionDeniedStatus(t *testing.T) {
	resp := ErrorResponse(multierror.Append(nil, sdklogical.ErrPermissionDenied))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestIsNotFound(t *testing.T) {
	assert.True(t, IsNotFound(ErrNotFound("gone")))
	assert.False(t, IsNotFound(ErrBadRequest("bad")))
	assert.False(t, IsNotFound(errors.New("plain")))
}

func TestErrorResponse(t *testing.T) {
	err := ErrBadRequest("invalid input")
	resp := ErrorResponse(err)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, err, resp.Err)
}

func TestErrorMessages(t *testing.T) {
	denied := fmt.Errorf("role %q is not assumable: %w", "ops", sdklogical.ErrPermissionDenied)
	gathered := multierror.Append(nil, denied)

	for _, tc := range []struct {
		name string
		err  error
		want []string
	}{
		{"nil", nil, nil},
		{"plain error", errors.New("plain"), []string{"plain"}},
		{"one gathered error reads as itself", gathered, []string{denied.Error()}},
		{"several gathered errors are each kept", multierror.Append(errors.New("first"), errors.New("second")), []string{"first", "second"}},
		{"nested multierrors flatten", &multierror.Error{Errors: []error{&multierror.Error{Errors: []error{errors.New("inner")}}, errors.New("outer")}}, []string{"inner", "outer"}},
		{"an empty multierror keeps its text", &multierror.Error{}, []string{(&multierror.Error{}).Error()}},
		{"a wrapped multierror keeps its context", fmt.Errorf("context: %w", gathered), []string{fmt.Errorf("context: %w", gathered).Error()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ErrorMessages(tc.err))
		})
	}

	// Unpacking the messages leaves the status alone.
	assert.Equal(t, http.StatusForbidden, ErrorResponse(gathered).StatusCode)
}

// --- BackendClass tests ---

func TestBackendClass_String(t *testing.T) {
	assert.Equal(t, "provider", ClassProvider.String())
	assert.Equal(t, "auth", ClassAuth.String())
	assert.Equal(t, "system", ClassSystem.String())
	assert.Equal(t, "unknown", ClassUnknown.String())
}

// --- TokenEntry tests ---

func TestTokenEntry_MarkUsed(t *testing.T) {
	te := &TokenEntry{}
	assert.False(t, te.IsUsed())
	te.MarkUsed()
	assert.True(t, te.IsUsed())
}

// --- Request tests ---

func TestRequest_TokenEntry(t *testing.T) {
	r := &Request{}
	assert.Nil(t, r.TokenEntry())

	te := &TokenEntry{ID: "test-id"}
	r.SetTokenEntry(te)
	require.NotNil(t, r.TokenEntry())
	assert.Equal(t, "test-id", r.TokenEntry().ID)
}

// Media types are case-insensitive and +json types are JSON, so a caller cannot
// relabel a JSON body to keep policy from reading it.
func TestBodyMediaType(t *testing.T) {
	tests := []struct {
		contentType string
		mediaType   string
		json        bool
	}{
		{"", "", true},
		{"application/json", "application/json", true},
		{"Application/JSON", "application/json", true},
		{"application/json; charset=utf-8", "application/json", true},
		{"application/json;;", "application/json", true}, // malformed parameter
		{"text/json", "text/json", true},
		{"application/vnd.api+json", "application/vnd.api+json", true},
		{"application/merge-patch+json", "application/merge-patch+json", true},
		{"application/x-www-form-urlencoded", "application/x-www-form-urlencoded", false},
		{"text/plain", "text/plain", false},
		{"application/jsonl", "application/jsonl", false}, // a stream of documents, not one
		{"application/json+protobuf", "application/json+protobuf", false},
		{"multipart/form-data; boundary=x", "multipart/form-data", false},
		{" Application/JSON ; charset=utf-8", "application/json", true},
		{"application/json; a=1; a=2", "application/json", true}, // a parameter mime.ParseMediaType refuses
		{"application json", "application json", false},          // not a media type at all
		{"application/x+jſon", "application/x+jſon", false},      // U+017F folds to s, but is not one
		{"   ", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			got := BodyMediaType(tt.contentType)
			assert.Equal(t, tt.mediaType, got)
			assert.Equal(t, tt.json, IsJSONMediaType(got))
		})
	}
}

// A label is one media type, read the same by whoever reads all of it.
func TestIsMediaTypeLabel(t *testing.T) {
	for _, label := range []string{
		"application/json",
		"Application/JSON",
		"application/json; charset=utf-8",
		"application/json;charset=UTF-8",
		"application/json ;charset=utf-8",
		"application/json; charset = utf-8", // spaces mime.ParseMediaType accepts
		"application/json;",
		"application/json;; charset=utf-8;",
		`application/json; charset="utf-8"`,
		`application/json; x="a \"quoted\"; value, with a comma"`,
		"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
		"application/x-git-upload-pack-request",
	} {
		assert.True(t, IsMediaTypeLabel(label), label)
	}
	for _, label := range []string{
		"",
		" ",
		"json",
		"application/",
		"/json",
		"application/x-www-form-urlencoded, application/x+json",
		"application/x-www-form-urlencoded; a=b, application/json",
		"application/x-www-form-urlencoded;, application/json",
		"application/json; a=b, application/x-www-form-urlencoded",
		"application/json; charset",
		"application/json; charset=",
		`application/json; charset="utf-8`,
		`application/json; charset="utf-8" x`,
		"application/json; charset=\"a\x01b\"",
		" application/json",
		"applİcation/json",
		"application/json; charset=utf‑8",
	} {
		assert.False(t, IsMediaTypeLabel(label), label)
	}

	assert.Zero(t, testing.AllocsPerRun(100, func() {
		_ = IsMediaTypeLabel(`multipart/form-data; boundary="b"; charset=utf-8`)
	}))
}
