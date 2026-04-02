package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestResponse_DecodeJSON(t *testing.T) {
	body := `{"key":"value","num":42}`
	resp := &Response{
		Response: &http.Response{
			Body: io.NopCloser(strings.NewReader(body)),
		},
	}

	var out map[string]interface{}
	err := resp.DecodeJSON(&out)
	if err != nil {
		t.Fatalf("DecodeJSON failed: %v", err)
	}
	if out["key"] != "value" {
		t.Errorf("expected value, got %v", out["key"])
	}
}

func TestResponse_Error_Success(t *testing.T) {
	resp := &Response{
		Response: &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("")),
		},
	}
	if err := resp.Error(); err != nil {
		t.Errorf("expected no error for 200, got %v", err)
	}
}

func TestResponse_Error_LegacyFormat(t *testing.T) {
	body := `{"errors":["permission denied","token expired"]}`
	url, _ := http.NewRequest("GET", "http://example.com/v1/test", nil)
	resp := &Response{
		Response: &http.Response{
			StatusCode: 403,
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    url,
		},
	}

	err := resp.Error()
	if err == nil {
		t.Fatal("expected error for 403")
	}
	respErr, ok := err.(*ResponseError)
	if !ok {
		t.Fatalf("expected *ResponseError, got %T", err)
	}
	if len(respErr.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d", len(respErr.Errors))
	}
	if respErr.StatusCode != 403 {
		t.Errorf("expected 403, got %d", respErr.StatusCode)
	}
}

func TestResponse_Error_HumaFormat(t *testing.T) {
	body := `{"title":"Forbidden","detail":"you lack permission"}`
	url, _ := http.NewRequest("POST", "http://example.com/v1/test", nil)
	resp := &Response{
		Response: &http.Response{
			StatusCode: 403,
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    url,
		},
	}

	err := resp.Error()
	if err == nil {
		t.Fatal("expected error")
	}
	respErr := err.(*ResponseError)
	if len(respErr.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(respErr.Errors))
	}
	if respErr.Errors[0] != "Forbidden: you lack permission" {
		t.Errorf("unexpected error message: %s", respErr.Errors[0])
	}
}

func TestResponse_Error_RawBody(t *testing.T) {
	body := `not json at all`
	url, _ := http.NewRequest("GET", "http://example.com/v1/test", nil)
	resp := &Response{
		Response: &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    url,
		},
	}

	err := resp.Error()
	if err == nil {
		t.Fatal("expected error")
	}
	respErr := err.(*ResponseError)
	if !respErr.RawError {
		t.Error("expected RawError=true")
	}
	if respErr.Errors[0] != "not json at all" {
		t.Errorf("expected raw body, got %s", respErr.Errors[0])
	}
}

func TestResponse_Error_EmptyErrorsAndDetail(t *testing.T) {
	body := `{"some_field":"value"}`
	url, _ := http.NewRequest("GET", "http://example.com/v1/test", nil)
	resp := &Response{
		Response: &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    url,
		},
	}

	err := resp.Error()
	if err == nil {
		t.Fatal("expected error")
	}
	respErr := err.(*ResponseError)
	if !respErr.RawError {
		t.Error("expected RawError=true when no errors or detail")
	}
}

func TestResponseError_Error(t *testing.T) {
	re := &ResponseError{
		HTTPMethod: "GET",
		URL:        "http://example.com/v1/test",
		StatusCode: 403,
		Errors:     []string{"denied"},
	}
	s := re.Error()
	if s == "" {
		t.Error("expected non-empty error string")
	}

	// Raw error
	reRaw := &ResponseError{
		HTTPMethod: "GET",
		URL:        "http://example.com/v1/test",
		StatusCode: 500,
		RawError:   true,
		Errors:     []string{"raw body content"},
	}
	s2 := reRaw.Error()
	if s2 == "" {
		t.Error("expected non-empty error string")
	}
}

func TestResponse_Error_HealthStandby429(t *testing.T) {
	url, _ := http.NewRequest("GET", "http://example.com/v1/sys/health", nil)
	resp := &Response{
		Response: &http.Response{
			StatusCode: 429,
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    url,
		},
	}
	if err := resp.Error(); err != nil {
		t.Errorf("expected no error for 429 on health endpoint, got %v", err)
	}
}
