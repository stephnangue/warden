package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRequest_ResetJSONBody(t *testing.T) {
	r := &Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "http", Host: "localhost"},
		Params: url.Values{},
	}

	// nil BodyBytes - noop
	err := r.ResetJSONBody()
	if err != nil {
		t.Fatalf("ResetJSONBody on nil should not error: %v", err)
	}

	// Set a body then reset
	err = r.SetJSONBody(map[string]string{"key": "val"})
	if err != nil {
		t.Fatalf("SetJSONBody failed: %v", err)
	}
	original := string(r.BodyBytes)

	err = r.ResetJSONBody()
	if err != nil {
		t.Fatalf("ResetJSONBody failed: %v", err)
	}
	if string(r.BodyBytes) != original {
		t.Errorf("expected same body after reset")
	}
}

func TestRequest_SetJSONBody_Nil(t *testing.T) {
	r := &Request{}
	err := r.SetJSONBody(nil)
	if err != nil {
		t.Fatalf("expected no error for nil body, got %v", err)
	}
	if r.BodyBytes != nil {
		t.Error("expected nil BodyBytes for nil input")
	}
}

func TestRequest_toRetryableHTTP(t *testing.T) {
	r := &Request{
		Method:      http.MethodPost,
		URL:         &url.URL{Scheme: "http", Host: "localhost:8400", Path: "/v1/test"},
		Params:      url.Values{"key": {"val"}},
		Headers:     http.Header{"X-Custom": {"header-val"}},
		ClientToken: "my-token",
	}
	r.SetJSONBody(map[string]string{"a": "b"})

	req, err := r.toRetryableHTTP()
	if err != nil {
		t.Fatalf("toRetryableHTTP failed: %v", err)
	}
	if req.Header.Get("X-Custom") != "header-val" {
		t.Errorf("expected custom header")
	}
	if req.Header.Get("X-Warden-Token") != "my-token" {
		t.Errorf("expected warden token header")
	}
}

func TestRequest_toRetryableHTTP_WithBodyReader(t *testing.T) {
	r := &Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "http", Host: "localhost:8400", Path: "/v1/test"},
		Params: url.Values{},
		Body:   strings.NewReader("raw body"),
	}

	req, err := r.toRetryableHTTP()
	if err != nil {
		t.Fatalf("toRetryableHTTP failed: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
}

func TestRequest_toRetryableHTTP_NoBody(t *testing.T) {
	r := &Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: "localhost:8400", Path: "/v1/test"},
		Params: url.Values{},
	}

	req, err := r.toRetryableHTTP()
	if err != nil {
		t.Fatalf("toRetryableHTTP failed: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
}
