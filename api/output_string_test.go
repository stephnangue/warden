package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

func TestOutputStringError_Error(t *testing.T) {
	req, _ := retryablehttp.NewRequest(http.MethodGet, "http://localhost:8400/v1/test", nil)
	d := &OutputStringError{
		Request: req,
	}

	errMsg := d.Error()
	if errMsg != ErrOutputStringRequest {
		t.Errorf("expected %q, got %q", ErrOutputStringRequest, errMsg)
	}
}

func TestOutputStringError_CurlString(t *testing.T) {
	req, _ := retryablehttp.NewRequest(http.MethodGet, "http://localhost:8400/v1/test", nil)
	d := &OutputStringError{
		Request: req,
	}

	cs, err := d.CurlString()
	if err != nil {
		t.Fatalf("CurlString failed: %v", err)
	}
	if !strings.Contains(cs, "curl") {
		t.Errorf("expected curl command, got %q", cs)
	}
	if !strings.Contains(cs, "localhost:8400") {
		t.Errorf("expected URL in curl, got %q", cs)
	}
}

func TestOutputStringError_CurlString_WithOptions(t *testing.T) {
	req, _ := retryablehttp.NewRequest(http.MethodPost, "http://localhost:8400/v1/test", strings.NewReader(`{"key":"val"}`))
	d := &OutputStringError{
		Request:       req,
		TLSSkipVerify: true,
		ClientCACert:  "/path/to/ca.crt",
		ClientCAPath:  "/path/to/ca/",
		ClientCert:    "/path/to/cert.pem",
		ClientKey:     "/path/to/key.pem",
	}

	cs, err := d.CurlString()
	if err != nil {
		t.Fatalf("CurlString failed: %v", err)
	}
	if !strings.Contains(cs, "--insecure") {
		t.Error("expected --insecure flag")
	}
	if !strings.Contains(cs, "-X POST") {
		t.Error("expected -X POST")
	}
	if !strings.Contains(cs, "--cacert") {
		t.Error("expected --cacert")
	}
	if !strings.Contains(cs, "--capath") {
		t.Error("expected --capath")
	}
	if !strings.Contains(cs, "--cert") {
		t.Error("expected --cert")
	}
	if !strings.Contains(cs, "--key") {
		t.Error("expected --key")
	}
	if !strings.Contains(cs, "-d '") {
		t.Error("expected body data")
	}
}

func TestOutputStringError_CurlString_Cached(t *testing.T) {
	req, _ := retryablehttp.NewRequest(http.MethodGet, "http://localhost/v1/test", nil)
	d := &OutputStringError{
		Request: req,
	}

	cs1, _ := d.CurlString()
	cs2, _ := d.CurlString()
	if cs1 != cs2 {
		t.Error("expected cached result")
	}
}

func TestOutputStringError_Error_Cached(t *testing.T) {
	rawReq := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: "localhost", Path: "/v1/test"},
	}
	req := &retryablehttp.Request{Request: rawReq}
	d := &OutputStringError{
		Request:         req,
		finalCurlString: "cached-curl",
	}

	errMsg := d.Error()
	if errMsg != ErrOutputStringRequest {
		t.Errorf("expected %q, got %q", ErrOutputStringRequest, errMsg)
	}
}
