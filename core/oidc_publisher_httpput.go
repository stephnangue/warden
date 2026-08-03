package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// httpPutPublisher PUTs each document under an operator-owned origin (a Cloudflare
// Worker/R2 endpoint, CDN, or authenticated proxy), authenticating with a header.
type httpPutPublisher struct {
	baseURL      string
	authHeader   string
	authValue    string
	cacheControl string
	client       *http.Client
}

func newHTTPPutPublisher(cfg publisherConfig, cacheControl string) (JWKSPublisher, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("oidc publisher: http_put requires 'base_url'")
	}
	authHeader := cfg.Autheader
	if authHeader == "" {
		authHeader = "Authorization"
	}
	return &httpPutPublisher{
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		authHeader:   authHeader,
		authValue:    cfg.AuthValue,
		cacheControl: cacheControl,
		client:       &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (p *httpPutPublisher) Type() string { return "http_put" }

func (p *httpPutPublisher) Publish(ctx context.Context, discovery, jwks []byte) error {
	if err := p.put(ctx, "/"+oidcDiscoveryObjectPath, discovery); err != nil {
		return err
	}
	return p.put(ctx, "/"+oidcJWKSObjectPath, jwks)
}

func (p *httpPutPublisher) put(ctx context.Context, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("oidc publisher: build PUT %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cacheControl != "" {
		req.Header.Set("Cache-Control", p.cacheControl)
	}
	if p.authValue != "" {
		req.Header.Set(p.authHeader, p.authValue)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc publisher: PUT %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("oidc publisher: PUT %s returned status %d", path, resp.StatusCode)
	}
	return nil
}
