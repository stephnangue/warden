package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// The OIDC issuer's public documents are published under these object paths, so
// their layout matches the served endpoints: an upstream fetching
// <issuer_url>/.well-known/openid-configuration and <issuer_url>/oidc/jwks works
// whether Warden serves them itself or they are pushed to a bucket/CDN.
const (
	oidcDiscoveryObjectPath = ".well-known/openid-configuration"
	oidcJWKSObjectPath      = "oidc/jwks"
)

// publisherConfig selects and configures where the public discovery + JWKS
// documents are pushed. Only public material is ever published; the private
// signing key never leaves Warden.
type publisherConfig struct {
	// Type is "", "none" (serve only from Warden's own endpoint), "local_file",
	// "http_put", or "s3".
	Type string `json:"type,omitempty"`

	// local_file: an external process (with its own credentials) syncs the
	// directory to the bucket/CDN, so Warden holds no bucket write-credential.
	Dir string `json:"dir,omitempty"`

	// http_put: Warden PUTs each document under this origin (e.g. a Cloudflare
	// Worker/R2 endpoint). AuthValue is the write credential — an unauthenticated
	// origin would let anyone overwrite the JWKS (the trust root), so it should
	// always be set unless the origin is protected another way (mTLS/network).
	BaseURL   string `json:"base_url,omitempty"`
	Autheader string `json:"auth_header,omitempty"` // header name; default Authorization
	AuthValue string `json:"auth_value,omitempty"`  // e.g. "Bearer <token>" (masked)

	// s3: stored static credentials (rotation support is a follow-on). Masked.
	Bucket          string `json:"bucket,omitempty"`
	Region          string `json:"region,omitempty"`
	Prefix          string `json:"prefix,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
}

// JWKSPublisher pushes the issuer's public discovery + JWKS documents to an
// external surface (bucket/CDN) so the issuer URL need not be Warden's own
// address. Implementations are selected by publisherConfig.Type.
type JWKSPublisher interface {
	Publish(ctx context.Context, discovery, jwks []byte) error
	Type() string
}

// newJWKSPublisher builds the configured publisher, or (nil, nil) when none is
// configured (the built-in HTTP endpoint remains the surface). cacheControl is
// the Cache-Control header value Warden derives from the JWKS cache TTL and sends
// on uploads, so a verifier refreshes the JWKS before a newly published key signs.
func newJWKSPublisher(cfg publisherConfig, cacheControl string) (JWKSPublisher, error) {
	switch cfg.Type {
	case "", "none":
		return nil, nil
	case "local_file":
		if cfg.Dir == "" {
			return nil, fmt.Errorf("oidc publisher: local_file requires 'dir'")
		}
		return &localFilePublisher{dir: cfg.Dir}, nil
	case "http_put":
		return newHTTPPutPublisher(cfg, cacheControl)
	case "s3":
		return newS3Publisher(cfg, cacheControl)
	default:
		return nil, fmt.Errorf("oidc publisher: unsupported type %q", cfg.Type)
	}
}

// localFilePublisher writes the documents to a directory. An external process
// (CI, a sidecar, rclone, aws s3 sync) syncs it to the bucket/CDN, so Warden
// itself needs no bucket write-credential.
type localFilePublisher struct{ dir string }

func (p *localFilePublisher) Type() string { return "local_file" }

func (p *localFilePublisher) Publish(_ context.Context, discovery, jwks []byte) error {
	if err := writeFileEnsureDir(filepath.Join(p.dir, filepath.FromSlash(oidcDiscoveryObjectPath)), discovery); err != nil {
		return err
	}
	return writeFileEnsureDir(filepath.Join(p.dir, filepath.FromSlash(oidcJWKSObjectPath)), jwks)
}

func writeFileEnsureDir(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("oidc publisher: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("oidc publisher: write %s: %w", path, err)
	}
	return nil
}

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

// s3Publisher PutObjects the documents to an S3 bucket using stored static
// credentials. This is an infra-scoped write credential used only on rotation
// (rare), distinct from the per-agent secrets WIF removes. Credential rotation
// is a planned follow-on.
type s3Publisher struct {
	client       *s3.Client
	bucket       string
	prefix       string
	cacheControl string
}

func newS3Publisher(cfg publisherConfig, cacheControl string) (JWKSPublisher, error) {
	if cfg.Bucket == "" || cfg.Region == "" {
		return nil, fmt.Errorf("oidc publisher: s3 requires 'bucket' and 'region'")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("oidc publisher: s3 requires 'access_key_id' and 'secret_access_key'")
	}
	client := s3.New(s3.Options{
		Region:      cfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
	})
	return &s3Publisher{
		client:       client,
		bucket:       cfg.Bucket,
		prefix:       strings.Trim(cfg.Prefix, "/"),
		cacheControl: cacheControl,
	}, nil
}

func (p *s3Publisher) Type() string { return "s3" }

func (p *s3Publisher) Publish(ctx context.Context, discovery, jwks []byte) error {
	if err := p.put(ctx, oidcDiscoveryObjectPath, discovery); err != nil {
		return err
	}
	return p.put(ctx, oidcJWKSObjectPath, jwks)
}

func (p *s3Publisher) put(ctx context.Context, key string, body []byte) error {
	fullKey := key
	if p.prefix != "" {
		fullKey = p.prefix + "/" + key
	}
	input := &s3.PutObjectInput{
		Bucket:      aws.String(p.bucket),
		Key:         aws.String(fullKey),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	}
	if p.cacheControl != "" {
		input.CacheControl = aws.String(p.cacheControl)
	}
	if _, err := p.client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("oidc publisher: s3 PutObject %s: %w", fullKey, err)
	}
	return nil
}
