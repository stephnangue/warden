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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
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
	// "http_put", "s3", or "azure_blob".
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
	Prefix          string `json:"prefix,omitempty"` // shared with azure_blob (in-container blob-name prefix)
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`

	// azure_blob: Shared Key auth to an Azure Storage container. AccountKey is a
	// stored static secret (masked); it never expires, and the storage account's
	// two-key model keeps it rotation-ready (a rotation follow-on regenerates the
	// inactive key and swaps AccountKey). Prefix above is reused as the blob-name
	// prefix within the container. Endpoint overrides the service URL (for a
	// sovereign cloud, a private endpoint, or a test/emulator); empty defaults to
	// the public-cloud host for AccountName.
	AccountName string `json:"account_name,omitempty"`
	Container   string `json:"container,omitempty"`
	AccountKey  string `json:"account_key,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
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
	case "azure_blob":
		return newAzureBlobPublisher(cfg, cacheControl)
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

// azureUploadTimeout bounds a single blob upload, matching the http_put
// publisher's per-request timeout so a slow/flaky endpoint cannot stall a
// rotation (which runs off the request path and has no outer deadline).
const azureUploadTimeout = 15 * time.Second

// azureBlobPublisher uploads the documents to an Azure Storage container using a
// Shared Key (account name + account key). Like the S3 publisher this is an
// infra-scoped write credential used only on rotation (rare), distinct from the
// per-agent secrets WIF removes. The account key never expires; regenerating and
// swapping it (the storage account's two-key model) is a planned rotation follow-on.
type azureBlobPublisher struct {
	client       *azblob.Client
	container    string
	prefix       string
	cacheControl string
}

func newAzureBlobPublisher(cfg publisherConfig, cacheControl string) (JWKSPublisher, error) {
	if cfg.AccountName == "" || cfg.Container == "" {
		return nil, fmt.Errorf("oidc publisher: azure_blob requires 'account_name' and 'container'")
	}
	if cfg.AccountKey == "" {
		return nil, fmt.Errorf("oidc publisher: azure_blob requires 'account_key'")
	}
	cred, err := azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
	if err != nil {
		return nil, fmt.Errorf("oidc publisher: azure_blob credential: %w", err)
	}
	// Default to the public-cloud host; an explicit endpoint covers sovereign
	// clouds (Government/China), a private endpoint, or a test emulator (Azurite).
	serviceURL := cfg.Endpoint
	if serviceURL == "" {
		serviceURL = fmt.Sprintf("https://%s.blob.core.windows.net/", cfg.AccountName)
	}
	client, err := azblob.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc publisher: azure_blob client: %w", err)
	}
	return &azureBlobPublisher{
		client:       client,
		container:    cfg.Container,
		prefix:       strings.Trim(cfg.Prefix, "/"),
		cacheControl: cacheControl,
	}, nil
}

func (p *azureBlobPublisher) Type() string { return "azure_blob" }

func (p *azureBlobPublisher) Publish(ctx context.Context, discovery, jwks []byte) error {
	if err := p.put(ctx, oidcDiscoveryObjectPath, discovery); err != nil {
		return err
	}
	return p.put(ctx, oidcJWKSObjectPath, jwks)
}

func (p *azureBlobPublisher) put(ctx context.Context, name string, body []byte) error {
	blobName := name
	if p.prefix != "" {
		blobName = p.prefix + "/" + name
	}
	headers := &blob.HTTPHeaders{BlobContentType: to.Ptr("application/json")}
	if p.cacheControl != "" {
		headers.BlobCacheControl = to.Ptr(p.cacheControl)
	}
	ctx, cancel := context.WithTimeout(ctx, azureUploadTimeout)
	defer cancel()
	_, err := p.client.UploadBuffer(ctx, p.container, blobName, body, &azblob.UploadBufferOptions{
		HTTPHeaders: headers,
	})
	if err != nil {
		return fmt.Errorf("oidc publisher: azure_blob upload %s: %w", blobName, err)
	}
	return nil
}
