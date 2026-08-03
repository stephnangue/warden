package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	// "http_put", "s3", "azure_blob", or "gcs".
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
	Endpoint    string `json:"endpoint,omitempty"` // shared with gcs (API endpoint override)

	// gcs: writes to a Google Cloud Storage bucket authenticated by a stored
	// static service-account JSON key. CredentialsJSON is a stored static secret
	// (masked); like the s3/azure_blob keys it is an infra-scoped write credential.
	// Warden can self-rotate it (see RotatablePublisher): on the configured cadence
	// it mints a fresh key via the IAM API, verifies it, swaps it in, and deletes the
	// old one — which requires the service account to hold
	// iam.serviceAccountKeys.create/delete on itself. Bucket above is reused; Prefix
	// is reused as the object-name prefix; Endpoint overrides the storage API endpoint
	// (for a private endpoint or a test/emulator).
	CredentialsJSON string `json:"credentials_json,omitempty"`

	// RotationPeriod, when > 0, enables automatic rotation of the credential-bearing
	// publisher's write key on that cadence (currently gcs only). Empty/0 disables it.
	// A duration string ("720h"); validated and floored server-side.
	RotationPeriod string `json:"rotation_period,omitempty"`
}

// rotationPeriod parses the configured publisher-credential rotation cadence; 0
// (empty or unparseable) disables automatic rotation. The write path parses and
// bounds the value strictly before it is stored, so a stored value is well-formed.
func (c *publisherConfig) rotationPeriod() time.Duration {
	if c.RotationPeriod == "" {
		return 0
	}
	d, err := time.ParseDuration(c.RotationPeriod)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// JWKSPublisher pushes the issuer's public discovery + JWKS documents to an
// external surface (bucket/CDN) so the issuer URL need not be Warden's own
// address. Implementations are selected by publisherConfig.Type.
type JWKSPublisher interface {
	Publish(ctx context.Context, discovery, jwks []byte) error
	Type() string
}

// RotatablePublisher is an optional interface a publisher implements when Warden can
// self-rotate its stored write credential. The rotation loop discovers it by type
// assertion, so a publisher that cannot rotate simply does not implement it.
//
// Rotation is single-stage with verify-before-swap (the credential is off the request
// hot path, and the built-in endpoint always serves, so no timed propagation overlap is
// needed):
//  1. PrepareRotation mints a NEW credential and verifies it works, leaving the old one
//     untouched. It returns the config fields to persist and an opaque handle for
//     deleting the old credential.
//  2. [the loop persists newFields into the publisher config]
//  3. CommitRotation swaps the live in-memory credential to the just-persisted new one.
//  4. CleanupRotation destroys the old credential (best-effort).
type RotatablePublisher interface {
	// SupportsRotation reports whether this publisher instance can rotate its credential.
	SupportsRotation() bool

	// PrepareRotation mints and verifies a new credential without touching the old one.
	// newFields are the publisher-config keys to persist (e.g. {"credentials_json": …});
	// cleanup is the handle CleanupRotation needs to destroy the superseded credential.
	PrepareRotation(ctx context.Context) (newFields, cleanup map[string]string, err error)

	// CommitRotation swaps the live in-memory credential to newFields (already persisted).
	CommitRotation(newFields map[string]string) error

	// CleanupRotation destroys the superseded credential (best-effort).
	CleanupRotation(ctx context.Context, cleanup map[string]string) error

	// RollbackRotation destroys a credential that PrepareRotation minted but that was
	// never persisted or committed (e.g. persistence failed), so a failed rotation does
	// not leak a live-but-unreferenced credential. Best-effort.
	RollbackRotation(ctx context.Context, newFields map[string]string) error
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
	case "gcs":
		return newGCSPublisher(cfg, cacheControl)
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

// gcsUploadTimeout bounds a single object upload, matching the other cloud
// publishers' per-upload timeout so a slow/flaky endpoint cannot stall a rotation
// (which runs off the request path and has no outer deadline).
const gcsUploadTimeout = 15 * time.Second

// gcsDefaultEndpoint is the public Cloud Storage host; Endpoint overrides it for a
// private endpoint or a test server.
const gcsDefaultEndpoint = "https://storage.googleapis.com"

// gcsScope is the OAuth2 scope needed to write objects.
const gcsScope = "https://www.googleapis.com/auth/devstorage.read_write"

// gcsPublisher uploads the documents to a Google Cloud Storage bucket over the
// single-request upload API, authenticated by an OAuth2 token minted from a stored
// static service-account JSON key. Like the S3/Azure publishers this is an
// infra-scoped write credential used only on rotation (rare), distinct from the
// per-agent secrets WIF removes. The key does not expire; regenerating and swapping
// it is a planned rotation follow-on. Uploading directly rather than via the cloud
// SDK keeps the credential path identical to the source drivers and avoids a large
// dependency for two small PUTs.
type gcsPublisher struct {
	// mu guards the mutable credential (tokenSource + credentialsJSON), which
	// CommitRotation swaps in place while Publish may be reading it concurrently.
	mu              sync.RWMutex
	tokenSource     oauth2.TokenSource
	credentialsJSON string // raw SA key JSON, retained for rotation

	endpoint     string
	bucket       string
	prefix       string
	cacheControl string
	client       *http.Client
}

func newGCSPublisher(cfg publisherConfig, cacheControl string) (JWKSPublisher, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("oidc publisher: gcs requires 'bucket'")
	}
	if cfg.CredentialsJSON == "" {
		return nil, fmt.Errorf("oidc publisher: gcs requires 'credentials_json'")
	}
	// Pin the credential type to a service-account key. Accepting an unvalidated
	// config here is a security risk: an external_account/workload-identity JSON
	// could point token minting at an attacker-controlled URL, so anything but a
	// service account is rejected.
	creds, err := google.CredentialsFromJSONWithType(gcsOAuthCtx(context.Background()), []byte(cfg.CredentialsJSON), google.ServiceAccount, gcsScope)
	if err != nil {
		return nil, fmt.Errorf("oidc publisher: gcs credentials: %w", err)
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = gcsDefaultEndpoint
	}
	return &gcsPublisher{
		tokenSource:     creds.TokenSource,
		credentialsJSON: cfg.CredentialsJSON,
		endpoint:        strings.TrimRight(endpoint, "/"),
		bucket:          cfg.Bucket,
		prefix:          strings.Trim(cfg.Prefix, "/"),
		cacheControl:    cacheControl,
		client:          &http.Client{},
	}, nil
}

func (p *gcsPublisher) Type() string { return "gcs" }

func (p *gcsPublisher) Publish(ctx context.Context, discovery, jwks []byte) error {
	if err := p.put(ctx, oidcDiscoveryObjectPath, discovery); err != nil {
		return err
	}
	return p.put(ctx, oidcJWKSObjectPath, jwks)
}

func (p *gcsPublisher) put(ctx context.Context, name string, body []byte) error {
	object := name
	if p.prefix != "" {
		object = p.prefix + "/" + name
	}
	p.mu.RLock()
	ts := p.tokenSource
	p.mu.RUnlock()
	token, err := ts.Token()
	if err != nil {
		return fmt.Errorf("oidc publisher: gcs token: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, gcsUploadTimeout)
	defer cancel()
	// Single-request upload: PUT {endpoint}/{bucket}/{object}. Object names may
	// contain '/', which stays a path separator in the URL.
	url := p.endpoint + "/" + p.bucket + "/" + object
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("oidc publisher: gcs build PUT %s: %w", object, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cacheControl != "" {
		req.Header.Set("Cache-Control", p.cacheControl)
	}
	token.SetAuthHeader(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc publisher: gcs upload %s: %w", object, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("oidc publisher: gcs upload %s returned status %d", object, resp.StatusCode)
	}
	return nil
}

// GCS credential rotation (implements RotatablePublisher).
//
// Warden self-rotates the stored service-account key: it mints a fresh key via the IAM
// API using the current key, verifies the new key can mint a token, swaps it in, and
// deletes the old key. This requires the service account to hold
// iam.serviceAccountKeys.create/delete on itself (roles/iam.serviceAccountKeyAdmin).

var _ RotatablePublisher = (*gcsPublisher)(nil)

const (
	// gcsIAMScope is the OAuth2 scope needed to manage the service account's own keys.
	gcsIAMScope = "https://www.googleapis.com/auth/iam"
	// gcsRotationMaxResponseBody caps IAM API response reads.
	gcsRotationMaxResponseBody = 1 << 20 // 1MB
)

// gcsRotationVerifyTimeout bounds how long we retry proving a brand-new key is usable
// (a freshly created key can be briefly invalid_grant while it propagates). It is a var
// so tests can shorten it.
var gcsRotationVerifyTimeout = 60 * time.Second

// gcsTokenHTTPTimeout bounds a single OAuth2 token exchange. The x/oauth2 JWT flow neither
// honors context cancellation nor sets a client timeout on the token POST, so a
// black-holed token endpoint would otherwise wedge a token fetch forever — hanging the
// rotation goroutine and, through it, seal and config writes that join the loop. We bound
// it by injecting a timeout-bearing HTTP client into the context the credential is built
// with (the token source reuses that client for every fetch).
const gcsTokenHTTPTimeout = 15 * time.Second

// gcsOAuthCtx returns ctx carrying an HTTP client whose per-request timeout bounds OAuth2
// token exchanges built from it.
func gcsOAuthCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: gcsTokenHTTPTimeout})
}

// minPublisherRotationPeriod is the floor for the publisher-credential rotation cadence,
// enforced on the config-write path so automatic rotation cannot hammer the provider API.
const minPublisherRotationPeriod = 24 * time.Hour

// gcsIAMEndpoint is the IAM API host. It is a package-level var (not operator config)
// so tests can point key create/delete at an httptest server; the operator-facing
// storage endpoint override targets object storage, which does not serve the IAM APIs.
var gcsIAMEndpoint = "https://iam.googleapis.com"

// gcsServiceAccountKey is the subset of a GCP service-account JSON key Warden needs to
// address the key for rotation.
type gcsServiceAccountKey struct {
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	ClientEmail  string `json:"client_email"`
}

func parseGCSServiceAccountKey(s string) (*gcsServiceAccountKey, error) {
	var k gcsServiceAccountKey
	if err := json.Unmarshal([]byte(s), &k); err != nil {
		return nil, fmt.Errorf("invalid service-account key JSON: %w", err)
	}
	if k.ProjectID == "" || k.ClientEmail == "" || k.PrivateKeyID == "" {
		return nil, fmt.Errorf("service-account key JSON missing project_id/client_email/private_key_id")
	}
	return &k, nil
}

func (p *gcsPublisher) SupportsRotation() bool { return true }

// PrepareRotation mints and verifies a new SA key, leaving the current key untouched.
func (p *gcsPublisher) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, error) {
	p.mu.RLock()
	curJSON := p.credentialsJSON
	p.mu.RUnlock()

	saKey, err := parseGCSServiceAccountKey(curJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc publisher: gcs rotation parse current key: %w", err)
	}

	iamToken, err := gcsMintToken(ctx, curJSON, gcsIAMScope)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc publisher: gcs rotation iam token: %w", err)
	}

	newJSON, err := p.createSAKey(ctx, iamToken, saKey.ProjectID, saKey.ClientEmail)
	if err != nil {
		return nil, nil, err
	}

	// Verify the new key can mint a storage token before we hand it back to be
	// persisted and swapped. If it never becomes usable, delete it so a failed
	// rotation does not leak toward the 10-key-per-SA quota. But when verification
	// failed only because the caller's context was cancelled (node sealing/demoting),
	// skip the delete: the loop is being torn down and a synchronous best-effort call
	// here would block seal for up to the delete timeout — a leftover key is a
	// tolerated orphan. The delete runs on a detached context (its own timeout) so a
	// genuine verify failure still cleans up even though verifyKey exhausted ctx.
	if err := p.verifyKey(ctx, newJSON); err != nil {
		if ctx.Err() == nil {
			if newKey, perr := parseGCSServiceAccountKey(newJSON); perr == nil {
				delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gcsUploadTimeout)
				_ = p.deleteSAKey(delCtx, iamToken, newKey.ProjectID, newKey.ClientEmail, newKey.PrivateKeyID)
				cancel()
			}
		}
		return nil, nil, fmt.Errorf("oidc publisher: gcs rotation verify new key: %w", err)
	}

	newFields := map[string]string{"credentials_json": newJSON}
	cleanup := map[string]string{
		"old_key_id":            saKey.PrivateKeyID,
		"service_account_email": saKey.ClientEmail,
		"project_id":            saKey.ProjectID,
		// Delete the old key authenticating AS the old key: it has been live all period
		// and is fully propagated, so it mints reliably — unlike the brand-new key, whose
		// public half may not yet be recognized across Google's replicas (a transient
		// "Invalid JWT Signature"). The token stays valid even after the key is deleted.
		"old_credentials_json": curJSON,
	}
	return newFields, cleanup, nil
}

// CommitRotation swaps the live token source to the newly persisted key.
func (p *gcsPublisher) CommitRotation(newFields map[string]string) error {
	newJSON := newFields["credentials_json"]
	if newJSON == "" {
		return fmt.Errorf("oidc publisher: gcs rotation commit: missing credentials_json")
	}
	creds, err := google.CredentialsFromJSONWithType(gcsOAuthCtx(context.Background()), []byte(newJSON), google.ServiceAccount, gcsScope)
	if err != nil {
		return fmt.Errorf("oidc publisher: gcs rotation commit credentials: %w", err)
	}
	p.mu.Lock()
	p.tokenSource = creds.TokenSource
	p.credentialsJSON = newJSON
	p.mu.Unlock()
	return nil
}

// CleanupRotation deletes the superseded key. It authenticates AS the old key (which is
// fully propagated) rather than the just-committed new key (whose public half may not have
// propagated yet), falling back to the live credential if the old key JSON is absent.
func (p *gcsPublisher) CleanupRotation(ctx context.Context, cleanup map[string]string) error {
	oldKeyID := cleanup["old_key_id"]
	if oldKeyID == "" {
		return nil
	}
	authJSON := cleanup["old_credentials_json"]
	if authJSON == "" {
		p.mu.RLock()
		authJSON = p.credentialsJSON
		p.mu.RUnlock()
	}
	iamToken, err := gcsMintIAMTokenWithRetry(ctx, authJSON)
	if err != nil {
		return fmt.Errorf("oidc publisher: gcs rotation cleanup iam token: %w", err)
	}
	if err := p.deleteSAKey(ctx, iamToken, cleanup["project_id"], cleanup["service_account_email"], oldKeyID); err != nil {
		return fmt.Errorf("oidc publisher: gcs rotation delete old key: %w", err)
	}
	return nil
}

// RollbackRotation deletes a prepared-but-uncommitted new key. It authenticates with the
// current (still the OLD) key, since the new key was never committed to the live state.
func (p *gcsPublisher) RollbackRotation(ctx context.Context, newFields map[string]string) error {
	newJSON := newFields["credentials_json"]
	if newJSON == "" {
		return nil
	}
	nk, err := parseGCSServiceAccountKey(newJSON)
	if err != nil {
		return fmt.Errorf("oidc publisher: gcs rotation rollback parse new key: %w", err)
	}
	p.mu.RLock()
	curJSON := p.credentialsJSON
	p.mu.RUnlock()
	iamToken, err := gcsMintIAMTokenWithRetry(ctx, curJSON)
	if err != nil {
		return fmt.Errorf("oidc publisher: gcs rotation rollback iam token: %w", err)
	}
	if err := p.deleteSAKey(ctx, iamToken, nk.ProjectID, nk.ClientEmail, nk.PrivateKeyID); err != nil {
		return fmt.Errorf("oidc publisher: gcs rotation rollback delete new key: %w", err)
	}
	return nil
}

// gcsMintIAMTokenWithRetry mints an IAM-scoped token, retrying briefly to absorb
// eventual-consistency lag in GCP's key propagation: a recently created key can
// transiently return "Invalid JWT Signature" from the token endpoint before its public
// half is recognized across all replicas. Abortable via ctx.
func gcsMintIAMTokenWithRetry(ctx context.Context, credJSON string) (string, error) {
	var err error
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		var tok string
		if tok, err = gcsMintToken(ctx, credJSON, gcsIAMScope); err == nil {
			return tok, nil
		}
		if attempt >= 4 {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 8*time.Second {
			backoff *= 2
		}
	}
}

// verifyKey proves a key can mint a storage-scoped token, retrying (with backoff, and
// abortable via ctx) up to gcsRotationVerifyTimeout to absorb brand-new-key propagation.
func (p *gcsPublisher) verifyKey(ctx context.Context, credJSON string) error {
	ctx, cancel := context.WithTimeout(ctx, gcsRotationVerifyTimeout)
	defer cancel()
	// Build the credential from the bounded, timeout-scoped context so each token
	// attempt is both time-bounded (the HTTP client timeout) and unable to outlive the
	// verify window.
	creds, err := google.CredentialsFromJSONWithType(gcsOAuthCtx(ctx), []byte(credJSON), google.ServiceAccount, gcsScope)
	if err != nil {
		return err
	}
	backoff := time.Second
	for {
		if _, terr := creds.TokenSource.Token(); terr == nil {
			return nil
		} else {
			err = terr
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("new key not usable within %s: %w", gcsRotationVerifyTimeout, err)
		case <-time.After(backoff):
		}
		if backoff < 8*time.Second {
			backoff *= 2
		}
	}
}

// gcsMintToken mints an OAuth2 access token for the given scope from an SA key JSON,
// pinned to a service-account credential (never external_account/workload-identity).
func gcsMintToken(ctx context.Context, credJSON, scope string) (string, error) {
	creds, err := google.CredentialsFromJSONWithType(gcsOAuthCtx(ctx), []byte(credJSON), google.ServiceAccount, scope)
	if err != nil {
		return "", fmt.Errorf("credentials: %w", err)
	}
	tok, err := creds.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	return tok.AccessToken, nil
}

// createSAKey creates a new key for the service account via the IAM API and returns the
// decoded JSON key file. Mirrors the GCP source driver's single-request key creation.
func (p *gcsPublisher) createSAKey(ctx context.Context, iamToken, projectID, saEmail string) (string, error) {
	api := fmt.Sprintf("%s/v1/projects/%s/serviceAccounts/%s/keys",
		gcsIAMEndpoint, url.PathEscape(projectID), url.PathEscape(saEmail))
	reqBody, _ := json.Marshal(map[string]string{
		"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
		"keyAlgorithm":   "KEY_ALG_RSA_2048",
	})
	respBody, err := p.doIAMRequest(ctx, http.MethodPost, api, iamToken, reqBody)
	if err != nil {
		return "", fmt.Errorf("oidc publisher: gcs create key: %w", err)
	}
	var keyResp struct {
		PrivateKeyData string `json:"privateKeyData"` // base64(std) JSON key file
	}
	if err := json.Unmarshal(respBody, &keyResp); err != nil {
		return "", fmt.Errorf("oidc publisher: gcs create key: decode response: %w", err)
	}
	if keyResp.PrivateKeyData == "" {
		return "", fmt.Errorf("oidc publisher: gcs create key: response missing privateKeyData")
	}
	keyJSON, err := base64.StdEncoding.DecodeString(keyResp.PrivateKeyData)
	if err != nil {
		return "", fmt.Errorf("oidc publisher: gcs create key: decode privateKeyData: %w", err)
	}
	if _, err := parseGCSServiceAccountKey(string(keyJSON)); err != nil {
		return "", fmt.Errorf("oidc publisher: gcs create key: %w", err)
	}
	return string(keyJSON), nil
}

// deleteSAKey deletes a specific key from the service account via the IAM API.
func (p *gcsPublisher) deleteSAKey(ctx context.Context, iamToken, projectID, saEmail, keyID string) error {
	api := fmt.Sprintf("%s/v1/projects/%s/serviceAccounts/%s/keys/%s",
		gcsIAMEndpoint, url.PathEscape(projectID), url.PathEscape(saEmail), url.PathEscape(keyID))
	if _, err := p.doIAMRequest(ctx, http.MethodDelete, api, iamToken, nil); err != nil {
		return fmt.Errorf("oidc publisher: gcs delete key: %w", err)
	}
	return nil
}

// doIAMRequest performs a bearer-authenticated IAM API call and returns the response
// body on a 2xx, or an error carrying the status. It bounds each call with its own
// timeout so a black-holed IAM endpoint cannot stall a rotation cycle indefinitely
// (which runs off the request path and has no outer deadline).
func (p *gcsPublisher) doIAMRequest(ctx context.Context, method, api, bearer string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, gcsUploadTimeout)
	defer cancel()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, api, r)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, gcsRotationMaxResponseBody))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}
