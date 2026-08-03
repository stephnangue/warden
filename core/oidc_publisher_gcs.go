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
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

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
func (p *gcsPublisher) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, map[string]string, error) {
	p.mu.RLock()
	curJSON := p.credentialsJSON
	p.mu.RUnlock()

	saKey, err := parseGCSServiceAccountKey(curJSON)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc publisher: gcs rotation parse current key: %w", err)
	}

	iamToken, err := gcsMintToken(ctx, curJSON, gcsIAMScope)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc publisher: gcs rotation iam token: %w", err)
	}

	newJSON, err := p.createSAKey(ctx, iamToken, saKey.ProjectID, saKey.ClientEmail)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, fmt.Errorf("oidc publisher: gcs rotation verify new key: %w", err)
	}

	newFields := map[string]string{"credentials_json": newJSON}
	prevFields := map[string]string{"credentials_json": curJSON}
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
	return newFields, prevFields, cleanup, nil
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
