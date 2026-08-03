package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
)

// azureUploadTimeout bounds a single blob upload, matching the http_put publisher's
// per-request timeout so a slow/flaky endpoint cannot stall a rotation (which runs off the
// request path and has no outer deadline). It also bounds the raw OAuth/Graph HTTP calls.
const azureUploadTimeout = 15 * time.Second

const (
	// azureStorageScope / azureGraphScope are the OAuth2 scopes for the blob data plane
	// and for Microsoft Graph (app-registration secret management), respectively.
	azureStorageScope = "https://storage.azure.com/.default"
	azureGraphScope   = "https://graph.microsoft.com/.default"
	// azurePublisherSecretPrefix is the base displayName Warden gives the password
	// credentials it creates; secretDisplayName qualifies it with account/container so
	// orphans from failed cleanups can be identified and pruned without a different Warden
	// deployment (different bucket) pruning this one's secrets.
	azurePublisherSecretPrefix = "warden-oidc-publisher"
)

// azureAuthorityHost / azureGraphEndpoint are the Entra ID token authority and the Graph
// API host. They are package-level vars (not operator config) so tests can point token
// acquisition and Graph calls at an httptest server (mirrors gcsIAMEndpoint/awsIAMEndpoint).
var (
	azureAuthorityHost = "https://login.microsoftonline.com"
	azureGraphEndpoint = "https://graph.microsoft.com"
)

// azureRotationVerifyTimeout bounds how long we retry proving a brand-new client secret is
// usable (a fresh secret is briefly rejected while Entra ID propagates it). A var so tests
// can shorten it.
var azureRotationVerifyTimeout = 60 * time.Second

// azureInsecureAllowHTTP lets tests point the blob client at a plain-HTTP httptest server
// (the OAuth bearer policy otherwise refuses to send a token over http). Never set in prod.
var azureInsecureAllowHTTP = false

// azureHTTPClient bounds each raw OAuth/Graph request.
var azureHTTPClient = &http.Client{Timeout: azureUploadTimeout}

// azureBlobPublisher uploads the documents to an Azure Storage container, authenticated by
// a service principal's OAuth token (Entra ID data-plane auth). Warden self-rotates the
// SP's client secret via Microsoft Graph (see RotatablePublisher): it adds a fresh secret
// to the app registration, verifies it, swaps it into the live client, and removes the old
// one. The SP needs Storage Blob Data Contributor on the container and Graph rights over
// its own app registration (Application.ReadWrite.OwnedBy as an owner, or ...All).
type azureBlobPublisher struct {
	// mu guards the mutable credential (client + client secret + secret id), which
	// CommitRotation swaps in place while Publish may be reading the client concurrently.
	mu           sync.RWMutex
	client       *azblob.Client
	clientSecret string
	secretID     string

	tenantID     string
	clientID     string
	accountName  string
	serviceURL   string
	container    string
	prefix       string
	cacheControl string
}

func newAzureBlobPublisher(cfg publisherConfig, cacheControl string) (JWKSPublisher, error) {
	if cfg.AccountName == "" || cfg.Container == "" {
		return nil, fmt.Errorf("oidc publisher: azure_blob requires 'account_name' and 'container'")
	}
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("oidc publisher: azure_blob requires 'tenant_id', 'client_id', and 'client_secret' (service-principal auth)")
	}
	// Default to the public-cloud blob host; an explicit endpoint covers a private endpoint
	// or a test emulator (Azurite). Note: the OAuth authority and Graph host are the public
	// cloud (see azureAuthorityHost/azureGraphEndpoint), so sovereign clouds (Government/
	// China) are not yet supported for the SP-authenticated path.
	serviceURL := cfg.Endpoint
	if serviceURL == "" {
		serviceURL = fmt.Sprintf("https://%s.blob.core.windows.net/", cfg.AccountName)
	}
	p := &azureBlobPublisher{
		clientSecret: cfg.ClientSecret,
		secretID:     cfg.SecretID,
		tenantID:     cfg.TenantID,
		clientID:     cfg.ClientID,
		accountName:  cfg.AccountName,
		serviceURL:   serviceURL,
		container:    cfg.Container,
		prefix:       strings.Trim(cfg.Prefix, "/"),
		cacheControl: cacheControl,
	}
	client, err := p.buildClient(cfg.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("oidc publisher: azure_blob client: %w", err)
	}
	p.client = client
	return p, nil
}

// buildClient constructs an azblob client authenticated by the SP OAuth token for the
// given client secret.
func (p *azureBlobPublisher) buildClient(clientSecret string) (*azblob.Client, error) {
	cred := &azureOAuthCredential{tenantID: p.tenantID, clientID: p.clientID, clientSecret: clientSecret}
	var opts *azblob.ClientOptions
	if azureInsecureAllowHTTP {
		opts = &azblob.ClientOptions{ClientOptions: azcore.ClientOptions{InsecureAllowCredentialWithHTTP: true}}
	}
	return azblob.NewClient(p.serviceURL, cred, opts)
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
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()
	_, err := client.UploadBuffer(ctx, p.container, blobName, body, &azblob.UploadBufferOptions{
		HTTPHeaders: headers,
	})
	if err != nil {
		return fmt.Errorf("oidc publisher: azure_blob upload %s: %w", blobName, err)
	}
	return nil
}

// azureOAuthCredential is an azcore.TokenCredential backed by the raw OAuth2
// client-credentials flow, so the blob client authenticates with the SP token without
// pulling in azidentity. It honors the exact scope the SDK requests.
type azureOAuthCredential struct {
	tenantID, clientID, clientSecret string
}

func (c *azureOAuthCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	scope := azureStorageScope
	if len(opts.Scopes) > 0 {
		scope = opts.Scopes[0]
	}
	token, expiresOn, err := azureAcquireToken(ctx, c.tenantID, c.clientID, c.clientSecret, scope)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	return azcore.AccessToken{Token: token, ExpiresOn: expiresOn}, nil
}

// Azure client-secret rotation (implements RotatablePublisher).

var _ RotatablePublisher = (*azureBlobPublisher)(nil)

func (p *azureBlobPublisher) SupportsRotation() bool { return true }

// secretDisplayName is the Graph displayName Warden stamps on the password credentials it
// mints, qualified by account/container so pruning only ever targets THIS publisher's own
// secrets (never an operator's, nor another Warden deployment's on a different bucket).
func (p *azureBlobPublisher) secretDisplayName() string {
	return fmt.Sprintf("%s/%s/%s", azurePublisherSecretPrefix, p.accountName, p.container)
}

// PrepareRotation adds and verifies a new client secret on the app registration, leaving
// the current secret untouched.
func (p *azureBlobPublisher) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, map[string]string, error) {
	p.mu.RLock()
	tenantID, clientID, oldSecret, oldSecretID := p.tenantID, p.clientID, p.clientSecret, p.secretID
	p.mu.RUnlock()

	graphToken, err := azureAcquireGraphTokenWithRetry(ctx, tenantID, clientID, oldSecret)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc publisher: azure_blob rotation graph token: %w", err)
	}
	appObjectID, err := resolveAppObjectID(ctx, graphToken, clientID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc publisher: azure_blob rotation resolve app: %w", err)
	}

	newSecret, newSecretID, err := graphAddPassword(ctx, graphToken, appObjectID, p.secretDisplayName())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc publisher: azure_blob rotation add secret: %w", err)
	}

	// Verify the new secret can acquire a storage token before handing it back. If it
	// never becomes usable, remove it (authenticating as the still-valid old secret) so a
	// failed rotation does not leave an orphaned password on the app registration. Skip the
	// removal on ctx cancellation (node sealing).
	if err := p.verifySecret(ctx, tenantID, clientID, newSecret); err != nil {
		if ctx.Err() == nil {
			delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), azureUploadTimeout)
			if gt, _, gerr := azureAcquireToken(delCtx, tenantID, clientID, oldSecret, azureGraphScope); gerr == nil {
				_ = graphRemovePassword(delCtx, gt, appObjectID, newSecretID)
			}
			cancel()
		}
		return nil, nil, nil, fmt.Errorf("oidc publisher: azure_blob rotation verify new secret: %w", err)
	}

	newFields := map[string]string{"client_secret": newSecret, "secret_id": newSecretID}
	prevFields := map[string]string{"client_secret": oldSecret}
	cleanup := map[string]string{
		// Remove the old secret authenticating AS the old secret (fully propagated),
		// avoiding new-secret eventual-consistency lag. In-memory only.
		"old_secret_id":     oldSecretID,
		"old_client_secret": oldSecret,
		"tenant_id":         tenantID,
		"client_id":         clientID,
		"app_object_id":     appObjectID,
	}
	return newFields, prevFields, cleanup, nil
}

// CommitRotation swaps the live blob client to the newly persisted client secret.
func (p *azureBlobPublisher) CommitRotation(newFields map[string]string) error {
	secret := newFields["client_secret"]
	if secret == "" {
		return fmt.Errorf("oidc publisher: azure_blob rotation commit: missing client_secret")
	}
	client, err := p.buildClient(secret)
	if err != nil {
		return fmt.Errorf("oidc publisher: azure_blob rotation commit client: %w", err)
	}
	p.mu.Lock()
	p.client = client
	p.clientSecret = secret
	p.secretID = newFields["secret_id"]
	p.mu.Unlock()
	return nil
}

// CleanupRotation removes the superseded secret, authenticating as the old (propagated) one.
func (p *azureBlobPublisher) CleanupRotation(ctx context.Context, cleanup map[string]string) error {
	oldSecretID := cleanup["old_secret_id"]
	if oldSecretID == "" {
		return nil
	}
	graphToken, err := azureAcquireGraphTokenWithRetry(ctx, cleanup["tenant_id"], cleanup["client_id"], cleanup["old_client_secret"])
	if err != nil {
		return fmt.Errorf("oidc publisher: azure_blob rotation cleanup graph token: %w", err)
	}
	if err := graphRemovePassword(ctx, graphToken, cleanup["app_object_id"], oldSecretID); err != nil {
		return fmt.Errorf("oidc publisher: azure_blob rotation remove old secret: %w", err)
	}
	// Best-effort: also prune any Warden secrets leaked by *prior* failed cleanups. Runs
	// only post-commit, keeping the just-committed live secret (p.secretID — known correct,
	// not the possibly-stale stored config value), so it can never delete the active
	// credential. Matches only this publisher's displayName, so it never touches another
	// deployment's or an operator's secrets.
	p.mu.RLock()
	liveID, displayName := p.secretID, p.secretDisplayName()
	p.mu.RUnlock()
	pruneOrphanPasswords(ctx, graphToken, cleanup["app_object_id"], displayName, liveID)
	return nil
}

// RollbackRotation removes a prepared-but-uncommitted new secret, authenticating with the
// current (still the OLD) secret.
func (p *azureBlobPublisher) RollbackRotation(ctx context.Context, newFields map[string]string) error {
	newSecretID := newFields["secret_id"]
	if newSecretID == "" {
		return nil
	}
	p.mu.RLock()
	tenantID, clientID, curSecret := p.tenantID, p.clientID, p.clientSecret
	p.mu.RUnlock()
	graphToken, err := azureAcquireGraphTokenWithRetry(ctx, tenantID, clientID, curSecret)
	if err != nil {
		return fmt.Errorf("oidc publisher: azure_blob rotation rollback graph token: %w", err)
	}
	appObjectID, err := resolveAppObjectID(ctx, graphToken, clientID)
	if err != nil {
		return fmt.Errorf("oidc publisher: azure_blob rotation rollback resolve app: %w", err)
	}
	if err := graphRemovePassword(ctx, graphToken, appObjectID, newSecretID); err != nil {
		return fmt.Errorf("oidc publisher: azure_blob rotation rollback remove new secret: %w", err)
	}
	return nil
}

// verifySecret proves a client secret is usable by acquiring a storage-scoped token,
// retrying up to azureRotationVerifyTimeout to absorb Entra ID eventual consistency.
func (p *azureBlobPublisher) verifySecret(ctx context.Context, tenantID, clientID, clientSecret string) error {
	ctx, cancel := context.WithTimeout(ctx, azureRotationVerifyTimeout)
	defer cancel()
	return retryWithBackoff(ctx, func() error {
		_, _, err := azureAcquireToken(ctx, tenantID, clientID, clientSecret, azureStorageScope)
		return err
	})
}

// azureAcquireGraphTokenWithRetry acquires a Graph token, retrying briefly to absorb
// secret-propagation lag.
func azureAcquireGraphTokenWithRetry(ctx context.Context, tenantID, clientID, clientSecret string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, azureRotationVerifyTimeout)
	defer cancel()
	var token string
	if err := retryWithBackoff(ctx, func() error {
		t, _, err := azureAcquireToken(ctx, tenantID, clientID, clientSecret, azureGraphScope)
		token = t
		return err
	}); err != nil {
		return "", err
	}
	return token, nil
}

// azureAcquireToken performs the OAuth2 client-credentials flow and returns the token and
// its expiry. Mirrors the Azure source driver's acquireToken but takes a full scope (the
// azblob credential shim passes the SDK's requested scope verbatim).
func azureAcquireToken(ctx context.Context, tenantID, clientID, clientSecret, scope string) (string, time.Time, error) {
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", strings.TrimRight(azureAuthorityHost, "/"), url.PathEscape(tenantID))
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", scope)
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := azureHTTPClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", time.Time{}, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return "", time.Time{}, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("token response missing access_token")
	}
	expiresOn := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return tok.AccessToken, expiresOn, nil
}

// resolveAppObjectID looks up an app registration's object id from its appId (client_id) —
// the Graph password endpoints key on the object id, not the appId.
func resolveAppObjectID(ctx context.Context, graphToken, appID string) (string, error) {
	q := url.Values{}
	// Escape single quotes in the OData string literal (doubled), so a client_id value
	// can't break the filter.
	q.Set("$filter", fmt.Sprintf("appId eq '%s'", strings.ReplaceAll(appID, "'", "''")))
	q.Set("$select", "id")
	api := fmt.Sprintf("%s/v1.0/applications?%s", strings.TrimRight(azureGraphEndpoint, "/"), q.Encode())
	respBody, err := doGraphRequest(ctx, http.MethodGet, api, graphToken, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("decode applications response: %w", err)
	}
	if len(resp.Value) == 0 || resp.Value[0].ID == "" {
		return "", fmt.Errorf("no app registration found for client_id")
	}
	return resp.Value[0].ID, nil
}

// graphAddPassword adds a new password credential to the app registration and returns its
// secret text and keyId.
func graphAddPassword(ctx context.Context, graphToken, appObjectID, displayName string) (secret, keyID string, err error) {
	api := fmt.Sprintf("%s/v1.0/applications/%s/addPassword",
		strings.TrimRight(azureGraphEndpoint, "/"), url.PathEscape(appObjectID))
	reqBody, _ := json.Marshal(map[string]any{
		"passwordCredential": map[string]any{"displayName": displayName},
	})
	respBody, err := doGraphRequest(ctx, http.MethodPost, api, graphToken, reqBody)
	if err != nil {
		return "", "", err
	}
	var resp struct {
		SecretText string `json:"secretText"`
		KeyID      string `json:"keyId"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", "", fmt.Errorf("decode addPassword response: %w", err)
	}
	if resp.SecretText == "" || resp.KeyID == "" {
		return "", "", fmt.Errorf("addPassword response missing secretText/keyId")
	}
	return resp.SecretText, resp.KeyID, nil
}

// graphRemovePassword removes a password credential (by keyId) from the app registration.
func graphRemovePassword(ctx context.Context, graphToken, appObjectID, keyID string) error {
	api := fmt.Sprintf("%s/v1.0/applications/%s/removePassword",
		strings.TrimRight(azureGraphEndpoint, "/"), url.PathEscape(appObjectID))
	reqBody, _ := json.Marshal(map[string]any{"keyId": keyID})
	_, err := doGraphRequest(ctx, http.MethodPost, api, graphToken, reqBody)
	return err
}

// azurePasswordCredential is the subset of a Graph passwordCredential Warden needs to
// identify and prune its own orphaned secrets.
type azurePasswordCredential struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
}

// listPasswordCredentials returns the app registration's password credentials.
func listPasswordCredentials(ctx context.Context, graphToken, appObjectID string) ([]azurePasswordCredential, error) {
	api := fmt.Sprintf("%s/v1.0/applications/%s?$select=passwordCredentials",
		strings.TrimRight(azureGraphEndpoint, "/"), url.PathEscape(appObjectID))
	respBody, err := doGraphRequest(ctx, http.MethodGet, api, graphToken, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		PasswordCredentials []azurePasswordCredential `json:"passwordCredentials"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decode passwordCredentials response: %w", err)
	}
	return resp.PasswordCredentials, nil
}

// pruneOrphanPasswords removes password credentials with the given displayName that aren't
// in keep — best-effort housekeeping for secrets leaked by prior failed cleanups. Only
// credentials with THIS publisher's displayName are touched, so operator-managed secrets
// (and other Warden deployments' secrets) are never removed. Callers must include the live
// secret's keyId in keep so the active credential is never pruned.
func pruneOrphanPasswords(ctx context.Context, graphToken, appObjectID, displayName string, keep ...string) {
	creds, err := listPasswordCredentials(ctx, graphToken, appObjectID)
	if err != nil {
		return // best-effort; the rotation cycle's outcome is logged by the loop
	}
	keepSet := make(map[string]bool, len(keep))
	for _, id := range keep {
		keepSet[id] = true
	}
	for _, c := range creds {
		if keepSet[c.KeyID] || c.DisplayName != displayName {
			continue
		}
		_ = graphRemovePassword(ctx, graphToken, appObjectID, c.KeyID)
	}
}

// doGraphRequest performs a bearer-authenticated Graph call, returning the body on a 2xx.
// It retries transient failures with backoff: Azure AD serializes writes to a directory
// object, so an add/remove pair on the same app registration (which every rotation cycle
// does) can hit 409 Directory_ConcurrencyViolation, and Graph also throttles with 429.
func doGraphRequest(ctx context.Context, method, api, bearer string, body []byte) ([]byte, error) {
	backoff := time.Second
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		respBody, status, err := doGraphOnce(ctx, method, api, bearer, body)
		if err == nil {
			return respBody, nil
		}
		lastErr = err
		if status != http.StatusConflict && status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
			return nil, err // non-transient — fail fast
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 8*time.Second {
			backoff *= 2
		}
	}
	return nil, lastErr
}

// doGraphOnce performs a single Graph call, returning the body, HTTP status (0 on a
// transport error), and error.
func doGraphOnce(ctx context.Context, method, api, bearer string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, api, r)
	if err != nil {
		return nil, 0, fmt.Errorf("build graph request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := azureHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, resp.StatusCode, fmt.Errorf("graph status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, resp.StatusCode, nil
}
