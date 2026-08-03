package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
)

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
