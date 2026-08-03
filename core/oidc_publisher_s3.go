package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// s3Publisher PutObjects the documents to an S3 bucket using stored static credentials.
// This is an infra-scoped write credential used only on rotation (rare), distinct from the
// per-agent secrets WIF removes. Warden can self-rotate it (see RotatablePublisher).
type s3Publisher struct {
	// mu guards the mutable credential (client + access/secret key), which
	// CommitRotation swaps in place while Publish may be reading it concurrently.
	mu              sync.RWMutex
	client          *s3.Client
	accessKeyID     string
	secretAccessKey string

	region       string
	endpoint     string // optional S3 endpoint override (S3-compatible stores / tests)
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
	return &s3Publisher{
		client:          news3Client(cfg.Region, cfg.Endpoint, cfg.AccessKeyID, cfg.SecretAccessKey),
		accessKeyID:     cfg.AccessKeyID,
		secretAccessKey: cfg.SecretAccessKey,
		region:          cfg.Region,
		endpoint:        cfg.Endpoint,
		bucket:          cfg.Bucket,
		prefix:          strings.Trim(cfg.Prefix, "/"),
		cacheControl:    cacheControl,
	}, nil
}

// news3Client builds an S3 client with static credentials, honoring an optional endpoint
// override (path-style, for S3-compatible stores or a test server).
func news3Client(region, endpoint, accessKeyID, secretAccessKey string) *s3.Client {
	opts := s3.Options{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
	}
	if endpoint != "" {
		opts.BaseEndpoint = aws.String(endpoint)
		opts.UsePathStyle = true
	}
	return s3.New(opts)
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
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()
	if _, err := client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("oidc publisher: s3 PutObject %s: %w", fullKey, err)
	}
	return nil
}

// S3 credential rotation (implements RotatablePublisher).
//
// Warden self-rotates the stored IAM user access key: it creates a new access key for its
// own IAM user, verifies it, swaps it into the live S3 client, and deletes the old key.
// This requires the IAM user to hold iam:CreateAccessKey / iam:DeleteAccessKey /
// iam:ListAccessKeys on itself. Only permanent user keys (AKIA prefix) can rotate; STS
// temporary credentials (ASIA) cannot.

var _ RotatablePublisher = (*s3Publisher)(nil)

// awsIAMEndpoint overrides the IAM/STS API host. Empty uses the default AWS endpoints;
// tests point it at an httptest server (mirrors gcsIAMEndpoint).
var awsIAMEndpoint = ""

// awsRotationVerifyTimeout bounds how long we retry proving a brand-new access key is
// usable (a seconds-old key transiently returns InvalidClientTokenId). A var so tests can
// shorten it.
var awsRotationVerifyTimeout = 60 * time.Second

// awsRotationDeleteTimeout bounds a best-effort key delete's retry window.
const awsRotationDeleteTimeout = 30 * time.Second

// awsRotationOpTimeout bounds the list/prune/create IAM sequence in PrepareRotation. The
// AWS SDK's default client sets dial/TLS timeouts but no overall request deadline, so a
// black-holed endpoint would otherwise wedge the rotation goroutine indefinitely.
const awsRotationOpTimeout = 30 * time.Second

func (p *s3Publisher) iamClient(accessKeyID, secretAccessKey string) *iam.Client {
	opts := iam.Options{
		Region:      p.region,
		Credentials: credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
	}
	if awsIAMEndpoint != "" {
		opts.BaseEndpoint = aws.String(awsIAMEndpoint)
	}
	return iam.New(opts)
}

func (p *s3Publisher) stsClient(accessKeyID, secretAccessKey string) *sts.Client {
	opts := sts.Options{
		Region:      p.region,
		Credentials: credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
	}
	if awsIAMEndpoint != "" {
		opts.BaseEndpoint = aws.String(awsIAMEndpoint)
	}
	return sts.New(opts)
}

func (p *s3Publisher) SupportsRotation() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// Only permanent IAM-user keys can create/delete keys for themselves.
	return strings.HasPrefix(p.accessKeyID, "AKIA")
}

// PrepareRotation creates and verifies a new IAM access key, leaving the current one live.
func (p *s3Publisher) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, map[string]string, error) {
	p.mu.RLock()
	ak, sk := p.accessKeyID, p.secretAccessKey
	p.mu.RUnlock()

	iamc := p.iamClient(ak, sk)

	// Bound the list/prune/create sequence so a black-holed IAM endpoint cannot wedge the
	// rotation goroutine (the SDK default client has no overall request deadline). verify
	// has its own, longer window.
	opCtx, cancel := context.WithTimeout(ctx, awsRotationOpTimeout)
	defer cancel()

	// IAM users are capped at 2 access keys. If a prior cleanup failed and left the max in
	// place, delete the non-current (orphan) one before creating a new key. This tight cap
	// makes reliable pruning matter more than it does for GCS (10-key cap). The prune
	// assumes the non-current key on this dedicated IAM user is our leftover — the same
	// assumption the AWS source driver makes.
	list, err := iamc.ListAccessKeys(opCtx, &iam.ListAccessKeysInput{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc publisher: s3 rotation list keys: %w", err)
	}
	if len(list.AccessKeyMetadata) >= 2 {
		for _, k := range list.AccessKeyMetadata {
			if aws.ToString(k.AccessKeyId) != ak {
				if _, err := iamc.DeleteAccessKey(opCtx, &iam.DeleteAccessKeyInput{AccessKeyId: k.AccessKeyId}); err != nil {
					var notFound *iamtypes.NoSuchEntityException
					if !errors.As(err, &notFound) { // already gone is fine; anything else aborts
						return nil, nil, nil, fmt.Errorf("oidc publisher: s3 rotation prune orphan key: %w", err)
					}
				}
				break
			}
		}
	}

	// Create a new key for the calling user (no UserName → the signing user).
	created, err := iamc.CreateAccessKey(opCtx, &iam.CreateAccessKeyInput{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc publisher: s3 rotation create key: %w", err)
	}
	if created.AccessKey == nil || created.AccessKey.AccessKeyId == nil || created.AccessKey.SecretAccessKey == nil {
		return nil, nil, nil, fmt.Errorf("oidc publisher: s3 rotation create key: empty response")
	}
	newAK := aws.ToString(created.AccessKey.AccessKeyId)
	newSK := aws.ToString(created.AccessKey.SecretAccessKey)

	// Verify the new key is active before handing it back. If it never becomes usable,
	// delete it (authenticating as the still-propagated old key) so a failed rotation does
	// not leak against the 2-key cap. Skip the delete on ctx cancellation (node sealing).
	if err := p.verifyKey(ctx, newAK, newSK); err != nil {
		if ctx.Err() == nil {
			delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), awsRotationDeleteTimeout)
			_ = p.deleteAccessKey(delCtx, ak, sk, newAK)
			cancel()
		}
		return nil, nil, nil, fmt.Errorf("oidc publisher: s3 rotation verify new key: %w", err)
	}

	newFields := map[string]string{"access_key_id": newAK, "secret_access_key": newSK}
	prevFields := map[string]string{"access_key_id": ak}
	cleanup := map[string]string{
		// Delete the old key authenticating AS the old key (fully propagated; a key can
		// delete itself), avoiding the new-key eventual-consistency lag. In-memory only.
		"old_access_key_id":     ak,
		"old_secret_access_key": sk,
	}
	return newFields, prevFields, cleanup, nil
}

// CommitRotation swaps the live S3 client to the newly persisted access key.
func (p *s3Publisher) CommitRotation(newFields map[string]string) error {
	ak := newFields["access_key_id"]
	sk := newFields["secret_access_key"]
	if ak == "" || sk == "" {
		return fmt.Errorf("oidc publisher: s3 rotation commit: missing access_key_id/secret_access_key")
	}
	client := news3Client(p.region, p.endpoint, ak, sk)
	p.mu.Lock()
	p.client = client
	p.accessKeyID = ak
	p.secretAccessKey = sk
	p.mu.Unlock()
	return nil
}

// CleanupRotation deletes the superseded key, authenticating as the old (propagated) key.
func (p *s3Publisher) CleanupRotation(ctx context.Context, cleanup map[string]string) error {
	oldAK := cleanup["old_access_key_id"]
	if oldAK == "" {
		return nil
	}
	authAK, authSK := cleanup["old_access_key_id"], cleanup["old_secret_access_key"]
	if authSK == "" {
		p.mu.RLock()
		authAK, authSK = p.accessKeyID, p.secretAccessKey
		p.mu.RUnlock()
	}
	if err := p.deleteAccessKey(ctx, authAK, authSK, oldAK); err != nil {
		return fmt.Errorf("oidc publisher: s3 rotation delete old key: %w", err)
	}
	return nil
}

// RollbackRotation deletes a prepared-but-uncommitted new key, authenticating with the
// current (still the OLD) key.
func (p *s3Publisher) RollbackRotation(ctx context.Context, newFields map[string]string) error {
	newAK := newFields["access_key_id"]
	if newAK == "" {
		return nil
	}
	p.mu.RLock()
	authAK, authSK := p.accessKeyID, p.secretAccessKey
	p.mu.RUnlock()
	if err := p.deleteAccessKey(ctx, authAK, authSK, newAK); err != nil {
		return fmt.Errorf("oidc publisher: s3 rotation rollback delete new key: %w", err)
	}
	return nil
}

// verifyKey proves an access key is active by calling STS GetCallerIdentity (no extra
// permission), retrying up to awsRotationVerifyTimeout to absorb IAM eventual consistency.
func (p *s3Publisher) verifyKey(ctx context.Context, accessKeyID, secretAccessKey string) error {
	stsc := p.stsClient(accessKeyID, secretAccessKey)
	ctx, cancel := context.WithTimeout(ctx, awsRotationVerifyTimeout)
	defer cancel()
	if err := retryWithBackoff(ctx, func() error {
		_, err := stsc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		return err
	}); err != nil {
		return fmt.Errorf("new key not usable within %s: %w", awsRotationVerifyTimeout, err)
	}
	return nil
}

// deleteAccessKey deletes an access key, authenticating with the given creds, retrying
// within a bounded window. A NoSuchEntity result is treated as success (idempotent — a
// prior attempt may have succeeded before returning a transient error).
func (p *s3Publisher) deleteAccessKey(ctx context.Context, authAccessKeyID, authSecretAccessKey, targetKeyID string) error {
	iamc := p.iamClient(authAccessKeyID, authSecretAccessKey)
	ctx, cancel := context.WithTimeout(ctx, awsRotationDeleteTimeout)
	defer cancel()
	return retryWithBackoff(ctx, func() error {
		_, err := iamc.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{AccessKeyId: aws.String(targetKeyID)})
		var notFound *iamtypes.NoSuchEntityException
		if errors.As(err, &notFound) {
			return nil
		}
		return err
	})
}
