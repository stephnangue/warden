package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

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
