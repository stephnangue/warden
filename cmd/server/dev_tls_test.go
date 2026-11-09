package server

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseDevCert(t *testing.T, certPath string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(certPath)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestGenerateDevTLSCert_TempDir(t *testing.T) {
	certPath, keyPath, certDir, err := generateDevTLSCert("", nil)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(certDir) })

	assert.Equal(t, filepath.Join(certDir, "cert.pem"), certPath)
	assert.Equal(t, filepath.Join(certDir, "key.pem"), keyPath)

	cert := parseDevCert(t, certPath)
	assert.Equal(t, []string{"localhost", "*.localhost"}, cert.DNSNames)
	require.Len(t, cert.IPAddresses, 2)
	assert.True(t, cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
	assert.True(t, cert.IPAddresses[1].Equal(net.IPv6loopback))
}

func TestGenerateDevTLSCert_CertDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "certs")

	certPath, keyPath, certDir, err := generateDevTLSCert(dir, nil)
	require.NoError(t, err)
	assert.Equal(t, dir, certDir)
	assert.Equal(t, filepath.Join(dir, "cert.pem"), certPath)
	assert.Equal(t, filepath.Join(dir, "key.pem"), keyPath)

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
	certInfo, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())
}

func TestGenerateDevTLSCert_CertDirRegeneratesWithStrictKeyMode(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("stale"), 0o644))
	other := filepath.Join(dir, "other.txt")
	require.NoError(t, os.WriteFile(other, []byte("keep"), 0o644))

	certPath, gotKeyPath, _, err := generateDevTLSCert(dir, nil)
	require.NoError(t, err)
	assert.Equal(t, keyPath, gotKeyPath)

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm(), "a regenerated key must not inherit a looser mode")
	parseDevCert(t, certPath)

	_, err = os.Stat(other)
	assert.NoError(t, err, "unrelated files in the cert dir are left alone")
}

func TestGenerateDevTLSCert_SANs(t *testing.T) {
	certPath, _, certDir, err := generateDevTLSCert("", []string{"warden", "10.0.0.5", "localhost", "127.0.0.1", "::1"})
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(certDir) })

	cert := parseDevCert(t, certPath)
	assert.Equal(t, []string{"localhost", "*.localhost", "warden"}, cert.DNSNames, "duplicates of the defaults are not repeated")
	require.Len(t, cert.IPAddresses, 3)
	assert.True(t, cert.IPAddresses[2].Equal(net.ParseIP("10.0.0.5")))
	assert.NoError(t, cert.VerifyHostname("warden"))
	assert.NoError(t, cert.VerifyHostname("10.0.0.5"))
}

func TestGenerateDevTLSCert_SANsTrimmed(t *testing.T) {
	certPath, _, certDir, err := generateDevTLSCert("", []string{" warden ", " 10.0.0.5"})
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(certDir) })

	cert := parseDevCert(t, certPath)
	assert.Contains(t, cert.DNSNames, "warden")
	assert.NoError(t, cert.VerifyHostname("warden"))
	assert.NoError(t, cert.VerifyHostname("10.0.0.5"))
}

func TestGenerateDevTLSCert_EarlyFailureKeepsPreviousFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, []byte("previous cert"), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("previous key"), 0o600))

	// A DNS SAN that is not IA5 makes certificate creation fail before any
	// file is written.
	_, _, _, err := generateDevTLSCert(dir, []string{"wärden"})
	require.Error(t, err)

	got, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, "previous cert", string(got))
	got, err = os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, "previous key", string(got))
}

func TestGenerateDevTLSCert_KeyWriteFailureRemovesNewCert(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory at key.pem cannot be removed, so the key write
	// fails after the certificate has been written.
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.MkdirAll(filepath.Join(keyPath, "occupied"), 0o700))

	_, _, _, err := generateDevTLSCert(dir, nil)
	require.Error(t, err)

	_, err = os.Stat(filepath.Join(dir, "cert.pem"))
	assert.ErrorIs(t, err, os.ErrNotExist, "a cert without its key is not left behind")
	_, err = os.Stat(filepath.Join(keyPath, "occupied"))
	assert.NoError(t, err, "entries this call did not write are left alone")
}

func TestWriteFileMode_ReplacesSymlinkWithoutFollowing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("untouched"), 0o644))
	path := filepath.Join(dir, "key.pem")
	require.NoError(t, os.Symlink(target, path))

	require.NoError(t, writeFileMode(path, []byte("KEY"), 0o600))

	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular(), "the symlink is replaced by a regular file")
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "untouched", string(got))
}

func TestWriteNewFile_RefusesExistingSymlink(t *testing.T) {
	tests := []struct {
		name     string
		dangling bool
	}{
		{name: "live"},
		{name: "dangling", dangling: true},
	}
	for _, tt := range tests {
		dangling := tt.dangling
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			if !dangling {
				require.NoError(t, os.WriteFile(target, []byte("untouched"), 0o644))
			}
			path := filepath.Join(dir, "key.pem")
			require.NoError(t, os.Symlink(target, path))

			require.Error(t, writeNewFile(path, []byte("KEY"), 0o600))

			if dangling {
				_, err := os.Lstat(target)
				assert.ErrorIs(t, err, os.ErrNotExist, "the link target is not created")
				return
			}
			got, err := os.ReadFile(target)
			require.NoError(t, err)
			assert.Equal(t, "untouched", string(got))
		})
	}
}

func TestValidateDevTLSGenFlags(t *testing.T) {
	tests := []struct {
		name     string
		dev      bool
		certDir  string
		sans     []string
		certFile string
		keyFile  string
		wantErr  string
	}{
		{name: "not requested"},
		{name: "not requested outside dev"},
		{name: "cert dir", dev: true, certDir: "/certs"},
		{name: "sans", dev: true, sans: []string{"warden"}},
		{name: "cert dir without -dev — error", certDir: "/certs", wantErr: "can only be used with -dev"},
		{name: "san without -dev — error", sans: []string{"warden"}, wantErr: "can only be used with -dev"},
		{name: "cert dir with cert file — error", dev: true, certDir: "/certs", certFile: "/c.pem", keyFile: "/k.pem", wantErr: "cannot be combined"},
		{name: "san with cert file — error", dev: true, sans: []string{"warden"}, certFile: "/c.pem", keyFile: "/k.pem", wantErr: "cannot be combined"},
		{name: "empty san — error", dev: true, sans: []string{" "}, wantErr: "must not be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDevTLSGenFlags(tt.dev, tt.certDir, tt.sans, tt.certFile, tt.keyFile)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
