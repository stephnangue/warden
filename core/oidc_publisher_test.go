package core

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWKSPublisher_Dispatch(t *testing.T) {
	// none -> nil publisher.
	p, err := newJWKSPublisher(publisherConfig{}, "")
	require.NoError(t, err)
	assert.Nil(t, p)

	// missing required fields error.
	_, err = newJWKSPublisher(publisherConfig{Type: "local_file"}, "")
	require.Error(t, err)
	_, err = newJWKSPublisher(publisherConfig{Type: "http_put"}, "")
	require.Error(t, err)
	_, err = newJWKSPublisher(publisherConfig{Type: "s3", Bucket: "b", Region: "r"}, "")
	require.Error(t, err) // missing keys
	_, err = newJWKSPublisher(publisherConfig{Type: "azure_blob", AccountName: "a", Container: "c"}, "")
	require.Error(t, err) // missing account_key
	_, err = newJWKSPublisher(publisherConfig{Type: "gcs"}, "")
	require.Error(t, err) // missing bucket
	_, err = newJWKSPublisher(publisherConfig{Type: "gcs", Bucket: "b"}, "")
	require.Error(t, err) // missing credentials_json

	// unsupported type.
	_, err = newJWKSPublisher(publisherConfig{Type: "ftp"}, "")
	require.Error(t, err)

	// valid constructions.
	p, err = newJWKSPublisher(publisherConfig{Type: "local_file", Dir: t.TempDir()}, "")
	require.NoError(t, err)
	assert.Equal(t, "local_file", p.Type())
	p, err = newJWKSPublisher(publisherConfig{Type: "http_put", BaseURL: "https://x"}, "")
	require.NoError(t, err)
	assert.Equal(t, "http_put", p.Type())
	p, err = newJWKSPublisher(publisherConfig{
		Type: "azure_blob", AccountName: "wardenoidc", Container: "jwks",
		AccountKey: base64.StdEncoding.EncodeToString([]byte("dummy-account-key")),
	}, "")
	require.NoError(t, err)
	assert.Equal(t, "azure_blob", p.Type())
}
