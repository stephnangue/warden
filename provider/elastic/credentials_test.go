package elastic

import (
	"encoding/base64"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Assembled rather than written out as a literal: a base64 blob of this length
// reads as a real credential to a secret scanner however synthetic its contents,
// and the encoding hides from a reviewer that it is fake.
var encodedKey = base64.StdEncoding.EncodeToString([]byte("elastic-id:elastic-not-a-real-secret"))

// Elasticsearch authenticates under its own "ApiKey" scheme rather than Bearer,
// which is also why the token extractor has to dispatch on scheme. The value is
// carried through verbatim: it is already the base64 id:key pair the cluster
// issued, so the extractor must not re-encode it.

func TestElasticCredentialExtractor_Success(t *testing.T) {
	headers, err := elasticCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": encodedKey},
		},
	})
	require.NoError(t, err)
	// Passed through verbatim: the value is already the encoded id:key pair the
	// cluster issued, so encoding it again would produce a credential the
	// upstream cannot read.
	assert.Equal(t, "ApiKey "+encodedKey, headers["Authorization"])
	assert.Len(t, headers, 1)
}

func TestElasticCredentialExtractor_NoCredential(t *testing.T) {
	_, err := elasticCredentialExtractor(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestElasticCredentialExtractor_WrongType(t *testing.T) {
	_, err := elasticCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeOAuthBearerToken,
			Data: map[string]string{"api_key": "encoded"},
		},
	})
	assert.ErrorContains(t, err, "unsupported credential type")
}

func TestElasticCredentialExtractor_MissingAPIKey(t *testing.T) {
	_, err := elasticCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

func TestElasticCredentialExtractor_EmptyAPIKey(t *testing.T) {
	_, err := elasticCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": ""},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}
