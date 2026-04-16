package ibmcloud

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpec(t *testing.T) {
	assert.Equal(t, "ibmcloud", Spec.Name)
	assert.Equal(t, credential.TypeIBMCloudKeys, Spec.CredentialType)
	assert.Equal(t, DefaultIBMCloudURL, Spec.DefaultURL)
	assert.Equal(t, "ibmcloud_url", Spec.URLConfigKey)
	assert.Equal(t, DefaultIBMCloudTimeout, Spec.DefaultTimeout)
	assert.Equal(t, "warden-ibmcloud-proxy", Spec.UserAgent)
}

func TestSpec_APIAuth(t *testing.T) {
	assert.Equal(t, "Authorization", Spec.APIAuth.HeaderName)
	assert.Equal(t, "Bearer %s", Spec.APIAuth.HeaderValueFormat)
	assert.Equal(t, "access_token", Spec.APIAuth.CredentialField)
	assert.True(t, Spec.APIAuth.StripAuthorization)
}

func TestSpec_S3Endpoint(t *testing.T) {
	require.NotNil(t, Spec.S3Endpoint)

	tests := []struct {
		region   string
		expected string
	}{
		{"us-south", "s3.us-south.cloud-object-storage.appdomain.cloud"},
		{"eu-de", "s3.eu-de.cloud-object-storage.appdomain.cloud"},
		{"au-syd", "s3.au-syd.cloud-object-storage.appdomain.cloud"},
		{"jp-tok", "s3.jp-tok.cloud-object-storage.appdomain.cloud"},
	}
	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			got := Spec.S3Endpoint(nil, tt.region)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestSpec_ExtractS3Credentials(t *testing.T) {
	require.NotNil(t, Spec.ExtractS3Credentials)
}

func TestFactory(t *testing.T) {
	assert.NotNil(t, Factory)
}
