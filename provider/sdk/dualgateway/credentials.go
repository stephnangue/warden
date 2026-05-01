package dualgateway

import (
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stephnangue/warden/logical"
)

// extractAPICredential extracts the API auth credential value using the
// provider's custom extractor or the default (reads CredentialField from Data).
func (b *dualgatewayBackend) extractAPICredential(req *logical.Request) (string, error) {
	if b.spec.ExtractAPICredential != nil {
		return b.spec.ExtractAPICredential(req)
	}
	return b.defaultExtractAPICredential(req)
}

func (b *dualgatewayBackend) defaultExtractAPICredential(req *logical.Request) (string, error) {
	if req.Credential == nil {
		return "", fmt.Errorf("no credential available")
	}
	if req.Credential.Type != b.spec.CredentialType {
		return "", fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
	value := req.Credential.Data[b.spec.APIAuth.CredentialField]
	if value == "" {
		return "", fmt.Errorf("credential missing %s", b.spec.APIAuth.CredentialField)
	}
	return value, nil
}

// extractS3Credentials extracts the real provider S3 credentials using the
// provider's custom extractor or the default (reads access_key + secret_key).
func (b *dualgatewayBackend) extractS3Credentials(req *logical.Request) (awssdk.Credentials, error) {
	if b.spec.ExtractS3Credentials != nil {
		return b.spec.ExtractS3Credentials(req)
	}
	return b.defaultExtractS3Credentials(req)
}

func (b *dualgatewayBackend) defaultExtractS3Credentials(req *logical.Request) (awssdk.Credentials, error) {
	if req.Credential == nil {
		return awssdk.Credentials{}, fmt.Errorf("no credential available")
	}
	if req.Credential.Type != b.spec.CredentialType {
		return awssdk.Credentials{}, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
	accessKey := req.Credential.Data["access_key"]
	secretKey := req.Credential.Data["secret_key"]
	if accessKey == "" || secretKey == "" {
		return awssdk.Credentials{}, fmt.Errorf("credential missing access_key or secret_key")
	}
	return awssdk.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	}, nil
}
