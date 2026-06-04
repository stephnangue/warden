package mcp_aws

import (
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
)

// extractAWSCredentials reads AWS credentials from req.Credential, which is
// populated by core's implicit-auth pipeline before the gateway handler runs.
// Mirrors alicloud's getCredentials in shape but matches the field names
// written by the aws source driver: access_key_id / secret_access_key /
// session_token (session_token is empty for long-lived AKIA... keys).
//
// Returns an error only on programmer-detected mismatch (wrong credential
// type bound to the role, or missing required fields). req.Credential is
// guaranteed non-nil here — STS mint failures surface earlier as
// logical.ErrorResponse from core's mintCredentialForRequest and the
// gateway handler is never invoked in that case.
func extractAWSCredentials(req *logical.Request) (awssdk.Credentials, error) {
	if req.Credential == nil {
		return awssdk.Credentials{}, fmt.Errorf("no credential available")
	}
	if req.Credential.Type != credential.TypeAWSAccessKeys {
		return awssdk.Credentials{}, fmt.Errorf("unsupported credential type %q (expected %q)", req.Credential.Type, credential.TypeAWSAccessKeys)
	}

	ak := req.Credential.Data["access_key_id"]
	sk := req.Credential.Data["secret_access_key"]
	if ak == "" || sk == "" {
		return awssdk.Credentials{}, fmt.Errorf("credential missing access_key_id or secret_access_key")
	}

	return awssdk.Credentials{
		AccessKeyID:     ak,
		SecretAccessKey: sk,
		SessionToken:    req.Credential.Data["session_token"],
	}, nil
}
