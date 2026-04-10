package aws

import (
	"context"
	"net/http"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stephnangue/warden/provider/sigv4"
)

// normalizeRequest prepares a request for re-signing by decoding aws-chunked
// bodies, stripping trailer-related headers, and removing hop-by-hop/proxy
// headers that would break the AWS signature. Returns the (possibly decoded)
// body bytes to forward.
func (b *awsBackend) normalizeRequest(r *http.Request, bodyBytes []byte) []byte {
	return sigv4.NormalizeRequest(b.Logger, r, bodyBytes)
}

// resignRequest re-signs the request with valid AWS credentials.
// The request must already be normalized via normalizeRequest.
func (b *awsBackend) resignRequest(
	ctx context.Context,
	r *http.Request,
	creds awssdk.Credentials,
	service, region string,
	bodyBytes []byte,
) error {
	return sigv4.ResignRequest(ctx, b.getSigner(service), r, creds, service, region, bodyBytes)
}

// getSigner returns the appropriate signer for the service.
// S3 and S3-Control services require DisableURIPathEscaping.
func (b *awsBackend) getSigner(service string) *v4.Signer {
	if service == "s3" || service == "s3-control" {
		return b.s3Signer
	}
	return b.signer
}

// verifyIncomingSignature verifies the AWS Signature V4 of the incoming request.
func (b *awsBackend) verifyIncomingSignature(
	r *http.Request,
	bodyBytes []byte,
	creds awssdk.Credentials,
	service, region string,
) (bool, error) {
	return sigv4.VerifyIncomingSignature(b.Logger, b.getSignerOpts(service), r, bodyBytes, creds, service, region)
}

// getSignerOpts returns the signer options for the given service.
func (b *awsBackend) getSignerOpts(service string) []func(*v4.SignerOptions) {
	if service == "s3" || service == "s3-control" {
		return []func(*v4.SignerOptions){
			func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true },
		}
	}
	return nil
}
