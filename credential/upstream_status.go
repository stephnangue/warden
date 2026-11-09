package credential

import (
	"errors"

	smithyhttp "github.com/aws/smithy-go/transport/http"
	vaultapi "github.com/hashicorp/vault/api"
	"golang.org/x/oauth2"
)

// UpstreamStatus is the HTTP status an upstream answered a failed call with,
// found anywhere in err's chain. It is false when the failure carries none:
// the call never got an answer (a transport failure), or the error that
// recorded the answer kept only its text.
//
// It recognises an error that reports the status itself (HTTPStatus, as
// httputil.StatusError and the OAuth2 token endpoint error do) and the error
// types of the client libraries the drivers call through: the AWS SDK's
// response errors, Vault's, and x/oauth2's.
func UpstreamStatus(err error) (int, bool) {
	var reported interface{ HTTPStatus() int }
	if errors.As(err, &reported) {
		if status := reported.HTTPStatus(); status > 0 {
			return status, true
		}
		// That error never got an answer, but one it wraps may have.
		if wrapper, ok := reported.(interface{ Unwrap() error }); ok && wrapper.Unwrap() != nil {
			if status, ok := UpstreamStatus(wrapper.Unwrap()); ok {
				return status, true
			}
		}
	}
	// The AWS SDK's response error is found through smithy's, which it embeds
	// and hands to errors.As. Checked field by field: HTTPStatusCode
	// dereferences the response, which a failure before any answer leaves nil.
	var smithyErr *smithyhttp.ResponseError
	if errors.As(err, &smithyErr) && smithyErr.Response != nil && smithyErr.Response.Response != nil {
		return smithyErr.Response.StatusCode, true
	}
	var vault *vaultapi.ResponseError
	if errors.As(err, &vault) && vault.StatusCode > 0 {
		return vault.StatusCode, true
	}
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) && retrieve.Response != nil {
		return retrieve.Response.StatusCode, true
	}
	return 0, false
}
