package drivers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// Signed-assertion grants: Warden writes a set of claims, has a signer turn them
// into a JWT, and trades the JWT for an access token at an authorization server
// (RFC 7523 §2.1). The claims name who the token is for, which is what sets this
// apart from a client assertion (client_assertion.go): there the JWT only
// authenticates the client, and the grant is something else.
//
// The pieces are kept apart so each upstream supplies only what is its own: the
// claims it expects, and where its signing key lives.

// grantTypeJWTBearer is the RFC 7523 §2.1 grant type: an assertion traded for an
// access token.
const grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// assertionSigner signs claims into a compact JWT.
//
// The header is the signer's to write: its algorithm and key id follow from the
// key, and a signer that is a remote API (a cloud's IAM service signing with a key
// it holds) writes the whole header itself and never takes one from the caller.
//
// Implementations must be safe for concurrent use: one signer may serve every
// cache miss of a spec at once.
type assertionSigner interface {
	SignJWT(ctx context.Context, claims map[string]interface{}) (string, error)
}

// jwtBearerReadableStatuses are the statuses whose token-endpoint body is read as
// an OAuth2 error. It adds 403 to the RFC 6749 §5.2 set: authorization servers
// answer some refusals of an assertion grant (a client not authorized for the
// requested scopes, say) with it, and the error code in the body is what tells
// an operator which.
var jwtBearerReadableStatuses = []int{
	http.StatusOK,
	http.StatusBadRequest,
	http.StatusUnauthorized,
	http.StatusForbidden,
}

// errNoAccessToken is a token response that succeeded and carried no token.
var errNoAccessToken = errors.New("token endpoint returned no access_token")

// postJWTBearerGrant trades a signed assertion for an access token (RFC 7523 §2.1).
//
// claims is called, and its result signed, once per attempt, so a retry presents a
// fresh assertion with a fresh iat rather than replaying one the server may have
// recorded. A signing failure means nothing was sent and is returned as the
// signer's own error, sentinels intact. A refusal is a *tokenEndpointError
// carrying the status and the parsed OAuth2 error code; this function does not
// classify it, since what a code means to an operator depends on the upstream.
func postJWTBearerGrant(ctx context.Context, httpClient *http.Client, tokenURL string, signer assertionSigner, claims func() map[string]interface{}) (*oauth2TokenResponse, error) {
	build := func() (url.Values, error) {
		assertion, err := signer.SignJWT(ctx, claims())
		if err != nil {
			return nil, err
		}
		return url.Values{
			"grant_type": {grantTypeJWTBearer},
			"assertion":  {assertion},
		}, nil
	}
	resp, err := postOAuthTokenFormFuncReading(ctx, httpClient, tokenURL, build, nil, jwtBearerReadableStatuses)
	if err != nil {
		return nil, err
	}
	if resp.AccessToken == "" {
		return nil, errNoAccessToken
	}
	return resp, nil
}
