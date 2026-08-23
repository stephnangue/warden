package dualgateway

import (
	"net/http"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
)

// extractTokens resolves the principals on a dual-mode gateway request.
//
// The two modes differ in what they can carry, so the scoping is per request,
// not per mount. An API-mode request uses the standard channel rules every
// other provider uses. An S3-mode request cannot: the SigV4 signature occupies
// Authorization and the access key it names *is* the agent identity, leaving
// nowhere for a second principal to ride. provider/aws is agent-only for the
// same reason.
//
// X-Warden-Token is checked ahead of the signature because a signed request may
// also carry the operator credential — that is the non-transparent S3 path,
// where the caller authenticates to Warden and Warden mints the keys the
// request is re-signed with.
//
// That path and user_auth_path are mutually exclusive, and the mount is where
// they collide rather than the request: core refuses X-Warden-Token alongside a
// non-empty Authorization on a protected-resource mount, and a signed request's
// Authorization is never empty. So configuring a user leg on a mount that also
// serves non-transparent S3 turns every such request into a 400. Fail-closed,
// but it means the two modes want separate mounts — see the user_auth_path
// help text on the config path.
//
// Extraction matrix. "-" means nothing extracted; an empty agent under a
// client certificate means the certificate authenticates the agent
// downstream. Off the user leg there is never a user.
//
//	request carries                     agent(off)  agent(on)  user(on)
//	Authorization: Bearer u             u           u          -
//	X-Warden-Token: w + Bearer u        w           w          -
//	X-Warden-Agent-Token: a + Bearer u  u           a          u
//	client cert + Bearer u              u           -          u
//	client cert only                    -           -          -
//	SigV4 signature                     key         key        -
//	SigV4 + X-Warden-Token: w           w           w          -
//	SigV4 + X-Warden-Agent-Token: a     key         key        -
//
// The last two rows are only reachable with the user leg off: with it on, core
// rejects the first before extraction, and the second authenticates as the
// signed access key while the agent-token header is ignored (and stripped
// before forwarding, like every other Warden channel).
func extractTokens(r *http.Request, userLeg bool) (agent, user string) {
	if r == nil {
		return "", ""
	}

	if r.Header.Get(logical.HeaderWardenToken) == "" && sigv4.IsSigV4Request(r) {
		return sigv4.ExtractAccessKeyID(r.Header.Get("Authorization")), ""
	}

	return logical.ExtractTokensWithChannels(r, userLeg, logical.HeaderWardenToken)
}
