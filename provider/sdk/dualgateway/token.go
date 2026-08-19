package dualgateway

import (
	"net/http"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
)

// extractTokens resolves the principals on an S3-compatible dualgateway
// request.
//
// Agent-only: S3-compatible clients have no user leg. Note that Authorization
// here is NOT always a SigV4 signature — X-Warden-Token and a standard Bearer
// are both checked first — so the scoping is a product decision, not a
// structural limit. Always returns user == "".
//
// Extraction matrix. "-" means nothing extracted; an empty agent under a
// client certificate means the certificate authenticates the agent
// downstream. Off the user leg there is never a user.
//
//	request carries                     agent(off)  agent(on)  user(on)
//	Authorization: Bearer u             u           u          -
//	X-Warden-Token: w + Bearer u        w           w          -
//	X-Warden-Agent-Token: a + Bearer u  u           u          -
//	client cert + Bearer u              u           u          -
//	client cert only                    -           -          -
func extractTokens(r *http.Request, _ bool) (agent, user string) {
	// Standard Warden token
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token, ""
	}

	// Bearer token
	authHeader := r.Header.Get("Authorization")
	if token := logical.StripBearer(authHeader); token != "" {
		return token, ""
	}

	// S3 transparent: extract access_key_id from SigV4 header
	if sigv4.IsSigV4Request(r) {
		if accessKeyID := sigv4.ExtractAccessKeyID(authHeader); accessKeyID != "" {
			return accessKeyID, ""
		}
	}

	return "", ""
}
