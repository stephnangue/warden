package spiffe

import (
	"context"
	"net/http"
	"time"

	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

func (b *spiffeAuthBackend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"jwt": {Type: framework.TypeString, Description: "A SPIFFE JWT-SVID. Omit when authenticating with an X.509-SVID via mTLS."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleLogin, Summary: "Authenticate with a SPIFFE X.509-SVID or JWT-SVID"},
			logical.CreateOperation: &framework.PathOperation{Callback: b.handleLogin, Summary: "Authenticate with a SPIFFE X.509-SVID or JWT-SVID"},
		},
		HelpSynopsis: "Authenticate with a SPIFFE SVID",
		HelpDescription: "Present an X.509-SVID (TLS/forwarded client certificate) or a JWT-SVID (the jwt field). When both are present the JWT-SVID is used. " +
			"It selects no role: the role a request runs under is granted per request.",
	}
}

// handleLogin admits the presented SVID against the mount's trust bundles and
// configuration with admitJWTSVID or admitX509SVID, the checks
// introspect/admit runs too, and returns the admission: the SPIFFE ID as
// principal, a JWT-SVID's act chain, and a TTL of the mount's token_ttl capped
// by the SVID's expiry. It carries no role, no policies, no credential spec and
// no metadata.
//
// A JWT-SVID (the jwt field) takes precedence over an X.509-SVID (a
// forwarded/TLS cert), so an explicitly-presented JWT-SVID is not shadowed by
// an ambient mesh cert. A nil config (an unconfigured mount) still admits
// X.509-SVIDs, which carry no audience, and admits no JWT-SVID, which needs
// bound_audiences.
func (b *spiffeAuthBackend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// One snapshot of the config and of the bundle set serves the whole
	// login, so a write landing mid-login cannot judge it by two of them.
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()
	set := b.spiffe.SnapshotBundleSet()
	now := time.Now()

	var (
		got         *admittedSVID
		err         error
		clientToken string
	)
	if jwtToken := d.Get("jwt").(string); jwtToken != "" {
		got, err = b.admitJWTSVID(set, config, jwtToken, now)
		clientToken = jwtToken
	} else if cert := extractClientCert(req); cert != nil {
		got, err = b.admitX509SVID(set, cert)
		clientToken = certFingerprint(cert)
	} else {
		return logical.ErrorResponse(logical.ErrBadRequest("no X.509-SVID (TLS/forwarded certificate) or JWT-SVID presented")), nil
	}
	if err != nil {
		b.logger.Warn("login failed: SVID not admitted", lgr.Err(err))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	// The act chain is read only from a JWT-SVID's claims; an X.509-SVID has
	// none.
	var actors []logical.ActorRef
	if got.claims != nil {
		actors = extractActChain(got.claims)
	}

	principalID := got.id.String()
	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID: principalID,
			TokenType:   logical.TokenTypeIdentity,
			TokenTTL:    calculateTTL(config, got.expiry, now),
			ClientIP:    req.ClientIP,
			ClientToken: clientToken,
			Actors:      actors,
			Admission:   got.adm,
		},
		Data: map[string]any{"principal_id": principalID},
	}, nil
}

// calculateTTL caps the token TTL at now by the SVID's expiry (so the token
// never outlives the SVID), then by the mount's token_ttl. A zero token_ttl
// (or a nil config) means "no cap from the mount," not "expire immediately."
func calculateTTL(config *SPIFFEAuthConfig, svidExpiry, now time.Time) time.Duration {
	effective := svidExpiry.Sub(now)
	if effective <= 0 {
		return 0
	}
	if config != nil && config.TokenTTL > 0 && config.TokenTTL < effective {
		effective = config.TokenTTL
	}
	return effective
}
