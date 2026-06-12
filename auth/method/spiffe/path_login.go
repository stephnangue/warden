package spiffe

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

func (b *spiffeAuthBackend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"role": {Type: framework.TypeString, Description: "Role to assume (falls back to default_role if configured)"},
			"jwt":  {Type: framework.TypeString, Description: "A SPIFFE JWT-SVID. Omit when authenticating with an X.509-SVID via mTLS."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleLogin, Summary: "Authenticate with a SPIFFE X.509-SVID or JWT-SVID"},
			logical.CreateOperation: &framework.PathOperation{Callback: b.handleLogin, Summary: "Authenticate with a SPIFFE X.509-SVID or JWT-SVID"},
		},
		HelpSynopsis:    "Authenticate with a SPIFFE SVID",
		HelpDescription: "Present an X.509-SVID (TLS/forwarded client certificate) or a JWT-SVID (the jwt field). When both are present the JWT-SVID is used.",
	}
}

// handleLogin sniffs the presented credential and dispatches. A JWT-SVID (the
// jwt field) takes precedence over an X.509-SVID (a forwarded/TLS cert), so an
// explicitly-presented JWT-SVID is not shadowed by an ambient mesh cert.
func (b *spiffeAuthBackend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()

	roleName := d.Get("role").(string)
	if roleName == "" && config != nil && config.DefaultRole != "" {
		roleName = config.DefaultRole
	}
	if roleName == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("missing role")), nil
	}

	role, err := b.getRole(ctx, roleName)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if role == nil || role.TrustDomain == "" {
		b.logger.Warn("login failed: role not found or not bound to a trust domain", lgr.String("role", roleName))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	jwtToken := d.Get("jwt").(string)
	if jwtToken != "" {
		return b.handleJWTSVIDLogin(ctx, req, role, jwtToken)
	}
	if cert := extractClientCert(req); cert != nil {
		return b.handleX509SVIDLogin(ctx, req, role, cert)
	}
	return logical.ErrorResponse(logical.ErrBadRequest("no X.509-SVID (TLS/forwarded certificate) or JWT-SVID presented")), nil
}

func (b *spiffeAuthBackend) handleX509SVIDLogin(ctx context.Context, req *logical.Request, role *SPIFFERole, cert *x509.Certificate) (*logical.Response, error) {
	expectedTD, err := spiffeid.TrustDomainFromString(role.TrustDomain)
	if err != nil {
		b.logger.Warn("login failed: role has invalid trust_domain", lgr.Err(err), lgr.String("role", role.Name))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	set := b.spiffe.SnapshotBundleSet()
	if set == nil || set.Len() == 0 {
		b.logger.Warn("login failed: no SPIFFE trust bundles loaded", lgr.String("role", role.Name))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	id, _, err := spiffelib.VerifyX509SVID(set, []*x509.Certificate{cert}, expectedTD, role.AllowedSPIFFEIDs)
	if err != nil {
		b.logger.Warn("login failed: X.509-SVID verification", lgr.Err(err), lgr.String("role", role.Name))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	principalID := id.String()
	fingerprint := certFingerprint(cert)
	return b.authResponse(req, role, principalID, b.calculateTTL(cert.NotAfter, role), fingerprint, nil), nil
}

func (b *spiffeAuthBackend) handleJWTSVIDLogin(ctx context.Context, req *logical.Request, role *SPIFFERole, jwtToken string) (*logical.Response, error) {
	expectedTD, err := spiffeid.TrustDomainFromString(role.TrustDomain)
	if err != nil {
		b.logger.Warn("login failed: role has invalid trust_domain", lgr.Err(err), lgr.String("role", role.Name))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	// JWT-SVID mandates an audience; a role with none must not authenticate one.
	audience := resolveAudience(role)
	if len(audience) == 0 {
		b.logger.Warn("login failed: JWT-SVID login requires bound_audiences on the role", lgr.String("role", role.Name))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	set := b.spiffe.SnapshotBundleSet()
	if set == nil || set.Len() == 0 {
		b.logger.Warn("login failed: no SPIFFE trust bundles loaded", lgr.String("role", role.Name))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	svid, err := spiffelib.VerifyJWTSVID(set, jwtToken, audience, expectedTD, role.AllowedSPIFFEIDs)
	if err != nil {
		b.logger.Warn("login failed: JWT-SVID verification", lgr.Err(err), lgr.String("role", role.Name))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errSPIFFEAuthFailed}, nil
	}

	policies := b.resolveGroupPolicies(role, svid.Claims)
	actors := extractActChain(svid.Claims)
	resp := b.authResponse(req, role, svid.ID.String(), b.calculateTTL(svid.Expiry, role), jwtToken, actors)
	resp.Auth.Policies = policies
	return resp, nil
}

// authResponse builds the common login response. policies default to the role's;
// the JWT path overrides with group-resolved policies.
func (b *spiffeAuthBackend) authResponse(req *logical.Request, role *SPIFFERole, principalID string, ttl time.Duration, clientToken string, actors []logical.ActorRef) *logical.Response {
	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID:    principalID,
			RoleName:       role.Name,
			Policies:       role.TokenPolicies,
			CredentialSpec: role.CredSpecName,
			TokenType:      "spiffe_role",
			TokenTTL:       ttl,
			ClientIP:       req.ClientIP,
			ClientToken:    clientToken,
			Actors:         actors,
		},
		Data: map[string]any{"principal_id": principalID, "role": role.Name},
	}
}

// resolveGroupPolicies appends group-derived policies (JWT-SVID only) to the
// role's token policies.
func (b *spiffeAuthBackend) resolveGroupPolicies(role *SPIFFERole, claims map[string]interface{}) []string {
	policies := role.TokenPolicies
	if role.GroupsClaim == "" {
		return policies
	}
	groups := extractGroupsClaim(claims, role.GroupsClaim)
	if len(groups) == 0 {
		return policies
	}
	prefix := role.GroupPolicyPrefix
	if prefix == "" {
		prefix = "group-"
	}
	groupPolicies := make([]string, len(groups))
	for i, g := range groups {
		groupPolicies[i] = prefix + g
	}
	return append(append([]string{}, policies...), groupPolicies...)
}

// calculateTTL caps the token TTL by the SVID's expiry (so the token never
// outlives the SVID), then by the role and config TTLs. A zero role/config TTL
// means "no cap from that source," not "expire immediately."
func (b *spiffeAuthBackend) calculateTTL(svidExpiry time.Time, role *SPIFFERole) time.Duration {
	effective := time.Until(svidExpiry)
	if effective <= 0 {
		return 0
	}
	if roleTTL, err := role.ParseTokenTTL(); err == nil && roleTTL > 0 && roleTTL < effective {
		effective = roleTTL
	}
	b.configMu.RLock()
	var configTTL time.Duration
	if b.config != nil {
		configTTL = b.config.TokenTTL
	}
	b.configMu.RUnlock()
	if configTTL > 0 && configTTL < effective {
		effective = configTTL
	}
	return effective
}
