package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

// Entra on-behalf-of (OBO) mint method.
//
// The user's own Entra access token — its audience is the app named by the spec's
// client_id — goes in the grant's assertion field. The app authenticates itself
// separately: over a keyless source with the Warden assertion core minted for the
// actor slot (checked by Entra against a federated identity credential on the
// app), over a static source with the source's client secret. The user's token is
// never the client credential: it only ever lands in assertion.
const (
	azureMintMethodOnBehalfOf = "on_behalf_of"

	oboGrantType          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	oboRequestedTokenUse  = "on_behalf_of"
	oboOperation          = "acquireOnBehalfOf"
	oboRefreshBuffer      = 2 * time.Minute
	oboMaxTokenLifetime   = 24 * time.Hour
	oboMaxClaimsChallenge = 4 << 10
	maxEntraErrorCodes    = 8
)

// AzureOnBehalfOf reports whether a spec mints on-behalf-of tokens. It is the one
// shape in which an azure source may take subject_token_source=user_identity and
// an actor: the user's token becomes the OBO assertion, never the app's own
// credential. Pure: reads spec config only.
func AzureOnBehalfOf(specType string, specCfg credential.Config) bool {
	return specType == credential.TypeAzureBearerToken &&
		credential.GetString(specCfg, "mint_method", "") == azureMintMethodOnBehalfOf
}

// AzureOnBehalfOfSpecError checks an on_behalf_of spec against its source: what
// authenticates the app depends on the source's auth_method, and a static secret
// belongs to one app. It is applied when the spec is written and again when the
// source changes, since a source switched between static and keyless would strand
// the spec. Pure: reads the two configs only.
func AzureOnBehalfOfSpecError(specCfg, sourceCfg credential.Config) error {
	if specCfg.Get(credential.ConfigSubjectTokenSource) != credential.SourceUserIdentity {
		return fmt.Errorf("mint_method=on_behalf_of forwards the user's Entra access token as the OBO assertion: set %s=%s",
			credential.ConfigSubjectTokenSource, credential.SourceUserIdentity)
	}
	actor := specCfg.Get(credential.ConfigActorTokenSource)
	if actor == credential.SourceNone {
		actor = ""
	}
	if credential.GetString(sourceCfg, "auth_method", azureAuthMethodStatic) == azureAuthMethodOIDCFederation {
		// A keyless spec may name any app: the Warden assertion is checked against
		// that app's own federated credential.
		if actor != credential.SourceWardenIdentity {
			return fmt.Errorf("a keyless on_behalf_of spec authenticates the app with a Warden assertion checked against its federated credential: set %s=%s",
				credential.ConfigActorTokenSource, credential.SourceWardenIdentity)
		}
	} else {
		if actor != "" {
			return fmt.Errorf("a static azure source authenticates on_behalf_of with its client_secret: remove %s",
				credential.ConfigActorTokenSource)
		}
		// A static secret belongs to the source's app, in the source's tenant.
		for _, key := range []string{"client_id", "tenant_id"} {
			if s, v := sourceCfg.Get(key), specCfg.Get(key); s != "" && v != "" && s != v {
				return fmt.Errorf("on_behalf_of over a static source authenticates as the source's app: spec '%s' must match the source's", key)
			}
		}
	}
	// Keys the OBO request has no use for. The driver would ignore them, but they
	// still change the credential cache key, and assertion_user_claims would read
	// as projecting the user into an assertion that names only the agent.
	for _, key := range []string{credential.ConfigAssertionUserClaims, credential.ConfigSubjectTokenType, credential.ConfigActorTokenType} {
		if specCfg.Get(key) != "" {
			return fmt.Errorf("'%s' does not apply to mint_method=on_behalf_of", key)
		}
	}
	return nil
}

// oboAuth is how the app authenticates an OBO request: exactly one of secret or
// assertion is set.
type oboAuth struct {
	secret    string
	assertion string
}

// mintOnBehalfOf exchanges the user's Entra token for a delegated token to the
// spec's resource (Microsoft Graph unless resource_uri says otherwise).
//
// Nothing per user is kept here: the credential manager caches the result under a
// key that carries the user token, and bounds it by the user token's lifetime.
func (d *AzureDriver) mintOnBehalfOf(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("azure: mint_method=on_behalf_of exchanges the user's Entra access token (subject_token_source=user_identity), and the request carried none: %w", credential.ErrUserRequired)
	}

	// One snapshot: a rotation landing mid-mint must not pair a client id with a
	// secret from another generation.
	srcCfg := d.sourceConfig()
	clientID, auth, err := d.oboClientAuth(ctx, srcCfg, spec, inputs)
	if err != nil {
		return nil, nil, 0, "", err
	}
	tenantID := credential.GetString(spec.Config, "tenant_id", credential.GetString(srcCfg, "tenant_id", ""))
	resourceURI := credential.GetString(spec.Config, "resource_uri", graphResource)
	scope := azureScope(resourceURI)

	form := url.Values{}
	form.Set("grant_type", oboGrantType)
	form.Set("client_id", clientID)
	form.Set("assertion", inputs.SubjectToken)
	form.Set("requested_token_use", oboRequestedTokenUse)
	form.Set("scope", scope)
	if auth.assertion != "" {
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", auth.assertion)
	} else {
		form.Set("client_secret", auth.secret)
	}

	tok, err := d.postOBOTokenRequest(ctx, tenantID, form)
	if err != nil {
		err = classifyEntraOBOError(err, tenantID, clientID, scope, auth.assertion != "")
		// The client re-authenticates at the same authority this request went to,
		// whatever cloud login_endpoint names.
		var uce *credential.UserChallengeError
		if errors.As(err, &uce) {
			uce.AuthorizationURI = fmt.Sprintf("%s/%s/oauth2/v2.0/authorize", d.loginBase(), tenantID)
		}
		return nil, nil, 0, "", err
	}

	lifetime := time.Duration(tok.ExpiresIn) * time.Second
	if lifetime > oboMaxTokenLifetime {
		lifetime = oboMaxTokenLifetime
	}
	ttl := federatedLeaseTTL(lifetime, oboRefreshBuffer, spec.MaxTTL)

	rawData := map[string]interface{}{"access_token": tok.AccessToken}
	metadata := azureOBOTokenMetadata(clientID, tenantID, resourceURI, inputs, ttl, time.Now())

	if d.logger != nil {
		d.logger.Debug("minted Azure AD on-behalf-of token",
			logger.String("spec", spec.Name),
			logger.String("resource_uri", resourceURI),
			logger.String("ttl", ttl.String()),
		)
	}

	// No leaseID: Entra tokens expire naturally and cannot be revoked.
	return rawData, metadata, ttl, "", nil
}

// oboClientAuth resolves the app an OBO request is made as, and how it proves it.
//
// It returns the client id along with the credential because the app is not
// always the spec's: a later Entra Agent ID mode authenticates as an agent
// identity with a blueprint token, which this resolver is the place to fetch.
// Today it reads only the source snapshot it is given.
func (d *AzureDriver) oboClientAuth(_ context.Context, srcCfg credential.Config, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (string, oboAuth, error) {
	srcTenant, srcClient, srcSecret := azureCreds(srcCfg)
	clientID := credential.GetString(spec.Config, "client_id", srcClient)
	if clientID == "" {
		return "", oboAuth{}, fmt.Errorf("azure: mint_method=on_behalf_of needs the app's 'client_id' on the spec or the source")
	}

	switch credential.GetString(srcCfg, "auth_method", azureAuthMethodStatic) {
	case azureAuthMethodOIDCFederation:
		if inputs.ActorToken == "" {
			return "", oboAuth{}, fmt.Errorf("azure: a keyless on_behalf_of spec authenticates the app with a Warden assertion; set actor_token_source=warden_identity")
		}
		// The user's token is never the client credential.
		if inputs.ActorToken == inputs.SubjectToken {
			return "", oboAuth{}, fmt.Errorf("azure: on_behalf_of refuses a client assertion identical to the user's token")
		}
		return clientID, oboAuth{assertion: inputs.ActorToken}, nil
	default:
		// A static source's secret belongs to the source's own app, so the spec
		// cannot name another one, and a source that switched from keyless to
		// static must not carry on sending an assertion it now ignores.
		if inputs.ActorToken != "" {
			return "", oboAuth{}, fmt.Errorf("azure: a static source authenticates on_behalf_of with its client secret; remove actor_token_source from the spec")
		}
		if clientID != srcClient {
			return "", oboAuth{}, fmt.Errorf("azure: on_behalf_of over a static source must use the source's own app; spec 'client_id' differs from the source's")
		}
		if t := credential.GetString(spec.Config, "tenant_id", ""); t != "" && t != srcTenant {
			return "", oboAuth{}, fmt.Errorf("azure: on_behalf_of over a static source must use the source's tenant; spec 'tenant_id' differs from the source's")
		}
		if srcSecret == "" {
			return "", oboAuth{}, fmt.Errorf("azure: the static source has no client_secret to authenticate on_behalf_of")
		}
		return clientID, oboAuth{secret: srcSecret}, nil
	}
}

// azureOBOTokenMetadata names the parties of a delegated token. subject is the
// user — oid (stable, and present for guests) before sub — read from the user's
// token, which the user leg verified at login. actor is the Warden identity that
// authenticated the app, when one did: the sub of the federated client assertion,
// which is the subject the app's federated credential must name. Claim reads
// only: no token bytes are recorded. Every value is a string: credential
// metadata is audited and salted as strings, so a credential type refuses any
// other value rather than guess at its rendering.
func azureOBOTokenMetadata(clientID, tenantID, resourceURI string, inputs *credential.ExchangeInputs, ttl time.Duration, now time.Time) map[string]interface{} {
	meta := map[string]interface{}{
		"client_id":    clientID,
		"tenant_id":    tenantID,
		"resource_uri": resourceURI,
		"delegated":    "true",
		// When Warden stops serving the token (the lease), not the token's own exp.
		"expiration": now.Add(ttl).UTC().Format(time.RFC3339),
	}
	if claims := unverifiedJWTClaims(inputs.SubjectToken); claims != nil {
		for _, key := range []string{"oid", "sub"} {
			if v, ok := scalarClaim(claims[key]); ok && v != "" {
				meta["subject"] = v
				break
			}
		}
	}
	if inputs.ActorToken != "" {
		if claims := unverifiedJWTClaims(inputs.ActorToken); claims != nil {
			if v, ok := scalarClaim(claims["sub"]); ok && v != "" {
				meta["actor"] = v
			}
		}
	}
	return meta
}

// entraTokenResponse is the part of a token response Warden keeps. Entra answers
// an OBO request with a refresh_token (and may add an id_token) even when
// offline_access was not asked for; they are deliberately not decoded, so they
// never reach the credential, its metadata, a log or the audit trail. Keeping one
// would let a delegated token outlive the user's own.
type entraTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// entraErrorResponse is the part of an Entra error body Warden reads.
// error_description is left out on purpose: it carries CR/LF, user names and
// free text, and must not reach an error string, a header or the audit trail.
type entraErrorResponse struct {
	Error         string `json:"error"`
	ErrorCodes    []int  `json:"error_codes"`
	Suberror      string `json:"suberror"`
	Claims        string `json:"claims"`
	TraceID       string `json:"trace_id"`
	CorrelationID string `json:"correlation_id"`
}

// entraTokenError is an Entra refusal, reduced to fields that are safe to log.
type entraTokenError struct {
	status        int
	code          string
	codes         []int
	suberror      string
	claims        string // compact JSON claims request, or ""
	traceID       string
	correlationID string
}

func (e *entraTokenError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: Entra ID answered %d", oboOperation, e.status)
	if e.code != "" {
		b.WriteString(" " + e.code)
	}
	if len(e.codes) > 0 {
		parts := make([]string, len(e.codes))
		for i, c := range e.codes {
			parts[i] = fmt.Sprintf("AADSTS%d", c)
		}
		b.WriteString(" [" + strings.Join(parts, ",") + "]")
	}
	if e.suberror != "" {
		b.WriteString(" suberror=" + e.suberror)
	}
	if e.traceID != "" {
		b.WriteString(" trace_id=" + e.traceID)
	}
	if e.correlationID != "" {
		b.WriteString(" correlation_id=" + e.correlationID)
	}
	return b.String()
}

// HTTPStatus is the status Entra answered with.
func (e *entraTokenError) HTTPStatus() int { return e.status }

func (e *entraTokenError) hasCode(codes ...int) bool {
	return slices.ContainsFunc(e.codes, func(c int) bool { return slices.Contains(codes, c) })
}

var (
	// entraWordRe and entraIDRe bound what an Entra error field may carry into an
	// error string: the authority is operator-configurable (login_endpoint), so its
	// answers are not trusted to be well-formed.
	entraWordRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	entraIDRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

func entraSafe(re *regexp.Regexp, s string) string {
	if re.MatchString(s) {
		return s
	}
	return ""
}

// compactClaims re-marshals an Entra claims request so nothing Entra wrote is
// copied through verbatim. A value that is not a JSON object, or is implausibly
// large, is dropped.
func compactClaims(raw string) string {
	if raw == "" || len(raw) > oboMaxClaimsChallenge {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil || len(obj) == 0 {
		return ""
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(out)
}

// loginBase is the Entra authority host: the source's login_endpoint, else the
// public cloud's.
func (d *AzureDriver) loginBase() string {
	if d.loginHost != "" {
		return d.loginHost
	}
	return defaultAzureLoginHost
}

// postOBOTokenRequest POSTs an OBO token request to the Entra token endpoint for
// tenantID. Unlike postTokenRequest it reads 400 and 401 bodies, so a refusal is
// classified by its AADSTS codes, and it never embeds a response body in an error.
// One attempt: a refused grant will not succeed on retry, and a throttled or
// failing endpoint is reported as such for the caller to retry.
func (d *AzureDriver) postOBOTokenRequest(ctx context.Context, tenantID string, form url.Values) (*entraTokenResponse, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", d.loginBase(), tenantID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader([]byte(form.Encode())))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request: %w", oboOperation, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", oboOperation, err)
	}
	body, bodyErr := readLimitedBody(resp.Body)
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if bodyErr != nil {
			return nil, fmt.Errorf("%s: failed to read token response: %w", oboOperation, bodyErr)
		}
		var tok entraTokenResponse
		if err := json.Unmarshal(body, &tok); err != nil {
			return nil, fmt.Errorf("%s: failed to decode token response", oboOperation)
		}
		if tok.AccessToken == "" {
			return nil, fmt.Errorf("%s: token response carried no access_token", oboOperation)
		}
		if tok.ExpiresIn <= 0 {
			return nil, fmt.Errorf("%s: token response carried no positive expires_in (got %d)", oboOperation, tok.ExpiresIn)
		}
		return &tok, nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		ete := &entraTokenError{status: resp.StatusCode}
		var eb entraErrorResponse
		if bodyErr == nil && json.Unmarshal(body, &eb) == nil {
			ete.code = entraSafe(entraWordRe, eb.Error)
			// Entra sends one or two codes; a longer list is not Entra's, and is cut
			// so it cannot swell an error string, a log line or an audit entry.
			ete.codes = eb.ErrorCodes[:min(len(eb.ErrorCodes), maxEntraErrorCodes)]
			ete.suberror = entraSafe(entraWordRe, eb.Suberror)
			ete.claims = compactClaims(eb.Claims)
			ete.traceID = entraSafe(entraIDRe, eb.TraceID)
			ete.correlationID = entraSafe(entraIDRe, eb.CorrelationID)
		}
		return nil, ete
	default:
		return nil, &httputil.StatusError{Status: resp.StatusCode,
			Err: fmt.Errorf("%s: token endpoint answered status %d", oboOperation, resp.StatusCode)}
	}
}

// classifyEntraOBOError turns an OBO failure into what the caller can act on.
// Codes decide, not the error value: Entra files a bad user token under
// invalid_grant and a refused federated credential under invalid_client.
//
//   - a claims challenge or interaction_required (AADSTS50079/50076): the user
//     re-authenticates satisfying the claims — a UserChallengeError;
//   - an unusable user token (50013 wrong audience or signature, 500133 expired):
//     the user presents a fresh one — a UserChallengeError. Not when Entra files
//     it under invalid_client: then it is the client assertion that failed (a
//     Warden-side clock or lifetime problem), and telling the user to sign in again
//     would only loop;
//   - missing consent (65001), a refused federated credential (70021,
//     700211–700213) or secret (7000215, 7000222): the operator must act, so the
//     message says what to fix.
func classifyEntraOBOError(err error, tenantID, clientID, scope string, federated bool) error {
	var ete *entraTokenError
	if !errors.As(err, &ete) {
		return fmt.Errorf("azure: on-behalf-of token request failed: %w", err)
	}
	switch {
	case ete.claims != "" || ete.code == "interaction_required" || ete.hasCode(50079, 50076):
		if ete.claims == "" {
			// Nothing to re-acquire the token with: the user has to sign in
			// interactively, which a silent refresh would never do.
			return &credential.UserChallengeError{Code: credential.UserChallengeInvalidToken, Interaction: true, TenantID: tenantID, Cause: ete}
		}
		return &credential.UserChallengeError{Code: credential.UserChallengeInsufficientClaims, Claims: ete.claims, TenantID: tenantID, Cause: ete}
	case ete.hasCode(50013, 500133) && ete.code != "invalid_client":
		return &credential.UserChallengeError{Code: credential.UserChallengeInvalidToken, TenantID: tenantID, Cause: ete}
	case ete.hasCode(65001) || ete.suberror == "consent_required":
		return fmt.Errorf("azure: admin consent is missing; grant admin consent to app %s for %s: %w", clientID, scope, ete)
	case ete.hasCode(70021, 700211, 700212, 700213) || (federated && ete.code == "invalid_client"):
		return fmt.Errorf("azure: Entra ID refused Warden's federated credential for app %s; check the federated identity credential's issuer, subject and audience (a new one can take minutes to propagate): %w", clientID, ete)
	case ete.hasCode(7000215, 7000222) || ete.code == "invalid_client":
		return fmt.Errorf("azure: Entra ID refused the client secret of app %s (wrong or expired): %w", clientID, ete)
	default:
		return fmt.Errorf("azure: on-behalf-of token request refused: %w", ete)
	}
}
