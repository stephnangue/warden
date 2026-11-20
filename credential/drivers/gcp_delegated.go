package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/types"
	"github.com/stephnangue/warden/logger"
)

// Google Workspace domain-wide delegation, keyless.
//
// A service account authorized for domain-wide delegation may act as any user of
// the Workspace domain: it signs a JWT naming the user (sub) and trades it at
// Google's token endpoint for a token acting as that user (RFC 7523). Google
// cannot restrict which users; the spec's domain list and policy are what does.
//
// The account's key never exists outside Google. Warden federates into GCP with
// its own assertion and has the IAM Credentials API sign the JWT with the key
// Google holds, as Google's guidance for domain-wide delegation asks.
//
// The user is the verified user on the request, projected from the user auth
// mount's facts: never a literal, never the agent, never anything the request
// says. Because the federated identity is the user (a gcp source discloses the
// user in the assertion's subject), each user's tokens are minted and cached
// apart.

const (
	// gcpDelegationAudience is the aud a delegation assertion names. It stays this
	// value whatever endpoint the trade is sent to: it is what Google checks.
	gcpDelegationAudience = "https://oauth2.googleapis.com/token"

	// defaultGCPOAuthTokenURL is where the signed assertion is traded.
	defaultGCPOAuthTokenURL = gcpDelegationAudience

	// gcpDelegationAssertionTTL is how long a signed delegation assertion is
	// good for. The signed JWT is itself a bearer for a user's token, so it lives
	// only as long as one trade takes; Google allows at most an hour.
	gcpDelegationAssertionTTL = 5 * time.Minute

	// gcpDelegationIATSkew backdates iat so a Google clock slightly behind
	// Warden's does not read the assertion as issued in the future.
	gcpDelegationIATSkew = 10 * time.Second

	// A delegated token lives one hour (Google fixes it). The fallback covers an
	// answer without expires_in, and is short so a guess only re-mints early.
	gcpDelegatedTokenFallback = 5 * time.Minute
	gcpDelegatedTokenMax      = time.Hour

	// gcpMaxDelegatedUserLen is the longest address a sub may carry (RFC 5321).
	gcpMaxDelegatedUserLen = 254
)

// gcpDelegatedUserPattern is an address Workspace can name: a username of the
// characters Workspace allows (letters, digits, dot, dash, underscore,
// apostrophe), one @, and a domain of two or more labels. It is matched against
// the raw claim before any case folding, so only ASCII ever reaches the fold:
// a non-ASCII rune that lowercases to an ASCII one (U+212A KELVIN SIGN becomes
// "k") cannot turn into a listed domain.
var gcpDelegatedUserPattern = regexp.MustCompile(`^[A-Za-z0-9._'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)

// GCPDelegatedAccess reports whether a spec mints domain-wide delegation tokens:
// typed as one, or naming the mint method. Both are read so a spec whose type and
// method disagree still meets the delegation rules; its type validation (or the
// mint, which refuses the mismatch) then turns it away. Pure: reads spec config
// only.
func GCPDelegatedAccess(specType string, specCfg credential.Config) bool {
	return specType == credential.TypeGCPDelegatedToken ||
		credential.GetString(specCfg, "mint_method", "") == types.GCPMintMethodDelegated
}

// GCPDelegatedAccessSpecError checks a domain-wide delegation spec against its
// source. It is applied when the spec is written and again when the source
// changes, since a source switched to static would strand the spec. Pure: reads
// the two configs only.
func GCPDelegatedAccessSpecError(specCfg, sourceCfg credential.Config) error {
	if credential.GetString(sourceCfg, "auth_method", gcpAuthMethodStatic) != gcpAuthMethodOIDCFederation {
		return fmt.Errorf("mint_method=%s has Google sign with the delegating account's own key and holds none: the source must use auth_method=%s",
			types.GCPMintMethodDelegated, gcpAuthMethodOIDCFederation)
	}
	if !credential.MintsWardenAssertion(specCfg.Get(credential.ConfigSubjectTokenSource)) {
		return fmt.Errorf("mint_method=%s acts as the verified user projected into Warden's assertion: set %s=%s or %s",
			types.GCPMintMethodDelegated, credential.ConfigSubjectTokenSource, credential.SourceWardenIdentity, credential.SourceWardenEntity)
	}
	if actor := specCfg.Get(credential.ConfigActorTokenSource); actor != "" && actor != credential.SourceNone {
		return fmt.Errorf("'%s' does not apply to mint_method=%s", credential.ConfigActorTokenSource, types.GCPMintMethodDelegated)
	}
	claim := specCfg.Get(types.DelegatedUserClaimKey)
	listed := false
	for _, k := range credential.AssertionUserClaimKeys(specCfg) {
		if k == claim {
			listed = true
			break
		}
	}
	if !listed {
		return fmt.Errorf("'%s' names %q, which must also be listed in %s so the verified user's value reaches the mint",
			types.DelegatedUserClaimKey, claim, credential.ConfigAssertionUserClaims)
	}
	// The pool lets only an assertion carrying the derived gcp-dwd: resource sign
	// as the delegating account. A spec naming its own resource, or a profile that
	// drops the claim, would either be refused there or need the pool opened wider.
	if specCfg.Get(credential.ConfigAssertionResource) != "" {
		return fmt.Errorf("'%s' does not apply to mint_method=%s: the resource is derived, and the workload identity pool binds the signing grant to it",
			credential.ConfigAssertionResource, types.GCPMintMethodDelegated)
	}
	if p := credential.AssertionProfileName(specCfg); p != credential.DefaultAssertionProfileName {
		return fmt.Errorf("'%s' must be %q for mint_method=%s: the signing grant binds the warden_resource claim only that profile carries with the user",
			credential.ConfigAssertionProfile, credential.DefaultAssertionProfileName, types.GCPMintMethodDelegated)
	}
	return nil
}

// resolveDelegatedSubject returns the address the delegation assertion names as
// sub: the verified user's claim, if it is an address in one of the listed
// domains. A refusal wraps credential.ErrUserNotAllowed and never repeats the
// value.
func resolveDelegatedSubject(userClaims map[string]string, claim string, domains []string) (string, error) {
	raw, ok := userClaims[claim]
	if !ok {
		// The spec lists the claim in assertion_user_claims, and projection fails
		// closed on an absent fact before the mint, so this is a spec the store
		// should not have accepted rather than a user to refuse.
		return "", fmt.Errorf("gcp: '%s' names %q, which is not among the user's projected claims; list it in %s",
			types.DelegatedUserClaimKey, claim, credential.ConfigAssertionUserClaims)
	}
	if len(raw) > gcpMaxDelegatedUserLen || !gcpDelegatedUserPattern.MatchString(raw) {
		return "", fmt.Errorf("gcp: the user's %q claim is not an address a Workspace user can have: %w", claim, credential.ErrUserNotAllowed)
	}
	// ASCII only, by the match above, so this fold cannot change what the
	// address names.
	user := strings.ToLower(raw)
	domain := user[strings.IndexByte(user, '@')+1:]
	for _, d := range domains {
		if d == domain {
			return user, nil
		}
	}
	return "", fmt.Errorf("gcp: the user's domain is not in %s: %w", types.DelegatedUserDomainsKey, credential.ErrUserNotAllowed)
}

// dwdSignError marks a failure to have Google sign the delegation assertion, so
// it is told apart from a refusal of the trade that follows.
type dwdSignError struct{ err error }

func (e *dwdSignError) Error() string { return e.err.Error() }
func (e *dwdSignError) Unwrap() error { return e.err }

// callerError is what the caller is told about a failure whose cause names the
// operator's configuration — a URL or an answer quoting the service account. The
// message is fixed; the cause stays underneath so its status, a refusal or an
// outage, still decides how the request is answered.
type callerError struct {
	msg string
	err error
}

func (e *callerError) Error() string { return e.msg }
func (e *callerError) Unwrap() error { return e.err }

// gcpJWTSigner signs with a service account's Google-held key through the IAM
// Credentials signJwt API. Google writes the header, its kid naming the key it
// used. Stateless past construction, so safe for concurrent use.
type gcpJWTSigner struct {
	d *GCPDriver
	// bearer authorizes the call: a token federated for the caller, granted
	// iam.serviceAccounts.signJwt on account.
	bearer  string
	account string
}

var _ assertionSigner = gcpJWTSigner{}

// SignJWT has Google sign claims as the service account. Every failure is a
// *dwdSignError.
func (s gcpJWTSigner) SignJWT(ctx context.Context, claims map[string]interface{}) (string, error) {
	signed, err := s.sign(ctx, claims)
	if err != nil {
		return "", &dwdSignError{err: err}
	}
	return signed, nil
}

func (s gcpJWTSigner) sign(ctx context.Context, claims map[string]interface{}) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to encode the assertion claims: %w", err)
	}
	body, err := json.Marshal(map[string]string{"payload": string(payload)})
	if err != nil {
		return "", fmt.Errorf("failed to encode the signJwt request: %w", err)
	}
	respBody, err := s.d.doGCPRequest(ctx, gcpAPIRequest{
		method:      http.MethodPost,
		url:         fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:signJwt", s.d.iamCredentialsHost, url.PathEscape(s.account)),
		body:        body,
		contentType: "application/json",
		bearerToken: s.bearer,
		okStatuses:  []int{http.StatusOK},
		operation:   "signJwt",
	})
	if err != nil {
		return "", err
	}
	var resp struct {
		KeyID     string `json:"keyId"`
		SignedJWT string `json:"signedJwt"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("failed to decode the signJwt response: %w", err)
	}
	if resp.SignedJWT == "" {
		return "", errors.New("signJwt response missing signedJwt")
	}
	return resp.SignedJWT, nil
}

// mintDelegatedAccessToken mints a token acting as the verified user: the user is
// checked against the spec first, so a refused user costs no call to Google; then
// Warden's assertion is federated, Google signs the delegation assertion as the
// spec's account, and the assertion is traded for the user's token.
func (d *GCPDriver) mintDelegatedAccessToken(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A token acting as a user is issued only as the type the gcp and mcp providers
	// refuse. A spec typed otherwise would hand it to them.
	if spec.Type != credential.TypeGCPDelegatedToken {
		return nil, nil, 0, "", fmt.Errorf("gcp: mint_method=%s issues a %s, but the spec's type is %q",
			types.GCPMintMethodDelegated, credential.TypeGCPDelegatedToken, spec.Type)
	}
	account := credential.GetString(spec.Config, "target_service_account", "")
	if account == "" {
		return nil, nil, 0, "", fmt.Errorf("gcp: target_service_account is required for mint_method=%s", types.GCPMintMethodDelegated)
	}
	scopes := splitScopes(credential.GetString(spec.Config, "scopes", ""))
	if len(scopes) == 0 {
		return nil, nil, 0, "", fmt.Errorf("gcp: 'scopes' is required for mint_method=%s", types.GCPMintMethodDelegated)
	}
	domains, err := types.ParseDelegatedUserDomains(spec.Config.Get(types.DelegatedUserDomainsKey))
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("gcp: %w", err)
	}
	user, err := resolveDelegatedSubject(inputs.UserClaims, spec.Config.Get(types.DelegatedUserClaimKey), domains)
	if err != nil {
		return nil, nil, 0, "", err
	}

	fedToken, _, err := d.exchangeWIFToken(ctx, inputs.SubjectToken, inputs.SubjectTokenType, gcpFederationScope)
	if err != nil {
		return nil, nil, 0, "", err
	}

	scope := strings.Join(scopes, " ")
	claims := func() map[string]interface{} {
		now := time.Now()
		return map[string]interface{}{
			"iss":   account,
			"sub":   user,
			"scope": scope,
			"aud":   gcpDelegationAudience,
			"iat":   now.Add(-gcpDelegationIATSkew).Unix(),
			"exp":   now.Add(gcpDelegationAssertionTTL).Unix(),
		}
	}
	signer := gcpJWTSigner{d: d, bearer: fedToken, account: account}
	tok, err := postJWTBearerGrant(ctx, d.httpClient, d.oauthTokenURL, signer, claims)
	if err != nil {
		return nil, nil, 0, "", d.delegationError(spec, account, err)
	}

	ttl := LeaseFromExpiresIn(tok.ExpiresIn, LeaseOpts{
		Fallback: gcpDelegatedTokenFallback,
		Max:      gcpDelegatedTokenMax,
		Buffer:   gcpSTSTokenBuffer,
		MaxTTL:   spec.MaxTTL,
	})
	rawData := map[string]interface{}{"access_token": tok.AccessToken}
	metadata := map[string]interface{}{
		"delegated_user":  user,
		"service_account": account,
		"scopes":          scope,
		"provider":        d.getWorkloadIdentityProvider(),
	}
	// The assertion's subject (the user) and actor (the agent), as Google saw them.
	for k, v := range assertionSubjectMetadata(inputs.SubjectToken) {
		metadata[k] = v
	}
	if d.logger != nil {
		d.logger.Debug("minted delegated Google Workspace access token",
			logger.String("spec", spec.Name),
			logger.String("ttl", ttl.String()),
		)
	}
	return rawData, metadata, ttl, "", nil
}

// delegationError words a failed signature or trade. What to fix — the account,
// the Admin console, the pool — goes to the log for the operator; the error the
// caller sees names no account or principal set. A user Google does not know is
// the caller's to hear about and wraps credential.ErrUserNotAllowed. Every other
// failure keeps its cause underneath, so a refusal is answered as a 403 and an
// outage as a 503.
func (d *GCPDriver) delegationError(spec *credential.CredSpec, account string, err error) error {
	var signErr *dwdSignError
	if errors.As(err, &signErr) {
		// Nothing was traded. The cause quotes the signJwt URL, and Google's answer
		// may quote the account, so the caller gets a fixed message.
		d.logDelegation(spec, account, err, false,
			"Google would not sign as the account: grant the workload identity pool's principal set for warden_resource "+
				credential.GCPDelegationResourcePrefix+account+", on a pool provider whose attribute condition also pins "+
				"warden_namespace, a role holding iam.serviceAccounts.signJwt on the account")
		return &callerError{msg: "gcp: Google would not sign the domain-wide delegation assertion", err: err}
	}
	var tee *tokenEndpointError
	if errors.As(err, &tee) && tee.code != "" {
		fix, userFault := dwdRefusalFix(tee)
		d.logDelegation(spec, account, err, userFault, fix)
		if userFault {
			return fmt.Errorf("gcp: Google Workspace has no such user: %w: %w", credential.ErrUserNotAllowed, err)
		}
		return fmt.Errorf("gcp: Google refused domain-wide delegation for this credential spec: %w", err)
	}
	// No OAuth answer at all: an outage, a dropped connection, or a reply that is
	// not a token response.
	d.logDelegation(spec, account, err, false, "Google's token endpoint gave no usable answer")
	return fmt.Errorf("gcp: Google's token endpoint gave no usable answer: %w", err)
}

// dwdRefusalFix says what a token-endpoint refusal of a delegation assertion
// means, and whether it is the user's rather than the configuration's.
func dwdRefusalFix(tee *tokenEndpointError) (fix string, userFault bool) {
	desc := strings.ToLower(tee.description)
	switch tee.code {
	case "unauthorized_client":
		return "domain-wide delegation is not authorized for the account's numeric client ID in the Workspace Admin console " +
			"(or it was authorized by email or through a group), or none of the requested scopes is", false
	case "access_denied":
		return "a requested scope is not authorized for the account in the Workspace Admin console", false
	case "invalid_scope":
		return "'scopes' names a scope Google does not know; scopes are URLs", false
	case "admin_policy_enforced", "org_internal":
		return "a Workspace admin policy blocks the account's client", false
	case "invalid_client", "deleted_client", "disabled_client":
		return "the account, or its OAuth client, is missing or disabled", false
	case "invalid_grant":
		switch {
		case strings.Contains(desc, "invalid email") || strings.Contains(desc, "not a valid email"):
			return "the verified user has no account in the Workspace domain", true
		case strings.Contains(desc, "short-lived") || strings.Contains(desc, "reasonable timeframe"):
			return "Google refused the assertion's time window: check the Warden host's clock", false
		case strings.Contains(desc, "signature"):
			return "Google could not verify the signature signJwt produced", false
		}
	}
	return "Google refused the delegation assertion", false
}

// logDelegation records a failed delegation for the operator. A user Google does
// not know is the caller's fault, and any caller can trigger it on every request,
// so it is logged at debug; everything else needs the operator and is a warning.
func (d *GCPDriver) logDelegation(spec *credential.CredSpec, account string, err error, userFault bool, fix string) {
	if d.logger == nil {
		return
	}
	fields := []logger.TypedField{
		logger.String("spec", spec.Name),
		logger.String("service_account", account),
		logger.String("fix", fix),
		logger.Err(err),
	}
	if userFault {
		d.logger.Debug("domain-wide delegation refused the user", fields...)
		return
	}
	d.logger.Warn("domain-wide delegation failed", fields...)
}
