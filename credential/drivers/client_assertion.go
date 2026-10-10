package drivers

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/remotesign"
)

// Client authentication to an OAuth 2.0 token endpoint, shared by every driver that
// authenticates as a client: the methods, the RFC 7523 client assertion and how it is
// signed, and how a client credential fetched through credential chaining is read.
// Keeping one copy means two drivers configured alike put the same bytes on the wire.
//
// Every error returned here is unprefixed; each driver names itself when it wraps one.

// Client-authentication methods selected by a source's `client_auth` config.
//
// kms_private_key_jwt puts the same assertion on the wire as private_key_jwt — the
// authorization server cannot tell them apart — but the key is held in a KMS and Warden
// never sees it. It is a separate method rather than a modifier because the two are
// configured from opposite ends: one takes a key, the other takes a reference to a
// capability, and nothing an operator sets for one is meaningful for the other.
//
// none makes Warden a public client (RFC 6749 §2.1): it presents no client credential,
// only its client_id when one is set (§2.3), and the token endpoint identifies the
// caller by the subject token alone. With a warden_identity subject that token is
// Warden's own signed assertion, so the source stores no secret at all.
const (
	clientAuthSecretBasic      = "client_secret_basic"
	clientAuthSecretPost       = "client_secret_post"
	clientAuthPrivateKeyJWT    = "private_key_jwt"
	clientAuthKMSPrivateKeyJWT = "kms_private_key_jwt"
	clientAuthNone             = "none"
)

// clientAssertionType is the RFC 7523 client-assertion type for private_key_jwt.
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientAssertionTTL bounds the lifetime of a signed client assertion.
const clientAssertionTTL = 5 * time.Minute

// kmsCapabilitySkew is how far ahead of a capability's expiry it is treated as already
// spent. Building and sending an assertion is not instantaneous, and a capability that
// expires mid-flight fails at the token endpoint as an opaque client-auth error rather
// than as the expiry it is.
const kmsCapabilitySkew = 10 * time.Second

// chainedClientAuth carries the client credential a single mint fetched through
// credential chaining. A nil pointer means the inline source config.
//
// secret is whichever half client_auth calls for: the client secret for
// client_secret_post/basic, or the PEM private key for private_key_jwt. kid is the
// optional key id naming that private key, and is empty for the secret methods. It
// holds fetched values only — never the mode — and is threaded by parameter rather than
// stored on a driver, so concurrent mints resolving different pairs cannot cross.
type chainedClientAuth struct {
	clientID string
	secret   string
	kid      string
	// kms is set instead of secret when the referenced spec minted a signing
	// capability rather than a key. The two are mutually exclusive: one carries the
	// key, the other carries permission to use a key it will never see.
	kms *remotesign.Capability
}

// chainedClientAuthFromMaterial reads a whole client credential out of fetched secret
// material. clientAuth decides which half the secret is — a client secret or a PEM
// private key — and so which conventional key names apply.
//
// secret_field names the secret alone, so a field that resolved to nothing is a
// misconfigured source rather than an invitation to look elsewhere: the conventional
// keys are consulted only when no field was resolved at all. The id is read by
// convention for the same reason, and has nowhere to fall back to — a source in
// chaining mode holds no client_id — so its absence is an error raised here, before any
// request is sent.
//
// Every "the payload lacks what I need" error carries ErrChainedSecretIncomplete, so a
// cached payload that predates a key it now has to hold is refetched once rather than
// failing for the rest of its secret_cache_ttl.
func chainedClientAuthFromMaterial(clientAuth string, material credential.SecretMaterial) (*chainedClientAuth, error) {
	// The id is never the secret. A payload holding nothing but an id resolves that
	// lone key as the secret field — the single-key shortcut has no way to know
	// better — and without this the same value would be spent as both halves of the
	// pair, which the endpoint answers with invalid_client and the chained path then
	// misreads as a rotated secret.
	if material.Field == "client_id" {
		return nil, fmt.Errorf("the fetched secret material holds a client id but no secret: %w", credential.ErrChainedSecretIncomplete)
	}

	secret := material.Secret()
	var kid string
	var kms *remotesign.Capability

	switch clientAuth {
	case clientAuthKMSPrivateKeyJWT:
		// Nothing secret is selected here: the payload is a set of coordinates read by
		// name, so material.Field plays no part. Clear whatever the generic selector
		// picked out — leaving a coordinate sitting in the secret slot would present it
		// as key material to anything that later reads the struct.
		secret = ""
		var err error
		if kms, err = remotesign.DecodeCapability(material.Data); err != nil {
			return nil, capabilityError(err)
		}
	case clientAuthSecretPost, clientAuthSecretBasic, "":
		if secret == "" && material.Field == "" {
			secret = material.Data["client_secret"]
		}
		if secret == "" {
			if material.Field != "" {
				return nil, fmt.Errorf("secret_field %q is empty or absent in the fetched secret material: %w", material.Field, credential.ErrChainedSecretIncomplete)
			}
			return nil, fmt.Errorf("no client secret in fetched secret material (set secret_field, or store it under 'client_secret'): %w", credential.ErrChainedSecretIncomplete)
		}
	case clientAuthPrivateKeyJWT:
		if secret == "" && material.Field == "" {
			secret = material.Data["private_key"]
		}
		if secret == "" {
			if material.Field != "" {
				return nil, fmt.Errorf("secret_field %q is empty or absent in the fetched secret material: %w", material.Field, credential.ErrChainedSecretIncomplete)
			}
			return nil, fmt.Errorf("no private key in fetched secret material (set secret_field, or store it under 'private_key'): %w", credential.ErrChainedSecretIncomplete)
		}
		// Optional, and read by convention like the id: an authorization server that
		// resolves the key from the client id alone needs none. When it is present it
		// has to be the one stored beside this key, which is why a chained source is
		// refused an inline client_assertion_kid rather than falling back to it.
		kid = material.Data["client_assertion_kid"]
		if kid == "" {
			kid = material.Data["kid"]
		}
	default:
		// A source-config error, not a payload one: refetching cannot change the answer,
		// so this must not carry the sentinel that asks the manager to try again.
		return nil, fmt.Errorf("credential chaining supports client_auth=%s, %s, %s or %s, got %q",
			clientAuthSecretPost, clientAuthSecretBasic, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT, clientAuth)
	}

	clientID := material.Data["client_id"]
	if clientID == "" {
		return nil, fmt.Errorf("no client id in fetched secret material (store it under 'client_id' alongside the secret): %w", credential.ErrChainedSecretIncomplete)
	}

	return &chainedClientAuth{clientID: clientID, secret: secret, kid: kid, kms: kms}, nil
}

// basicClientAuthHeader is the client_secret_basic Authorization header: per RFC 6749
// §2.3.1 the id and secret are form-urlencoded first, then Basic-encoded.
func basicClientAuthHeader(clientID, clientSecret string) string {
	creds := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

// clientAssertionClaims builds the claims of an RFC 7523 client assertion: a
// short-lived JWT with iss=sub=client_id, naming aud as the one server it is for, with
// a fresh jti so no two assertions are alike.
func clientAssertionClaims(clientID, aud string) (map[string]interface{}, error) {
	jti, err := newJTI()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return map[string]interface{}{
		"iss": clientID,
		"sub": clientID,
		"aud": aud,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(clientAssertionTTL).Unix(),
	}, nil
}

// signClientAssertionLocal signs client-assertion claims with an RSA key held in this
// process, stamping kid in the header when there is one.
func signClientAssertionLocal(key *rsa.PrivateKey, kid string, claims map[string]interface{}) (string, error) {
	assertion, err := signRS256JWT(key, kidHeader(kid), claims)
	if err != nil {
		return "", fmt.Errorf("failed to sign client assertion: %w", err)
	}
	return assertion, nil
}

// signClientAssertionWithCapability signs client-assertion claims with a key the
// capability names but Warden cannot read.
//
// Errors are mapped deliberately. Anything meaning "this capability is spent" carries
// ErrChainedSecretRejected, so the minting layer discards the cached one and mints a
// fresh capability — the same self-healing a rotated secret gets. Anything meaning "the
// KMS is unreachable" carries no sentinel at all: a refetch cannot mend a network, and
// evicting a perfectly good capability would turn a blip into a stampede.
func signClientAssertionWithCapability(ctx context.Context, signers *remotesign.CapabilitySigners, c *remotesign.Capability, claims map[string]interface{}) (string, error) {
	// Cheaper than discovering the same thing from a refused signature, and it keeps a
	// spent capability distinguishable from a broken one.
	if !c.ExpiresAt.IsZero() && time.Now().Add(kmsCapabilitySkew).After(c.ExpiresAt) {
		return "", fmt.Errorf("the fetched signing capability expired at %s: %w",
			c.ExpiresAt.Format(time.RFC3339), credential.ErrChainedSecretRejected)
	}

	assertion, err := signers.SignJWS(ctx, c, kidHeader(c.Kid), claims)
	if err != nil {
		return "", capabilityError(err)
	}
	return assertion, nil
}

// kidHeader is the JWS header carrying kid, or an empty one when there is no kid.
func kidHeader(kid string) map[string]string {
	header := map[string]string{}
	if kid != "" {
		header["kid"] = kid
	}
	return header
}

// capabilityError adds the chaining sentinel a capability failure calls for, keeping
// the original in the chain so the store's status stays readable. A backend this build
// cannot drive gets no sentinel: refetching yields the same backend.
func capabilityError(err error) error {
	switch {
	case errors.Is(err, remotesign.ErrCapabilityIncomplete):
		return fmt.Errorf("%w: %w", err, credential.ErrChainedSecretIncomplete)
	case errors.Is(err, remotesign.ErrCapabilityRejected):
		return fmt.Errorf("%w: %w", err, credential.ErrChainedSecretRejected)
	}
	return err
}
