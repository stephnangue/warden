package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// statePurpose is what the mount seals a pending login for. Core binds it to
// this mount (logical.Sealer), so a state sealed by another mount, or for
// anything else, never opens here.
const statePurpose = "oidc-login-state/v1"

// stateTTL bounds a login from auth_url to callback.
const stateTTL = 10 * time.Minute

// maxStateLen bounds a presented state before it is decoded. A sealed pending
// login is a few hundred characters.
const maxStateLen = 2048

var errStateInvalid = errors.New("the login state is invalid or has expired; start the login again")

// pendingLogin is everything a login needs between auth_url and callback. It
// travels sealed in the OAuth state parameter, through the browser and the
// identity provider, so the mount keeps no server-side state. Only the hash
// of the CLI's secret rides in it (Binding); the secret itself never leaves
// the CLI until callback.
type pendingLogin struct {
	V           int    `json:"v"`
	Verifier    string `json:"verifier"`
	Nonce       string `json:"nonce"`
	RedirectURI string `json:"redirect_uri"`
	Binding     string `json:"login_binding"`
	NamespaceID string `json:"ns"`
	ExpiresAt   int64  `json:"exp"`
}

// sealState returns p sealed for this mount, base64url-encoded.
func (b *oidcAuthBackend) sealState(ctx context.Context, p *pendingLogin) (string, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sealed, err := b.sealer.Seal(ctx, statePurpose, plain)
	if err != nil {
		return "", fmt.Errorf("sealing the login state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// openState returns the pending login state carries, refusing one that does
// not open on this mount, is malformed, or has expired at now. Every refusal
// is errStateInvalid.
func (b *oidcAuthBackend) openState(ctx context.Context, state string, now time.Time) (*pendingLogin, error) {
	if state == "" || len(state) > maxStateLen {
		return nil, errStateInvalid
	}
	sealed, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return nil, errStateInvalid
	}
	plain, err := b.sealer.Open(ctx, statePurpose, sealed)
	if err != nil {
		return nil, errStateInvalid
	}
	var p pendingLogin
	if err := json.Unmarshal(plain, &p); err != nil || p.V != 1 || p.Verifier == "" || p.Nonce == "" ||
		p.RedirectURI == "" || p.Binding == "" || p.NamespaceID == "" {
		return nil, errStateInvalid
	}
	if !now.Before(time.Unix(p.ExpiresAt, 0)) {
		return nil, errStateInvalid
	}
	return &p, nil
}

// bindingSecretLen is the length of the CLI's login secret.
const bindingSecretLen = 32

var (
	errBindingInvalid = errors.New("login_binding must be the base64url SHA-256 of a 32-byte secret")
	errProofMismatch  = errors.New("login_proof does not match the login this state started")
)

// checkBinding reports whether binding has the shape of the hash the CLI
// sends at auth_url: base64url (no padding) of 32 bytes.
func checkBinding(binding string) error {
	raw, err := base64.RawURLEncoding.DecodeString(binding)
	if err != nil || len(raw) != sha256.Size {
		return errBindingInvalid
	}
	return nil
}

// proofMatches reports whether proof, the secret the CLI presents at
// callback, is the one whose hash binding is, comparing in constant time. It
// binds the callback to the process that started the login: whoever captures
// the code and state off the loopback redirect still lacks the secret.
func proofMatches(binding, proof string) bool {
	want, err := base64.RawURLEncoding.DecodeString(binding)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	secret, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil || len(secret) != bindingSecretLen {
		return false
	}
	got := sha256.Sum256(secret)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
