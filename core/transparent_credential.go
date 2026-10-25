// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/logical"
)

// transparentCredential is the credential a transparent auth mount admits from
// a request, in the form its identity token is keyed by.
type transparentCredential struct {
	// kind tells credentials of one value but different extraction apart in
	// the login singleflight key: "cert", "jwt", "spiffe-jwt", "spiffe-cert".
	kind string
	// key is the credential's identity-token lookup value: the raw JWT, or
	// the hex SHA-256 fingerprint of the client certificate.
	key string
	// cert reports that the credential is a certificate, not a bearer.
	cert bool
}

// transparentCredentialOf returns the credential a mount of the given format
// (an auth method of mountType at mountPath) admits from req: the explicit
// credential when one is given (the secondary, user path: bearer formats
// only, used verbatim), else req.ClientToken or the presented client
// certificate.
//
// Cases group by what the credential looks like on the wire (cert vs JWT
// bearer): a generic JWT and a Kubernetes service account JWT both arrive as
// JWTs in the Authorization header and share the same parse path. The
// identity token is keyed per mount, so formats sharing an extraction case
// never share an entry.
//
// It is the one place the key is derived: implicit auth logs in with it, and
// discovery names a role-less caller's identity with it, so both give one
// credential the same identity token ID.
func transparentCredentialOf(req *logical.Request, credential string, format logical.CredentialFormat, mountType, mountPath string) (transparentCredential, error) {
	explicitCred := credential != ""
	bearer := credential
	if bearer == "" {
		bearer = req.ClientToken
	}

	switch format {
	case logical.CredentialFormatCert:
		if explicitCred {
			return transparentCredential{}, fmt.Errorf("auth method %q at %q requires a bearer credential, not a TLS client certificate", mountType, mountPath)
		}
		clientCert := extractTransparentClientCert(req)
		if clientCert == nil {
			return transparentCredential{}, fmt.Errorf("auth method %q at %q requires a TLS client certificate", mountType, mountPath)
		}
		return transparentCredential{kind: "cert", key: certFingerprintHex(clientCert.Raw), cert: true}, nil

	case logical.CredentialFormatJWT, logical.CredentialFormatKubernetesJWT:
		if !strings.HasPrefix(bearer, "eyJ") {
			return transparentCredential{}, fmt.Errorf("auth method %q at %q requires a JWT bearer token", mountType, mountPath)
		}
		return transparentCredential{kind: "jwt", key: bearer}, nil

	case logical.CredentialFormatSPIFFE:
		// Unified SPIFFE mount: accept either a JWT-SVID (bearer) or an
		// X.509-SVID (TLS/forwarded cert). Prefer an explicitly-presented
		// JWT-SVID over an ambient mesh-forwarded cert — a sidecar makes a
		// forwarded cert present on most requests, so cert-first would shadow
		// the JWT path and mis-attribute a JWT-SVID workload to the cert
		// identity. A JWT-SVID is a bearer JWT whose (unverified) sub is a
		// spiffe:// ID; the mount re-verifies it against the trust-domain bundle.
		if spiffelib.IsJWTSVID(bearer) {
			return transparentCredential{kind: "spiffe-jwt", key: bearer}, nil
		}
		if explicitCred {
			// The secondary (user) path is bearer-only; an X.509-SVID can't ride a
			// header, so a non-SVID credential here is a misconfigured user mount.
			return transparentCredential{}, fmt.Errorf("auth method %q at %q requires a JWT-SVID bearer credential", mountType, mountPath)
		}
		if clientCert := extractTransparentClientCert(req); clientCert != nil {
			return transparentCredential{kind: "spiffe-cert", key: certFingerprintHex(clientCert.Raw), cert: true}, nil
		}
		return transparentCredential{}, fmt.Errorf("auth method %q at %q requires an X.509-SVID (TLS/forwarded cert) or a JWT-SVID bearer token", mountType, mountPath)

	default:
		return transparentCredential{}, fmt.Errorf("auth method %q has unsupported credential format %q for implicit auth", mountType, format)
	}
}

// certFingerprintHex is the hex SHA-256 of a certificate's DER bytes.
func certFingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
