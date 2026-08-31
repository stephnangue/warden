package remotesign

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// SignCompactJWS signs header and claims as a compact JWS with the given JWS alg.
//
// It is written against crypto.Signer alone, so the same call serves a private key
// held in this process and one held in a KMS: the caller picks which by choosing the
// signer. That is the point of the helper — a caller that supports both should not
// have two signing paths that can drift apart in header handling or encoding.
//
// The alg header is always set from alg (never taken from the caller's map), so the
// header cannot disagree with the key and hash actually used.
func SignCompactJWS(ctx context.Context, signer crypto.Signer, alg string, header map[string]string, claims map[string]interface{}) (string, error) {
	if signer == nil {
		return "", errors.New("remotesign: no signer")
	}
	p, ok := algParamsByAlg[alg]
	if !ok {
		return "", fmt.Errorf("remotesign: unsupported signing algorithm %q", alg)
	}

	// Copy rather than mutate: the caller's map may be reused across signatures, and
	// silently writing alg/typ into it would make this call order-dependent.
	hdr := make(map[string]string, len(header)+2)
	for k, v := range header {
		hdr[k] = v
	}
	hdr["alg"] = alg
	if hdr["typ"] == "" {
		hdr["typ"] = "JWT"
	}

	headerJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("remotesign: marshal JWS header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("remotesign: marshal JWS claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := p.hash.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	// Bind the request context when the signer supports it. For a remote signer Sign
	// is a network call, so without this it would run unbounded regardless of the
	// caller's deadline; a local key has no such method and is unaffected.
	if b, ok := signer.(interface {
		WithContext(context.Context) crypto.Signer
	}); ok && ctx != nil {
		signer = b.WithContext(ctx)
	}

	// crypto.Signer.Sign takes the already-hashed digest and returns, for RSA, PKCS#1
	// v1.5 bytes (opts is a plain crypto.Hash, not *rsa.PSSOptions) and, for ECDSA, an
	// ASN.1 SEQUENCE{r,s}.
	sig, err := signer.Sign(rand.Reader, digest, p.hash)
	if err != nil {
		return "", fmt.Errorf("remotesign: sign: %w", err)
	}
	if p.curve != nil {
		sig, err = ecSigASN1ToJWS(sig, p.curve)
		if err != nil {
			return "", err
		}
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ecSigASN1ToJWS converts the ASN.1 SEQUENCE{r,s} that crypto.Signer produces for
// ECDSA into the fixed-width R‖S concatenation JWS requires. The two encodings are
// not interchangeable: a DER signature placed on the wire as-is is well-formed bytes
// that no verifier accepts.
func ecSigASN1ToJWS(der []byte, curve elliptic.Curve) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		return nil, fmt.Errorf("remotesign: parse ECDSA signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("remotesign: trailing bytes after ECDSA signature")
	}
	if parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, errors.New("remotesign: invalid ECDSA signature scalars")
	}
	n := (curve.Params().BitSize + 7) / 8
	return append(ecCoord(parsed.R, n), ecCoord(parsed.S, n)...), nil
}

// ecCoord renders an ECDSA signature scalar as a fixed byteLen-wide big-endian slice —
// the width JWS requires, left-padded with zeros.
func ecCoord(n *big.Int, byteLen int) []byte {
	b := make([]byte, byteLen)
	n.FillBytes(b)
	return b
}
