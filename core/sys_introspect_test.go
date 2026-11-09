// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
)

// mintK8sJWT returns a well-formed (but unsigned) JWT with the given payload.
func mintK8sJWT(payloadJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	signature := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	return header + "." + payload + "." + signature
}

// Discovery needs a credential to present, and never looks at it: any bearer
// or a forwarded client certificate will do; the target mounts decide.
func TestHasDiscoveryCredential(t *testing.T) {
	withAuth := func(v string) *logical.Request {
		httpReq := httptest.NewRequest(http.MethodGet, "/x", nil)
		if v != "" {
			httpReq.Header.Set("Authorization", v)
		}
		return &logical.Request{HTTPRequest: httpReq}
	}
	assert.False(t, hasDiscoveryCredential(&logical.Request{}), "no HTTP request")
	assert.False(t, hasDiscoveryCredential(withAuth("")), "no Authorization")
	assert.False(t, hasDiscoveryCredential(withAuth("Basic dXNlcjpwYXNz")), "not a bearer")
	assert.False(t, hasDiscoveryCredential(withAuth("Bearer ")), "an empty bearer")
	assert.True(t, hasDiscoveryCredential(withAuth("Bearer opaque")), "any bearer, JWT-shaped or not")
	assert.True(t, hasDiscoveryCredential(withAuth("Bearer "+mintK8sJWT(`{"sub":"system:serviceaccount:default:app"}`))))

	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "c"}}
	req := withAuth("")
	req.HTTPRequest = req.HTTPRequest.WithContext(listener.WithForwardedClientCert(req.HTTPRequest.Context(), cert))
	assert.True(t, hasDiscoveryCredential(req), "a forwarded client certificate")
}
