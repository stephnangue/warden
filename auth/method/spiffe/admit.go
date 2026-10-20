package spiffe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/stephnangue/warden/auth/helper"
	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	jwtparse "github.com/stephnangue/warden/helper"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// admittedSVID is what a role-free admission verified about one SVID.
type admittedSVID struct {
	adm    *logical.Admission
	id     spiffeid.ID
	expiry time.Time      // the X.509-SVID's NotAfter, or the JWT-SVID's exp
	claims map[string]any // the JWT-SVID's claims; nil for an X.509-SVID
}

// errNoBundles refuses admission while no trust bundle is loaded.
var errNoBundles = errors.New("no SPIFFE trust bundles loaded")

// admitX509SVID verifies cert as an X.509-SVID against the trust bundles in
// set alone, with no role: go-spiffe's SVID rules and a chain to the X.509
// authorities of the SVID's own trust domain. An X.509-SVID carries no
// audience and no issue time, so neither bound_audiences nor max_age applies.
// It returns what it verified as an admission of this mount, or why it is not
// admitted.
func (b *spiffeAuthBackend) admitX509SVID(set *spiffebundle.Set, cert *x509.Certificate) (*admittedSVID, error) {
	if set == nil || set.Len() == 0 {
		return nil, errNoBundles
	}
	id, _, err := spiffelib.VerifyX509SVIDChain(set, []*x509.Certificate{cert})
	if err != nil {
		return nil, fmt.Errorf("X.509-SVID verification: %w", err)
	}
	return &admittedSVID{
		adm:    newAdmission(id, svidX509, nil, time.Time{}, b.mountFacts),
		id:     id,
		expiry: cert.NotAfter,
	}, nil
}

// admitJWTSVID verifies token as a JWT-SVID against the trust bundles in set
// and config alone, with no role: go-spiffe's SVID rules, a signature from the
// JWT authorities of the SVID's own trust domain, an audience among the
// mount's bound_audiences (a nil config, or one without bound_audiences,
// admits no JWT-SVID), and the mount's max_age against its iat at now
// (CheckSVIDMaxAge). It returns what it verified as an admission of this
// mount, or why it is not admitted.
func (b *spiffeAuthBackend) admitJWTSVID(set *spiffebundle.Set, config *SPIFFEAuthConfig, token string, now time.Time) (*admittedSVID, error) {
	if set == nil || set.Len() == 0 {
		return nil, errNoBundles
	}
	var audiences []string
	if config != nil {
		audiences = config.BoundAudiences
	}
	svid, err := spiffelib.VerifyJWTSVIDToken(set, token, audiences)
	if err != nil {
		return nil, fmt.Errorf("JWT-SVID verification: %w", err)
	}
	adm := newAdmission(svid.ID, svidJWT, svid.Audience, helper.IssuedAt(svid.Claims), b.mountFacts)
	if err := config.CheckSVIDMaxAge(adm, now); err != nil {
		return nil, fmt.Errorf("max_age: %w", err)
	}
	return &admittedSVID{adm: adm, id: svid.ID, expiry: svid.Expiry, claims: svid.Claims}, nil
}

// isJWTSVID reports whether token is a JWT whose unverified subject is a
// SPIFFE ID: the bearer the gateway treats as a JWT-SVID, in preference to a
// forwarded certificate. The signature is checked by admitJWTSVID.
func isJWTSVID(token string) bool {
	if !strings.HasPrefix(token, "eyJ") {
		return false
	}
	claims, err := jwtparse.ParseJWTClaimsUnverified(token)
	if err != nil {
		return false
	}
	sub, _ := claims["sub"].(string)
	return strings.HasPrefix(sub, "spiffe://")
}

// admit is the mount's helper.AdmitFunc. It picks the SVID as the gateway
// does: a bearer JWT-SVID first (a mesh sidecar forwards a certificate on most
// requests, which must not shadow it), else the forwarded X.509-SVID. Safe
// for concurrent use: it takes the config under configMu and the bundle set
// as a snapshot, and releases both before verifying.
func (b *spiffeAuthBackend) admit(_ context.Context, req *logical.Request, now time.Time) *logical.Admission {
	token := extractJWTFromRequest(req)
	cert := extractClientCert(req)
	useJWT := token != "" && isJWTSVID(token)
	if !useJWT && cert == nil {
		return nil
	}
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()
	set := b.spiffe.SnapshotBundleSet()

	var (
		got *admittedSVID
		err error
	)
	if useJWT {
		got, err = b.admitJWTSVID(set, config, token, now)
	} else {
		got, err = b.admitX509SVID(set, cert)
	}
	if err != nil {
		b.logger.Debug("introspect/admit: SVID not admitted", lgr.Err(err))
		return nil
	}
	return got.adm
}
