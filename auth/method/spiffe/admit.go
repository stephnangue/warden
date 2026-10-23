package spiffe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/stephnangue/warden/auth/helper"
	spiffelib "github.com/stephnangue/warden/auth/spiffe"
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

var (
	// errNoBundles: with no trust bundle loaded the mount cannot decide.
	errNoBundles = helper.AdmitError(helper.ErrAdmitNoTrustBundle, "no SPIFFE trust bundles loaded")
	// errNoMountAudiences: with no bound_audiences the mount cannot decide on
	// any JWT-SVID.
	errNoMountAudiences = helper.AdmitError(helper.ErrAdmitNoAudiences, "bound_audiences is not set: no JWT-SVID can be admitted")
)

// admitX509SVID verifies cert as an X.509-SVID against the trust bundles in
// set alone, with no role: go-spiffe's SVID rules and a chain to the X.509
// authorities of the SVID's own trust domain. An X.509-SVID carries no
// audience and no issue time, so neither bound_audiences nor max_age applies:
// it is admitted with or without a config, and on an agent mount whose stored
// config has no bound_audiences.
// It returns what it verified as an admission of this mount, or why it is not
// admitted: errNoBundles when the mount cannot decide, any other error when the
// SVID failed a check.
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
// mount, or why it is not admitted: errNoBundles, errNoMountAudiences or
// helper.ErrAgentAudiencesRequired when the mount cannot decide, any other
// error when the SVID failed a check.
//
// admitJWTSVID and admitX509SVID are the mount's admission checks: login and
// introspect/admit both call them, so they cannot drift.
func (b *spiffeAuthBackend) admitJWTSVID(set *spiffebundle.Set, config *SPIFFEAuthConfig, token string, now time.Time) (*admittedSVID, error) {
	if set == nil || set.Len() == 0 {
		return nil, errNoBundles
	}
	if config == nil || len(config.BoundAudiences) == 0 {
		// A stored agent config without bound_audiences (written before
		// audience binding was required) says so; anything else simply has
		// no audience to verify against.
		if config != nil {
			if err := helper.RequireAgentAudiences(config.EntityKind, nil); err != nil {
				return nil, err
			}
		}
		return nil, errNoMountAudiences
	}
	svid, err := spiffelib.VerifyJWTSVIDToken(set, token, config.BoundAudiences)
	if err != nil {
		return nil, fmt.Errorf("JWT-SVID verification: %w", err)
	}
	adm := newAdmission(svid.ID, svidJWT, svid.Audience, helper.IssuedAt(svid.Claims), b.mountFacts)
	adm.AudienceBound = true
	if err := config.CheckSVIDMaxAge(adm, now); err != nil {
		return nil, fmt.Errorf("max_age: %w", err)
	}
	return &admittedSVID{adm: adm, id: svid.ID, expiry: svid.Expiry, claims: svid.Claims}, nil
}

var _ logical.AudienceBinder = (*spiffeAuthBackend)(nil)

// BindsAudience implements logical.AudienceBinder: the only bearer credential
// the mount admits is a JWT-SVID, and admitJWTSVID admits none without
// bound_audiences.
func (b *spiffeAuthBackend) BindsAudience() bool { return true }

// admit is the mount's helper.AdmitFunc. It picks the SVID as the gateway
// does (spiffelib.IsJWTSVID): a bearer JWT-SVID first, else the forwarded
// X.509-SVID. A mount with no trust bundle, or asked about a JWT-SVID without
// bound_audiences, cannot decide, which is an error; an SVID that fails a check
// is not admitted. Safe for concurrent use: it takes the config under configMu
// and the bundle set as a snapshot, and releases both before verifying.
func (b *spiffeAuthBackend) admit(_ context.Context, req *logical.Request, now time.Time) (*logical.Admission, error) {
	token := extractJWTFromRequest(req)
	cert := extractClientCert(req)
	useJWT := token != "" && spiffelib.IsJWTSVID(token)
	if !useJWT && cert == nil {
		return nil, nil
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
	if errors.Is(err, errNoBundles) || errors.Is(err, errNoMountAudiences) || errors.Is(err, helper.ErrAgentAudiencesRequired) {
		return nil, err
	}
	if err != nil {
		b.logger.Debug("introspect/admit: SVID not admitted", lgr.Err(err))
		return nil, nil
	}
	return got.adm, nil
}
