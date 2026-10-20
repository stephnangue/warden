package spiffe

import (
	"slices"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// Built-in fact names of a spiffe mount: the verified SPIFFE ID and its
// components, as today's metadata_mappings selectors name them, the kind of
// SVID that carried it, and a JWT-SVID's audiences. They are also the sources
// a mount's facts can rename.
const (
	factSPIFFEID    = "spiffe_id"
	factTrustDomain = "trust_domain"
	factPath        = "path"
	factSVID        = "svid"
	factAudiences   = "aud"
)

// The values of the "svid" fact.
const (
	svidX509 = "x509"
	svidJWT  = "jwt"
)

// spiffeBuiltinFacts returns the fact names every spiffe mount publishes under
// their own names. The slice is fresh on each call.
func spiffeBuiltinFacts() []string {
	return []string{
		factSPIFFEID,
		factTrustDomain,
		factPath,
		factSVID,
		factAudiences,
	}
}

// defaultNaming returns the naming of a mount with no config: the built-in
// facts, and the agent kind. It always compiles.
func defaultNaming() *logical.MountNaming {
	var fc helper.FactsConfig
	fc.CompileFields(spiffeBuiltinFacts())
	return fc.Naming()
}

var _ logical.FactsProvider = (*spiffeAuthBackend)(nil)

// FactNames implements logical.FactsProvider (see helper.FactNames).
func (b *spiffeAuthBackend) FactNames() []string { return helper.FactNames(b.mountFacts) }

// newAdmission returns what a successful login verified: id is the SVID's
// verified SPIFFE ID, svid the kind that carried it (svidX509 or svidJWT),
// audiences a JWT-SVID's 'aud' (nil for an X.509-SVID, which has none) and
// issuedAt a JWT-SVID's 'iat' (zero for an X.509-SVID, whose validity window
// is not an issue time).
//
// "spiffe_id" is the ID's URI string, "trust_domain" its trust domain name and
// "path" its path, as token metadata renders them today. An empty value is not
// a fact: the ID of a trust domain itself has no "path", and empty audience
// entries are left out. The table copies every value and retains no SVID.
// mount is the backend's live naming, so a later mapping edit reaches this
// admission.
func newAdmission(id spiffeid.ID, svid string, audiences []string, issuedAt time.Time, mount *logical.MountFacts) *logical.Admission {
	facts := selector.NewTable(
		helper.TableValue(factSPIFFEID, id.String()),
		helper.TableValue(factTrustDomain, id.TrustDomain().Name()),
		helper.TableValue(factPath, id.Path()),
		helper.TableValue(factSVID, svid),
		helper.TableValues(factAudiences, audiences),
	)
	return &logical.Admission{
		Facts:    facts,
		Mount:    mount,
		IssuedAt: issuedAt,
		Bytes:    facts.Bytes(),
	}
}

// CheckSVIDMaxAge returns why adm, an admission of this mount, is too old to
// admit at now under the mount's max_age, or nil. max_age applies to JWT-SVIDs
// only: an X.509-SVID carries no issue time and is not checked. Any other
// admission, a JWT-SVID or one whose kind is not x509, goes through
// helper.CheckMaxAge, which refuses one without an issue time. A nil config is
// the unconfigured mount, which sets no max_age.
func (c *SPIFFEAuthConfig) CheckSVIDMaxAge(adm *logical.Admission, now time.Time) error {
	if c == nil || c.MaxAge <= 0 {
		return nil
	}
	if adm != nil && adm.Facts != nil {
		cur := adm.Facts.Lookup(selector.Key{Name: factSVID})
		if v, ok := cur.Next(); ok && v.Kind == selector.KindString && v.S == svidX509 {
			return nil
		}
	}
	var issuedAt time.Time
	if adm != nil {
		issuedAt = adm.IssuedAt
	}
	return helper.CheckMaxAge(c.MaxAge, issuedAt, now)
}

// factsSources is the phrase the config path uses for what a facts source is
// on a spiffe mount: the built-in names, sorted, as CompileFields lists them
// when it refuses a source.
var factsSources = "one of the SVID fields: " +
	strings.Join(slices.Sorted(slices.Values(spiffeBuiltinFacts())), ", ")
