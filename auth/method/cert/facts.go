package cert

import (
	"crypto/x509"
	"slices"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// Built-in fact names of a cert mount: the verified leaf certificate's subject
// and SAN fields, as today's metadata_mappings selectors name them, and the
// trust anchors its chains were verified to. They are also the sources a
// mount's facts can rename.
const (
	factCommonName = "cn"
	factSerial     = "serial"
	factOrgUnit    = "ou"
	factOrg        = "org"
	factDNSSAN     = "dns_san"
	factEmailSAN   = "email_san"
	factURISAN     = "uri_san"
	factCA         = "ca"
)

// certBuiltinFacts returns the fact names every cert mount publishes under
// their own names. The slice is fresh on each call.
func certBuiltinFacts() []string {
	return []string{
		factCommonName,
		factSerial,
		factOrgUnit,
		factOrg,
		factDNSSAN,
		factEmailSAN,
		factURISAN,
		factCA,
	}
}

var _ logical.FactsProvider = (*certAuthBackend)(nil)

// FactNames implements logical.FactsProvider (see helper.FactNames).
func (b *certAuthBackend) FactNames() []string { return helper.FactNames(b.mountFacts) }

// newAdmission returns what a successful login verified about cert: its
// subject and SAN fields, and as "ca" the SHA-256 fingerprint (lowercase hex
// of the DER) of the anchor of every chain in chains, the chains cert was
// verified along, each distinct anchor once. The serial is rendered in
// decimal and a URI SAN as its URL string, as token metadata renders them
// today.
//
// An empty value is not a fact: a certificate without a common name has no
// "cn", and empty OU, organization or SAN entries are left out. The table
// copies every value and retains neither cert nor chains. IssuedAt stays zero:
// a certificate's validity window is not an issue time. mount is the backend's
// live naming, so a later mapping edit reaches this admission.
func newAdmission(cert *x509.Certificate, chains [][]*x509.Certificate, mount *logical.MountFacts) *logical.Admission {
	var serial string
	if cert.SerialNumber != nil {
		serial = cert.SerialNumber.String()
	}
	var uris []string
	if len(cert.URIs) > 0 {
		uris = make([]string, 0, len(cert.URIs))
		for _, u := range cert.URIs {
			if u != nil {
				uris = append(uris, u.String())
			}
		}
	}
	facts := selector.NewTable(
		helper.TableValue(factCommonName, cert.Subject.CommonName),
		helper.TableValue(factSerial, serial),
		helper.TableValues(factOrgUnit, cert.Subject.OrganizationalUnit),
		helper.TableValues(factOrg, cert.Subject.Organization),
		helper.TableValues(factDNSSAN, cert.DNSNames),
		helper.TableValues(factEmailSAN, cert.EmailAddresses),
		helper.TableValues(factURISAN, uris),
		helper.TableValues(factCA, anchorFingerprints(chains)),
	)
	return &logical.Admission{
		Facts: facts,
		Mount: mount,
		Bytes: facts.Bytes(),
	}
}

// anchorFingerprints returns the fingerprint of the last certificate of each
// chain, the trust anchor it was verified to, each distinct one once, in the
// order the chains first reach it. Verification yields a handful of chains, so
// a linear scan dedupes them.
func anchorFingerprints(chains [][]*x509.Certificate) []string {
	var out []string
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		fp := certFingerprint(chain[len(chain)-1])
		if !slices.Contains(out, fp) {
			out = append(out, fp)
		}
	}
	return out
}

// factsSources is the phrase the config path uses for what a facts source is
// on a cert mount.
const factsSources = "one of the certificate fields: " +
	factCommonName + ", " + factSerial + ", " + factOrgUnit + ", " + factOrg + ", " +
	factDNSSAN + ", " + factEmailSAN + ", " + factURISAN + ", " + factCA
