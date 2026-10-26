package cert

import (
	"crypto/x509"
	"slices"
	"strings"

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

// certAliasPolicy takes a certificate's alias from its common name by default,
// or from another identity field (the fields principal_claim accepts).
var certAliasPolicy = helper.AliasPolicy{
	Default: factCommonName,
	Allowed: []string{factCommonName, factDNSSAN, factEmailSAN, factURISAN, factSerial},
}

// certAliasSources is the phrase the config path uses for what
// alias_name_source may name on a cert mount.
const certAliasSources = "one of cn, dns_san, email_san, uri_san, serial; default cn"

// cnAliasSpansAnchors is the warning a config write returns when aliases are
// common names while the mount trusts more than one anchor: two CAs can issue
// the same name, and both certificates would present one native identity.
const cnAliasSpansAnchors = "alias_name_source is cn while trusted_ca_pem holds %d certificates: " +
	"certificates from different CAs with the same common name present the same native identity; " +
	"use uri_san, or one mount per CA"

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

// EntityKind implements logical.FactsProvider (see helper.EntityKind).
func (b *certAuthBackend) EntityKind() string { return helper.EntityKind(b.mountFacts) }

var _ logical.CredentialFormatProvider = (*certAuthBackend)(nil)

// CredentialFormat implements logical.CredentialFormatProvider: the mount
// admits a TLS client certificate.
func (b *certAuthBackend) CredentialFormat() logical.CredentialFormat {
	return logical.CredentialFormatCert
}

// newAdmission returns what a successful login verified about cert: its
// subject and SAN fields, and as "ca" the SHA-256 fingerprint (lowercase hex
// of the DER) of the anchor of every chain in chains, the chains cert was
// verified along, each distinct anchor once, sorted. The serial is rendered in
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
		uris = make([]string, len(cert.URIs))
		for i, u := range cert.URIs {
			uris[i] = u.String()
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
		helper.TableValues(factCA, helper.AnchorFingerprints(chains)),
	)
	return &logical.Admission{
		Facts: facts,
		Mount: mount,
		Bytes: facts.Bytes(),
	}
}

// factsSources is the phrase the config path uses for what a facts source is
// on a cert mount: the built-in names, sorted, as CompileFields lists them when
// it refuses a source.
var factsSources = "one of the certificate fields: " +
	strings.Join(slices.Sorted(slices.Values(certBuiltinFacts())), ", ")
