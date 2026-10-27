package kubernetes

import (
	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// Built-in fact names of a kubernetes mount: what the TokenReview asserted
// about the service account (status.user) and the audiences it validated
// (status.audiences). They are also the sources a mount's facts can rename.
const (
	factServiceAccountNamespace = "service_account_namespace"
	factServiceAccountName      = "service_account_name"
	factServiceAccountUID       = "service_account_uid"
	factUsername                = "username"
	factGroups                  = "groups"
	factAudiences               = "aud"
)

// kubernetesAliasPolicy takes a service account's alias from its username
// (system:serviceaccount:<namespace>:<name>) by default, which a service
// account re-created under the same name keeps, or from its UID, which it
// does not.
var kubernetesAliasPolicy = helper.AliasPolicy{
	Default: factUsername,
	Allowed: []string{factUsername, factServiceAccountUID},
}

// kubernetesAliasSources is the phrase the config path uses for what
// alias_name_source may name on a kubernetes mount.
const kubernetesAliasSources = "username (system:serviceaccount:<namespace>:<name>, the default) or service_account_uid " +
	"(stricter: a service account re-created under the same name is a new identity)"

// kubernetesBuiltinFacts returns the fact names every kubernetes mount
// publishes under their own names. The slice is fresh on each call.
func kubernetesBuiltinFacts() []string {
	return []string{
		factServiceAccountNamespace,
		factServiceAccountName,
		factServiceAccountUID,
		factUsername,
		factGroups,
		factAudiences,
	}
}

var _ logical.FactsProvider = (*kubernetesAuthBackend)(nil)

// FactNames implements logical.FactsProvider (see helper.FactNames).
func (b *kubernetesAuthBackend) FactNames() []string { return helper.FactNames(b.mountFacts) }

// EntityKind implements logical.FactsProvider (see helper.EntityKind).
func (b *kubernetesAuthBackend) EntityKind() string { return helper.EntityKind(b.mountFacts) }

var _ logical.CredentialFormatProvider = (*kubernetesAuthBackend)(nil)

// CredentialFormat implements logical.CredentialFormatProvider: the mount
// admits a service account JWT bearer, verified by a TokenReview.
func (b *kubernetesAuthBackend) CredentialFormat() logical.CredentialFormat {
	return logical.CredentialFormatKubernetesJWT
}

// newAdmission returns what a successful TokenReview verified about a
// service-account token: status is the review's result and namespace and name
// the service account parsed from its username. claims are the token's
// claims, parsed locally without checking the signature; the review verified
// that same token, so its iat is the one the cluster issued, and it becomes
// IssuedAt (zero when absent or not a number). claims are only read, never
// retained.
//
// An empty value is not a fact: an empty uid is absent, and empty group or
// audience entries are left out. The table copies every value, so status may
// be reused. mount is the backend's live naming, so a later mapping edit
// reaches this admission.
func newAdmission(status *tokenReviewStatus, namespace, name string, claims map[string]any, mount *logical.MountFacts) *logical.Admission {
	facts := selector.NewTable(
		helper.TableValue(factServiceAccountNamespace, namespace),
		helper.TableValue(factServiceAccountName, name),
		helper.TableValue(factServiceAccountUID, status.User.UID),
		helper.TableValue(factUsername, status.User.Username),
		helper.TableValues(factGroups, status.User.Groups),
		helper.TableValues(factAudiences, status.Audiences),
	)
	return &logical.Admission{
		Facts:       facts,
		PrincipalID: status.User.Username,
		Mount:       mount,
		IssuedAt:    helper.IssuedAt(claims),
		Bytes:       facts.Bytes(),
	}
}

// factsSources is the phrase the config path uses for what a facts source is
// on a kubernetes mount.
const factsSources = "one of the TokenReview fields: " +
	factServiceAccountNamespace + ", " + factServiceAccountName + ", " + factServiceAccountUID + ", " +
	factUsername + ", " + factGroups + ", " + factAudiences
