package logical

// DiscoveryAdmission is how a request on an identity path was admitted when
// it presented no service token. It belongs to one request, is built whole
// before the request is audited, and is not modified after.
type DiscoveryAdmission struct {
	// AdmittedBy lists the mounts that admitted the presented credential, in
	// mount order, each with the principal it was admitted as. Empty for an
	// anonymous request.
	AdmittedBy []AdmittedMount

	// RolesGranted counts the roles the groups grant the credential at the
	// mounts its roles are reached through.
	RolesGranted int

	// Anonymous reports that the request ran without an identity: the call
	// it carries answers the same to every caller, so no credential was
	// checked.
	Anonymous bool

	// CredentialUnverified reports, on an anonymous request, that a credential
	// was presented anyway and was neither checked nor used.
	CredentialUnverified bool
}

// AdmittedMount is one mount that admitted a credential.
type AdmittedMount struct {
	Mount       string // the auth mount's path relative to the namespace, without "auth/"
	PrincipalID string
}
