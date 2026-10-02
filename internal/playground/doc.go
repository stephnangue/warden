// Package playground holds the fixtures behind `warden server -dev-playground`:
// a dev identity provider that doubles as a bank's authorization server, a bank
// with an MCP face and a REST face, and the bootstrap that wires Warden to them.
// Nothing here runs unless the playground is asked for; the package is only ever
// started next to an in-memory dev server.
//
// The IdP signs the agent and user identities people try Warden with. It is not
// Warden's own OIDC issuer: Warden's issuer stays outbound-only, and the
// authorization server verifies the assertions it signs, exactly as a real
// security-token service would.
package playground
