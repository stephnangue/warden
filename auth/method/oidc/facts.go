package oidc

import (
	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/logical"
)

// builtinFacts returns the ID token claims every oidc mount publishes under
// their own names: the ones the login checks against the mount's
// expectations. Every other claim is invisible until mapped. The slice is
// fresh on each call.
func builtinFacts() []string { return []string{"sub", "iss", "aud"} }

// aliasPolicy takes a person's alias from sub by default, or from any fact the
// mount publishes, built-in or mapped (an identity provider whose sub is
// pairwise per application maps a stable claim and names it).
var aliasPolicy = helper.AliasPolicy{Default: "sub"}

// aliasSources is the phrase the config path uses for what alias_name_source
// may name on an oidc mount.
const aliasSources = "any fact this mount publishes, built-in (sub, iss, aud) or mapped; default sub"

var _ logical.FactsProvider = (*oidcAuthBackend)(nil)

// FactNames implements logical.FactsProvider (see helper.FactNames).
func (b *oidcAuthBackend) FactNames() []string { return helper.FactNames(b.mountFacts) }

// EntityKind implements logical.FactsProvider (see helper.EntityKind).
func (b *oidcAuthBackend) EntityKind() string { return helper.EntityKind(b.mountFacts) }

// MountFacts implements logical.FactsProvider.
func (b *oidcAuthBackend) MountFacts() *logical.MountFacts { return b.mountFacts }

// AliasChange implements logical.FactsProvider (see helper.AliasChange).
func (b *oidcAuthBackend) AliasChange(data map[string]any) (from, to string) {
	var cur helper.FactsConfig
	b.configMu.RLock()
	if b.config != nil {
		cur = b.config.FactsConfig
	}
	b.configMu.RUnlock()
	return helper.AliasChange(b.mountFacts, cur, data, func(c *helper.FactsConfig) {
		if c.EntityKind == "" {
			c.EntityKind = logical.EntityKindHuman
		}
		c.Compile(builtinFacts(), aliasPolicy)
	})
}

// keptClaims returns the claims a ticket keeps: the top-level claim each
// built-in and each mapped source reads (a plain source names it, a JSON
// pointer starts at its first token). A map is a set, so a claim two sources
// read is kept once. It adopts the values of claims without copying.
func keptClaims(claims map[string]any, n *logical.MountNaming) map[string]any {
	sources := n.Mapping.Sources()
	kept := make(map[string]any, len(sources))
	for _, k := range sources {
		top := k.Name
		if k.IsPointer() {
			top = k.Path[0]
		}
		if v, ok := claims[top]; ok {
			kept[top] = v
		}
	}
	return kept
}
