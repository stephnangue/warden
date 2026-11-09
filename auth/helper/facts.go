package helper

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// FactsConfig is the part of an auth mount's configuration that names what it
// admits: the kind of entity, the facts it publishes beyond the method's
// built-ins (source to canonical name), and the fact its native identities
// (aliases) are taken from. Methods embed it in their config struct;
// encoding/json flattens the exported fields into the config's own keys and
// skips the compiled state.
//
// A FactsConfig is compiled once, when the config is built, and is not changed
// afterwards: the config that holds it is installed whole and read under the
// mount's config lock, and the naming it compiled to is immutable.
type FactsConfig struct {
	EntityKind      string            `json:"entity_kind,omitempty"`
	Facts           map[string]string `json:"facts,omitempty"`
	AliasNameSource string            `json:"alias_name_source,omitempty"`

	naming    *logical.MountNaming
	namingErr error
}

// AliasPolicy is what a method allows as its alias source: the fact an empty
// alias_name_source means (Default), and the names it may be set to (Allowed;
// nil allows any fact name visible on the mount, built-in or mapped). A Fixed
// policy refuses alias_name_source altogether: the alias is always Default.
type AliasPolicy struct {
	Default string
	Allowed []string
	Fixed   bool
}

// Compile compiles EntityKind, Facts and AliasNameSource with the method's
// built-in fact names and alias policy. On success Naming returns the result;
// on failure Naming is nil and Err says why, naming the config key at fault.
// Either way an empty EntityKind becomes logical.EntityKindAgent, the default
// it stands for, so a config reads back the same kind whether or not its facts
// compile; a kind that is set is left as written. An empty AliasNameSource
// stays empty in the config and compiles to the policy's default.
func (c *FactsConfig) Compile(builtins []string, alias AliasPolicy) {
	c.naming, c.namingErr = nil, nil
	c.defaultKind()
	mapping, err := selector.CompileMapping(builtins, c.Facts)
	if err != nil {
		c.namingErr = fmt.Errorf("facts: %w", err)
		return
	}
	naming, err := logical.NewMountNaming(mapping, c.EntityKind)
	if err != nil {
		c.namingErr = fmt.Errorf("entity_kind: %w", err)
		return
	}
	source, err := c.aliasSource(mapping, alias)
	if err != nil {
		c.namingErr = fmt.Errorf("alias_name_source: %w", err)
		return
	}
	naming.AliasSource = source
	c.naming = naming
	c.EntityKind = naming.Kind
}

// aliasSource returns the fact the mount's aliases are taken from: the
// configured one, or the policy's default when none is configured. A
// configured name must be allowed by the policy and visible under mapping.
func (c *FactsConfig) aliasSource(mapping *selector.Mapping, alias AliasPolicy) (string, error) {
	source := c.AliasNameSource
	switch {
	case source == "":
		return alias.Default, nil
	case alias.Fixed:
		return "", fmt.Errorf("cannot be set on this mount: the alias is always %q", alias.Default)
	case alias.Allowed != nil && !slices.Contains(alias.Allowed, source):
		return "", fmt.Errorf("%q is not one of %s", source, strings.Join(alias.Allowed, ", "))
	case !slices.Contains(mapping.Names(), source):
		return "", fmt.Errorf("%q is not a fact this mount publishes (one of %s)",
			source, strings.Join(mapping.Names(), ", "))
	}
	return source, nil
}

// CompileFields is Compile for a method whose facts are a fixed set of fields
// (a selector.Table): fields are its built-in names and the only sources Facts
// may map, since a Table answers nothing else. A source outside fields fails
// the compile, naming the fields that exist; EntityKind is defaulted as
// Compile defaults it.
func (c *FactsConfig) CompileFields(fields []string, alias AliasPolicy) {
	sources := slices.Sorted(maps.Keys(c.Facts))
	for _, source := range sources {
		if !slices.Contains(fields, source) {
			c.defaultKind()
			c.naming = nil
			c.namingErr = fmt.Errorf("facts: source %q is not a field of this mount (one of %s)",
				source, strings.Join(slices.Sorted(slices.Values(fields)), ", "))
			return
		}
	}
	c.Compile(fields, alias)
}

// defaultKind sets an empty EntityKind to logical.EntityKindAgent, the kind an
// empty one means.
func (c *FactsConfig) defaultKind() {
	if c.EntityKind == "" {
		c.EntityKind = logical.EntityKindAgent
	}
}

// Naming returns the compiled naming, or nil when Compile failed or has not
// run. A nil naming answers no fact.
func (c *FactsConfig) Naming() *logical.MountNaming { return c.naming }

// Err returns why Compile failed, or nil.
func (c *FactsConfig) Err() error { return c.namingErr }

// FactsDoNotCompileLog is logged when a mount installs a configuration whose
// facts do not compile at load (from the mount table, or storage written under
// looser rules). Such a mount answers no fact until its config is rewritten;
// failing the load instead would fail the mount, and at unseal the unseal.
const FactsDoNotCompileLog = "auth mount facts do not compile; the mount answers no fact until its config is rewritten"

// FactsWriteError returns why a config write must be refused over its facts,
// or nil. built is the facts part of the config the write would install, with
// the stored values merged under the request's; touched reports whether the
// request carried facts, entity_kind or alias_name_source. A write that left
// them out can only fail on what is stored, and is told how to replace it.
func FactsWriteError(built *FactsConfig, touched bool) error {
	err := built.Err()
	if err == nil {
		return nil
	}
	if touched {
		return err
	}
	return fmt.Errorf("the stored facts do not compile (%v); send facts (and entity_kind) in this write to replace them", err)
}

// FactsFieldSchemas returns the config fields every fact-naming auth method
// accepts, so their descriptions stay alike. sources says what a source is on
// the calling method, as a phrase ("a claim name, or …"; "one of the
// TokenReview fields: …"); aliases says what alias_name_source may name, as
// a phrase, and is empty on a method whose alias is fixed. The map is fresh on
// each call, for the caller to merge into its path's fields.
func FactsFieldSchemas(sources, aliases string) map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		"entity_kind": {
			Type:        framework.TypeString,
			Description: "Kind of entity this mount admits: agent (default) or human.",
		},
		"facts": {
			Type: framework.TypeMap,
			Description: "Map of a source (" + sources + ") " +
				"to the fact name it is published as. The method's built-in facts are always published under their own names. " +
				"A write replaces the whole map; an empty map clears it.",
		},
	}
	if aliases != "" {
		fields["alias_name_source"] = &framework.FieldSchema{
			Type: framework.TypeString,
			Description: "Fact whose first value is a credential's native identity (alias): " + aliases + ". " +
				"Applies to credentials admitted after the change. An empty value restores the default.",
		}
	}
	return fields
}

// ParseAliasNameSource converts the alias_name_source field of a config write.
func ParseAliasNameSource(raw any) (string, error) {
	switch v := raw.(type) {
	case nil:
		return "", nil
	case string:
		return strings.TrimSpace(v), nil
	}
	return "", fmt.Errorf("alias_name_source: must be a string, got %T", raw)
}

// ParseBoundAudiences converts a bound_audiences value, from a config write,
// storage or a mount table config, to a list: a list of strings, or one
// comma-separated string. Entries are trimmed and none may be empty; an empty
// string or list (or nil) clears the list and returns nil.
func ParseBoundAudiences(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	auds, err := parseutil.ParseCommaStringSlice(raw)
	if err != nil {
		return nil, fmt.Errorf("bound_audiences: %w", err)
	}
	for i, aud := range auds {
		if aud == "" {
			return nil, fmt.Errorf("bound_audiences: entry %d is empty", i)
		}
	}
	if len(auds) == 0 {
		return nil, nil
	}
	return auds, nil
}

// TableValue returns a single-valued field of a selector.Table, or a field
// with no value when v is empty: an empty value is not a fact.
func TableValue(name, v string) selector.Field {
	if v == "" {
		return selector.Field{Name: name}
	}
	return selector.Field{Name: name, Values: []string{v}}
}

// TableValues returns a multi-valued field of a selector.Table holding vs
// without its empty entries: an empty value is not a fact. It holds vs itself
// when vs has none, which is the norm; selector.NewTable copies either way.
func TableValues(name string, vs []string) selector.Field {
	for i, v := range vs {
		if v != "" {
			continue
		}
		out := make([]string, 0, len(vs)-1)
		out = append(out, vs[:i]...)
		for _, w := range vs[i+1:] {
			if w != "" {
				out = append(out, w)
			}
		}
		return selector.Field{Name: name, Values: out}
	}
	return selector.Field{Name: name, Values: vs}
}

// CertFingerprint returns the SHA-256 fingerprint of a certificate's DER, as
// lowercase hex.
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// AnchorFingerprints returns the fingerprint (CertFingerprint) of the trust
// anchor of each chain a certificate verification returned, the chain's last
// certificate: each distinct anchor once, sorted, so a credential yields the
// same values in the same order whatever order the chains came in. A verified
// chain is never empty. The slice is fresh, and empty when there are no
// chains.
func AnchorFingerprints(chains [][]*x509.Certificate) []string {
	out := make([]string, 0, len(chains))
	for _, chain := range chains {
		out = append(out, CertFingerprint(chain[len(chain)-1]))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ParseFactsField converts the facts field of a config write to a source to
// name map. Every name must be a string; an empty map clears the mapping.
func ParseFactsField(raw any) (map[string]string, error) {
	switch m := raw.(type) {
	case nil:
		return nil, nil
	case map[string]string:
		if len(m) == 0 {
			return nil, nil
		}
		return maps.Clone(m), nil
	case map[string]any:
		if len(m) == 0 {
			return nil, nil
		}
		facts := make(map[string]string, len(m))
		for source, v := range m {
			name, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("facts: the fact name for source %q must be a string, got %T", source, v)
			}
			facts[source] = name
		}
		return facts, nil
	}
	return nil, fmt.Errorf("facts: must be a map of source to fact name, got %T", raw)
}

// FactNames returns every fact name a mount answers under the naming mf holds,
// built-in and mapped, sorted, as a fresh slice. It is empty when mf is nil or
// holds no naming (an unconfigured mount, or facts that do not compile). It
// loads the naming without a lock.
func FactNames(mf *logical.MountFacts) []string {
	n := mf.Load()
	if n == nil {
		return nil
	}
	return slices.Clone(n.Mapping.Names())
}

// AliasDerivation describes how n derives a credential's alias: the kind of
// entity it admits, the fact the alias is taken from and, for a mapped fact,
// the raw key it reads. Two namings with the same derivation derive the same
// alias from every credential. It is "" for a nil naming.
func AliasDerivation(n *logical.MountNaming) string {
	if n == nil {
		return ""
	}
	key, _ := n.Mapping.Resolve(n.AliasSource)
	if key.Name == n.AliasSource {
		return fmt.Sprintf("kind %s, fact %q", n.Kind, n.AliasSource)
	}
	return fmt.Sprintf("kind %s, fact %q (source %q)", n.Kind, n.AliasSource, key.Name)
}

// AliasChange returns how the mount whose live naming mf holds derives
// aliases (from), and how it would once a config write carrying data is
// installed (to): cur, the stored facts config, with the write's entity_kind,
// facts and alias_name_source applied as the write applies them, compiled by
// compile. A sent key replaces the stored value and an absent one keeps it.
// to is "" when the write is refused anyway: a value that does not parse, or
// facts that do not compile.
func AliasChange(mf *logical.MountFacts, cur FactsConfig, data map[string]any, compile func(*FactsConfig)) (from, to string) {
	next := FactsConfig{EntityKind: cur.EntityKind, Facts: cur.Facts, AliasNameSource: cur.AliasNameSource}
	if raw, sent := data["entity_kind"]; sent {
		kind, ok := raw.(string)
		if !ok {
			return "", ""
		}
		next.EntityKind = kind
	}
	if raw, sent := data["facts"]; sent {
		facts, err := ParseFactsField(raw)
		if err != nil {
			return "", ""
		}
		next.Facts = facts
	}
	if raw, sent := data["alias_name_source"]; sent {
		source, err := ParseAliasNameSource(raw)
		if err != nil {
			return "", ""
		}
		next.AliasNameSource = source
	}
	compile(&next)
	return AliasDerivation(mf.Load()), AliasDerivation(next.Naming())
}

// EntityKind returns the kind of the naming mf holds, or "" when mf is nil or
// holds no naming. It loads the naming without a lock.
func EntityKind(mf *logical.MountFacts) string {
	if n := mf.Load(); n != nil {
		return n.Kind
	}
	return ""
}

// maxIssuedAt bounds an accepted iat, in seconds since the epoch (about the
// year 36812): far beyond any real token, and well inside time.Time.
const maxIssuedAt = 1 << 40

// IssuedAt returns a credential's iat claim as a time, or zero when it is
// absent, not a number, not after the epoch, or beyond 1<<40 seconds. It
// accepts what JSON decoding yields (float64, or json.Number with UseNumber)
// and the Go integer types; a fraction is truncated.
func IssuedAt(claims map[string]any) time.Time {
	var secs int64
	switch v := claims["iat"].(type) {
	case float64:
		if math.IsNaN(v) || v <= 0 || v > maxIssuedAt {
			return time.Time{}
		}
		secs = int64(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			secs = i
		} else if f, err := v.Float64(); err == nil && f > 0 && f <= maxIssuedAt {
			secs = int64(f)
		} else {
			return time.Time{}
		}
	case int:
		secs = int64(v)
	case int32:
		secs = int64(v)
	case int64:
		secs = v
	case uint32:
		secs = int64(v)
	case uint64:
		if v > maxIssuedAt {
			return time.Time{}
		}
		secs = int64(v)
	default:
		return time.Time{}
	}
	if secs <= 0 || secs > maxIssuedAt {
		return time.Time{}
	}
	return time.Unix(secs, 0)
}

// JWTPayloadBytes estimates the memory a JWT's decoded claims retain as the
// size of its JSON payload: the decoded length of the token's middle segment.
// The decoded map is larger than its text by a roughly constant factor, so the
// estimate ranks cached admissions correctly. It is 0 for a token without
// three segments.
func JWTPayloadBytes(token string) int64 {
	_, rest, ok := strings.Cut(token, ".")
	if !ok {
		return 0
	}
	payload, _, ok := strings.Cut(rest, ".")
	if !ok {
		return 0
	}
	return int64(base64.RawURLEncoding.DecodedLen(len(payload)))
}
