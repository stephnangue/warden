package credential

import "strings"

// Adjunct carriage: how a credential comes to hold more than its primary field.
//
// A credential type declares one primary field and, historically, a fixed list of
// extra ones. That list is a constant, so a provider needing a field the type's
// author did not anticipate reads something no configuration can supply — the
// branch is live code with no reachable input.
//
// The apikey source already lets an operator name extra fields (credential_fields)
// and copies them into rawData. What was missing is that the type filter then
// discarded them. Carriage closes that gap: the driver records which names it
// resolved under RawAdjunctFieldsKey, and the parser copies exactly those into the
// credential after the type has parsed it.
//
// The operator names the fields; the type decides what they mean. Nothing travels
// that nobody asked for, which is why the denylist below is a sanity check rather
// than the thing keeping secrets out of credential data.

// AdjunctCarrier is an optional interface a credential Type implements when its
// specs may carry operator-declared adjunct fields. It exists so a spec that sets
// a credential field the source will not carry is rejected at write time, rather
// than minting a credential quietly missing it — the failure that follows is a
// provider taking its fallback branch, which looks like a working mount.
type AdjunctCarrier interface {
	// KnownAdjunctFields returns the spec-config keys that describe the
	// credential rather than the mint. Only these are checked; a key the type
	// has never heard of is left alone, since it may belong to a mechanism this
	// type does not model.
	KnownAdjunctFields() []string
}

// UncarriedAdjunctFields returns the credential fields a spec sets that its
// source will not carry, along with the reason, so the caller can reject the spec
// and say what to do about it.
//
// Two different failures, and telling them apart matters. A source that could
// carry the field but was not told to needs a line adding to its
// credential_fields. A source whose driver has no such mechanism cannot carry it
// at all, and pointing that operator at credential_fields would send them to add
// a key that changes nothing — the same silent divergence this check exists to
// prevent, one layer up.
//
// Returns nothing for a type that does not carry adjuncts.
func UncarriedAdjunctFields(credType interface{}, specConfig, sourceConfig map[string]string, sourceType string) (fields []string, carriable bool) {
	carrier, ok := credType.(AdjunctCarrier)
	if !ok {
		return nil, true
	}

	// Only the apikey driver resolves credential_fields and tells the parser what
	// it carried; the parser honours the declaration from that driver alone.
	carriable = sourceType == SourceTypeAPIKey

	declared := make(map[string]bool)
	if carriable {
		for _, name := range ParseAdjunctNames(sourceConfig["credential_fields"]) {
			declared[name] = true
		}
	}

	for _, field := range carrier.KnownAdjunctFields() {
		if specConfig[field] != "" && !declared[field] {
			fields = append(fields, field)
		}
	}
	return fields, carriable
}

// reservedSpecConfigKeys are spec-config keys that address the mint itself —
// where to fetch, what to fetch, how to chain — rather than describing the
// credential. They are never carriable, and never masked on read either, since a
// locator is not a secret.
//
// Derived from the exported Config* constants where those exist. The store-backed
// locators do not have constants: they are string literals in the drivers, so
// they are listed here by name. A constants-only derivation would silently miss
// them — json_key_map in particular is a legitimate api_key spec key.
//
// Adding a spec-config key anywhere in the tree means adding it here.
var reservedSpecConfigKeys = map[string]struct{}{
	// Credential chaining.
	ConfigSecretSpec:     {},
	ConfigSecretField:    {},
	ConfigSecretCacheTTL: {},

	// Token exchange.
	ConfigSubjectTokenSource:      {},
	ConfigSubjectTokenType:        {},
	ConfigActorTokenSource:        {},
	ConfigActorTokenType:          {},
	ConfigAssertionAudience:       {},
	ConfigAssertionMetadataClaims: {},
	ConfigAssertionUserClaims:     {},
	ConfigAssertionAlgorithm:      {},
	ConfigAssertionResource:       {},

	// Store-backed mint locators (string literals in the drivers).
	"mint_method":     {},
	"kv2_mount":       {},
	"secret_path":     {},
	"secret_id":       {},
	"role_arn":        {},
	"version_stage":   {},
	"version_id":      {},
	"secret_version":  {},
	"credential_type": {},
	"json_key_map":    {},
}

// reservedRawDataPrefix marks keys that belong to the mint pipeline rather than
// to the credential — RawAdjunctFieldsKey and the rotated-refresh-token keys. No
// operator-declared field may use it, and no such key may be carried.
const reservedRawDataPrefix = "__"

// IsReservedSpecConfigName reports whether a name is one of the known mint-
// configuration keys — a locator or a chaining reference. These describe how to
// mint rather than what was minted, so they are neither carriable nor secret.
func IsReservedSpecConfigName(name string) bool {
	_, reserved := reservedSpecConfigKeys[name]
	return reserved
}

// IsReservedSpecConfigKey reports whether a name may be declared as an adjunct or
// carried into a credential. It covers the known mint keys plus the whole "__"
// namespace, which belongs to the mint pipeline.
//
// Use IsReservedSpecConfigName instead when deciding whether a key is *safe to
// display*: nothing stops an operator from putting a key called "__whatever" in a
// spec config, and treating the prefix as trusted there would print it in the
// clear.
func IsReservedSpecConfigKey(name string) bool {
	return strings.HasPrefix(name, reservedRawDataPrefix) || IsReservedSpecConfigName(name)
}

// ParseAdjunctNames splits a comma-separated declaration, trimming blanks. Shared
// by the driver that writes the declaration and the parser that reads it, so the
// two cannot disagree about what a name is.
func ParseAdjunctNames(raw string) []string {
	if raw == "" {
		return nil
	}
	var names []string
	for _, n := range strings.Split(raw, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	return names
}

// takeAdjunctNames removes the declaration from rawData and returns the names it
// held. It always removes, whatever the driver: a fetched secret payload reaches
// the parser verbatim, so the key may be a field of someone's Vault secret rather
// than something Warden wrote. Leaving it would let a lenient type copy it into
// the credential's Data.
func takeAdjunctNames(rawData map[string]interface{}) []string {
	raw, present := rawData[RawAdjunctFieldsKey]
	if !present {
		return nil
	}
	delete(rawData, RawAdjunctFieldsKey)
	s, _ := raw.(string)
	return ParseAdjunctNames(s)
}

// applyAdjunctCarriage copies the declared fields from rawData into the parsed
// credential. Called only for drivers that own the declaration.
//
// A field is skipped when the type already produced it, so carriage can never
// overwrite the primary field or anything the type's own Parse decided; when it
// is reserved, so the denylist holds even against a driver that ignored it; and
// when it is absent or empty, since a credential field with no value is worse
// than none — a provider reading it would build a malformed header rather than
// fall back.
func applyAdjunctCarriage(cred *Credential, rawData map[string]interface{}, names []string) {
	for _, name := range names {
		if IsReservedSpecConfigKey(name) {
			continue
		}
		if _, taken := cred.Data[name]; taken {
			continue
		}
		if v, ok := rawData[name].(string); ok && v != "" {
			if cred.Data == nil {
				cred.Data = make(map[string]string, len(names))
			}
			cred.Data[name] = v
		}
	}
}
