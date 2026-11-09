package anthropic

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
	"golang.org/x/net/http/httpguts"
)

// DefaultAnthropicVersion is the API version sent when a mount names none.
const DefaultAnthropicVersion = "2023-06-01"

// betaAllowAll is the beta_allowlist value that passes every client beta through.
// It is the default, so a mount that never set the field behaves as it did before
// the field existed.
const betaAllowAll = "*"

// State keys. The first four hold the operator's values exactly as written, and
// are what OnConfigRead reports and so what is persisted. The last two are built
// from them on every write and every load, and never persisted: a function value
// cannot be stored, and a derived value that was stored could disagree with the
// fields it came from.
//
// The framework persists whatever OnConfigRead returns, so keeping the derived
// values out of storage rests on onConfigRead naming its keys one by one. It must
// never return the state itself, or a copy of it.
const (
	stateVersion        = "anthropic_version"
	stateBetaAllowlist  = "beta_allowlist"
	stateBetaRequired   = "beta_required"
	stateProfileKey     = "user_profile_metadata_key"
	stateExtractor      = "credential_extractor"
	stateVersionHeaders = "version_headers"
)

// profileIDPrefix begins every upstream user profile id. A profile is an object
// the upstream issues, so an id can only be looked up, never derived; checking the
// prefix is what keeps an unrelated metadata value from being sent as one.
const profileIDPrefix = "uprof_"

// profileBetaPrefix begins every beta that enables anthropic-user-profile-id. The
// upstream requires one alongside the header, and has published several dated
// versions, so the mount checks for the family rather than one name.
const profileBetaPrefix = "user-profiles-"

// profileBetaName matches a member of that family. The upstream names its betas
// feature-YYYY-MM-DD, so the date is checked as well as the prefix: a bare
// "user-profiles-", or one with a mistyped suffix, would pass a prefix check and
// then be refused upstream on every request.
var profileBetaName = regexp.MustCompile(`^` + profileBetaPrefix + `\d{4}-\d{2}-\d{2}$`)

// betaHeaderKey is the canonical form of anthropic-beta. Inbound header names are
// canonicalised by the server, so indexing the map with it directly reads the
// client's values without the per-call key canonicalisation Header.Values does.
var betaHeaderKey = http.CanonicalHeaderKey("anthropic-beta")

// defaultVersionHeaders serves every mount that names no version. The framework
// only ranges over what DynamicHeaders returns, so one shared map is safe to hand
// out concurrently and saves an allocation on each request.
var defaultVersionHeaders = map[string]string{"anthropic-version": DefaultAnthropicVersion}

// betaPolicy decides which anthropic-beta values reach the upstream.
//
// A value is immutable once built: a config write builds a new one and swaps it
// into the state, so a request that captured the old policy applies all of it,
// never half of an update. That holds per policy, not per request — the gateway
// reads the version from a separate snapshot of the state, so a write landing
// between the two can pair the old policy with the new version on one request.
type betaPolicy struct {
	// allow filters the client's betas. nil passes every one through; an empty,
	// non-nil set passes none.
	allow map[string]struct{}

	// required is injected on every request, whatever the client sent and
	// whatever allow says — it is the operator's own choice, not the client's.
	required []string
}

// passThroughBetas is the policy of a mount with no beta config: every client
// beta through, nothing added.
var passThroughBetas = &betaPolicy{}

// merge returns the anthropic-beta value to send, or "" to send none.
//
// Client values come first, in the order sent, then any required value the
// client did not already send. A name is sent once however many times it
// appears, since the upstream reads every value of the header and a duplicate
// adds nothing but length.
func (p *betaPolicy) merge(client []string) string {
	// The common case, left byte-for-byte as the client sent it: one header, no
	// filtering and nothing to add. Anything else has to be rebuilt anyway.
	if p.allow == nil && len(p.required) == 0 {
		switch len(client) {
		case 0:
			return ""
		case 1:
			return client[0]
		}
	}

	var names betaNames
	for _, header := range client {
		for rest := header; rest != ""; {
			var name string
			name, rest, _ = strings.Cut(rest, ",")
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if p.allow != nil {
				if _, ok := p.allow[name]; !ok {
					continue
				}
			}
			names.add(name)
		}
	}
	for _, name := range p.required {
		names.add(name)
	}
	return strings.Join(names.out, ",")
}

// betaNamesLinearMax is how many names are deduplicated by scanning before a set
// takes over. Real requests carry a handful of betas, which a scan handles with
// no allocation; the set is there for a client that sends thousands.
const betaNamesLinearMax = 16

// betaNames collects distinct names in first-seen order.
//
// Deduplicating by scanning alone would be quadratic in the client's input, and
// the input is a header the client controls: one of the size the server accepts
// holds a couple of hundred thousand names, which scanning turns into seconds of
// CPU per request. Switching to a set past a small count keeps the whole thing
// linear.
type betaNames struct {
	out  []string
	seen map[string]struct{}
}

func (n *betaNames) add(name string) {
	if n.seen != nil {
		if _, dup := n.seen[name]; dup {
			return
		}
		n.seen[name] = struct{}{}
		n.out = append(n.out, name)
		return
	}
	if slices.Contains(n.out, name) {
		return
	}
	n.out = append(n.out, name)
	if len(n.out) > betaNamesLinearMax {
		n.seen = make(map[string]struct{}, 2*len(n.out))
		for _, v := range n.out {
			n.seen[v] = struct{}{}
		}
	}
}

// newExtractor wraps the credential extractor with the mount's beta policy and,
// when profileKey is set, the requesting user's profile.
//
// anthropic-beta is on the strip list, so the client's value is gone by the time
// the credential headers are applied. Whatever the policy lets through has to be
// put back from here — including, under the default policy, all of it. The
// extractor runs before the strip, which is why it can still read the value.
func newExtractor(policy *betaPolicy, profileKey string) httpproxy.CredentialExtractor {
	return func(req *logical.Request) (map[string]string, error) {
		headers, err := anthropicCredentialExtractor(req)
		if err != nil {
			return nil, err
		}
		var client []string
		if req.HTTPRequest != nil {
			client = req.HTTPRequest.Header[betaHeaderKey]
		}
		if betas := policy.merge(client); betas != "" {
			headers["anthropic-beta"] = betas
		}
		if id := userProfileID(req, profileKey); id != "" {
			headers["anthropic-user-profile-id"] = id
		}
		return headers, nil
	}
}

// userProfileID returns the upstream profile the request is made on behalf of, or
// "" when there is none to send.
//
// It is read from the user principal's verified metadata and from nowhere else.
// The agent's metadata is the tempting fallback and the wrong one: it would
// attribute an agent's own traffic to an end user whenever the agent's role
// happened to map the same key. A profile can carry grants that change what the
// upstream will do, so that is not a billing slip but a request acting under
// someone else's standing. No user, no header.
//
// A value that is not a profile id is dropped rather than failing the request.
// Metadata keys are named by the operator and filled from identity-provider
// claims, so a missing or unrelated value is ordinary, and sending it would only
// be refused upstream. The token check also keeps a claim carrying a line break
// from reaching a header.
//
// The metadata is read without the token entry's lock. A cached entry is shared
// by concurrent requests, which is safe only because its metadata is set when the
// token is issued and never changed afterwards.
func userProfileID(req *logical.Request, key string) string {
	if key == "" || req.User == nil || req.User.TokenEntry == nil {
		return ""
	}
	id := req.User.TokenEntry.Metadata[key]
	if len(id) <= len(profileIDPrefix) || !strings.HasPrefix(id, profileIDPrefix) || !isToken(id) {
		return ""
	}
	return id
}

// checkProfilePairing refuses a profile key with no beta that enables the header.
// The upstream requires a user-profiles beta alongside anthropic-user-profile-id,
// so a mount mapping one without the other would attribute nothing while reading
// as configured.
func checkProfilePairing(profileKey string, required []string) error {
	if profileKey == "" {
		return nil
	}
	for _, name := range required {
		if profileBetaName.MatchString(name) {
			return nil
		}
	}
	return fmt.Errorf("%s: beta_required must name a %sYYYY-MM-DD beta, which the upstream requires alongside anthropic-user-profile-id",
		stateProfileKey, profileBetaPrefix)
}

// parseBetaNames splits a comma-separated beta list. Each name must be an HTTP
// token: the upstream names its betas that way, and anything else would either
// break the header or be refused on every request.
//
// Blank entries are skipped rather than refused, so a trailing comma is not an
// error. "*" is refused here; only the allowlist gives it a meaning, and only as
// its whole value.
func parseBetaNames(field, raw string) ([]string, error) {
	var names betaNames
	for rest := raw; rest != ""; {
		var name string
		name, rest, _ = strings.Cut(rest, ",")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if name == betaAllowAll {
			return nil, fmt.Errorf("%s: %q is only meaningful as the whole beta_allowlist value", field, betaAllowAll)
		}
		if !isToken(name) {
			return nil, fmt.Errorf("%s: %q is not a valid beta name", field, name)
		}
		names.add(name)
	}
	return names.out, nil
}

// buildBetaPolicy parses the two beta fields into a policy.
//
// allowlist has three meanings, told apart by presence rather than by value:
// absent or "*" passes every client beta; a list passes only those; and "" —
// present but empty — passes none. The empty case is the strictest, so an
// operator who clears the field is left failing closed rather than open.
func buildBetaPolicy(allowlist string, allowlistSet bool, required string) (*betaPolicy, error) {
	policy := &betaPolicy{}

	if allowlistSet && strings.TrimSpace(allowlist) != betaAllowAll {
		names, err := parseBetaNames(stateBetaAllowlist, allowlist)
		if err != nil {
			return nil, err
		}
		policy.allow = make(map[string]struct{}, len(names))
		for _, name := range names {
			policy.allow[name] = struct{}{}
		}
	}

	names, err := parseBetaNames(stateBetaRequired, required)
	if err != nil {
		return nil, err
	}
	policy.required = names

	if policy.allow == nil && len(policy.required) == 0 {
		return passThroughBetas, nil
	}
	return policy, nil
}

// validateVersion accepts "" (the default) or an HTTP token. The upstream's
// versions are dates, which are tokens; anything with a space or a separator in
// it would be refused on every request.
func validateVersion(v string) error {
	if v == "" || isToken(v) {
		return nil
	}
	return fmt.Errorf("anthropic_version: %q is not a valid version", v)
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !httpguts.IsTokenRune(r) {
			return false
		}
	}
	return true
}

// rebuild derives the request-time values from the operator's fields in state.
// It is the one place both are built, so a write and a load cannot build them
// differently.
//
// The version comes first because it cannot fail. On an error the state is still
// returned with the version applied, so a caller that falls back on the beta
// policy does not also lose the mount's version.
func rebuild(state map[string]any) (map[string]any, error) {
	if v, _ := state[stateVersion].(string); v != "" {
		state[stateVersionHeaders] = map[string]string{"anthropic-version": v}
	} else {
		delete(state, stateVersionHeaders)
	}

	allowlist, allowlistSet := state[stateBetaAllowlist].(string)
	required, _ := state[stateBetaRequired].(string)
	profileKey, _ := state[stateProfileKey].(string)

	policy, err := buildBetaPolicy(allowlist, allowlistSet, required)
	if err != nil {
		return state, err
	}
	if err := checkProfilePairing(profileKey, policy.required); err != nil {
		return state, err
	}
	state[stateExtractor] = newExtractor(policy, profileKey)
	return state, nil
}

// extraConfigFields are the mount settings this provider adds to the standard set.
var extraConfigFields = map[string]*framework.FieldSchema{
	stateVersion: {
		Type:        framework.TypeString,
		Default:     DefaultAnthropicVersion,
		Description: "API version sent as anthropic-version. Empty restores the default (" + DefaultAnthropicVersion + ")",
	},
	stateBetaAllowlist: {
		Type:    framework.TypeString,
		Default: betaAllowAll,
		Description: `Comma-separated anthropic-beta values a client may send. "*" (the default) ` +
			`passes every one; an empty value passes none`,
	},
	stateBetaRequired: {
		Type:        framework.TypeString,
		Description: "Comma-separated anthropic-beta values added to every request, whatever the allowlist says",
	},
	stateProfileKey: {
		Type: framework.TypeString,
		Description: "Key in the user's verified token metadata holding their upstream profile id (uprof_...), " +
			"sent as anthropic-user-profile-id. Requires a user-profiles-* beta in beta_required. Empty disables it",
	},
}

// dynamicHeaders supplies anthropic-version.
//
// The framework applies these only where the request carries no such header.
// That still amounts to always sending the mount's version, because
// anthropic-version is on the strip list and the strip runs first — so a client
// cannot pin its own. The default is read here rather than only from state: a
// mount whose persisted config predates the field has no version in state, and
// would otherwise send an empty one.
func dynamicHeaders(state map[string]any) map[string]string {
	if h, ok := state[stateVersionHeaders].(map[string]string); ok {
		return h
	}
	return defaultVersionHeaders
}

// resolveUpstream hands the gateway the extractor built for the mount's current
// beta policy. It is consulted twice per request, so it only looks one up; it
// builds nothing. A mount whose config was never written has none, and falls
// back to the spec's own pass-through extractor.
//
// It never sets SkipDynamicHeaders. Doing so would strip anthropic-version and
// then decline to put it back, and the upstream refuses a request without one.
func resolveUpstream(_ *http.Request, _ string, state map[string]any) (httpproxy.Dispatch, bool) {
	if ex, ok := state[stateExtractor].(httpproxy.CredentialExtractor); ok {
		return httpproxy.Dispatch{ExtractCredentials: ex}, true
	}
	return httpproxy.Dispatch{}, false
}

// configString reads a string from a raw config map, reporting whether it was
// present. A present value of another type is an error, not an absence: read as
// absent, an allowlist given as an array would mean "*" and let every client
// beta through.
//
// This is for the maps that reach the provider untyped — the config a mount is
// enabled with, and the one loaded from storage. A config write needs no such
// care: the framework checks each field against its declared type before the
// write reaches onConfigWrite, and refuses an array for a string field there.
func configString(conf map[string]any, k string) (string, bool, error) {
	v, present := conf[k]
	if !present || v == nil {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", false, fmt.Errorf("%s: must be a string", k)
	}
	return s, true, nil
}

// onConfigWrite applies a config write to a copy of the mount's state.
//
// Writes are partial, so each field is applied only when it is present and the
// rest keep their stored values. Validation runs after, over the merged result,
// because that — not the fields of this one write — is what will be in force.
//
// This is the check a live mount gets. ValidateExtraConfig runs only against the
// config a mount is enabled with; a later config write never reaches it.
func onConfigWrite(d *framework.FieldData, state map[string]any) (map[string]any, error) {
	if v, ok := d.GetOk(stateVersion); ok {
		version := strings.TrimSpace(v.(string))
		if err := validateVersion(version); err != nil {
			return nil, err
		}
		if version == "" {
			delete(state, stateVersion)
		} else {
			state[stateVersion] = version
		}
	}
	for _, k := range []string{stateBetaAllowlist, stateBetaRequired} {
		if v, ok := d.GetOk(k); ok {
			state[k] = v.(string)
		}
	}

	if v, ok := d.GetOk(stateProfileKey); ok {
		if profileKey := strings.TrimSpace(v.(string)); profileKey == "" {
			delete(state, stateProfileKey)
		} else {
			state[stateProfileKey] = profileKey
		}
	}
	return rebuild(state)
}

// onConfigRead reports the settings in force. Its result is also what is
// persisted, so it carries only the operator's own values — never the derived
// ones, which could not be stored.
func onConfigRead(state map[string]any) map[string]any {
	version, _ := state[stateVersion].(string)
	if version == "" {
		version = DefaultAnthropicVersion
	}
	allowlist, ok := state[stateBetaAllowlist].(string)
	if !ok {
		allowlist = betaAllowAll
	}
	required, _ := state[stateBetaRequired].(string)
	profileKey, _ := state[stateProfileKey].(string)
	return map[string]any{
		stateVersion:       version,
		stateBetaAllowlist: allowlist,
		stateBetaRequired:  required,
		stateProfileKey:    profileKey,
	}
}

// onInitialize loads the settings from a mount's persisted or enable-time config.
//
// beta_allowlist is read by presence. A mount that predates the field has no such
// key, and must keep passing client betas through as it did; reading the missing
// key as "" would instead mean "pass none", and silently drop every client beta
// on the first restart after upgrade.
//
// A persisted value that no longer parses cannot have come from a validated
// write; it means storage was edited by hand, or a later release validates more
// strictly than the one that wrote it. There is no error to return from here, so
// the mount fails closed — see failClosedPolicy. The config still reads back as
// stored, not as the policy in force; surfacing the gap needs a way for this hook
// to report an error, which it does not have.
func onInitialize(config map[string]any, state map[string]any) map[string]any {
	if v, ok := config[stateVersion].(string); ok && v != "" {
		state[stateVersion] = v
	}
	allowlist, allowlistSet, allowlistErr := configString(config, stateBetaAllowlist)
	if allowlistSet {
		state[stateBetaAllowlist] = allowlist
	}
	required, _, requiredErr := configString(config, stateBetaRequired)
	if required != "" {
		state[stateBetaRequired] = required
	}
	profileKey, _, profileErr := configString(config, stateProfileKey)
	if profileKey = strings.TrimSpace(profileKey); profileKey != "" {
		state[stateProfileKey] = profileKey
	}

	// Failing closed also means attributing no one: a profile is sent only from a
	// config known to be sound.
	rebuilt, err := rebuild(state)
	if err != nil || allowlistErr != nil || requiredErr != nil || profileErr != nil {
		state[stateExtractor] = newExtractor(failClosedPolicy(state), "")
		return state
	}
	return rebuilt
}

// failClosedPolicy is the policy of a mount whose stored config did not load: no
// client beta passes. The operator's required betas are kept when they parse on
// their own. They are the operator's choice rather than the client's, so they are
// not what failing closed guards against, and dropping them because an unrelated
// field failed would break the requests that depend on them.
func failClosedPolicy(state map[string]any) *betaPolicy {
	required, _ := state[stateBetaRequired].(string)
	names, err := parseBetaNames(stateBetaRequired, required)
	if err != nil {
		names = nil
	}
	return &betaPolicy{allow: map[string]struct{}{}, required: names}
}

// validateExtraConfig checks the config a mount is enabled with. It applies the
// same rules as onConfigWrite, which is what guards every later write.
func validateExtraConfig(conf map[string]any) error {
	version, _, err := configString(conf, stateVersion)
	if err != nil {
		return err
	}
	if err := validateVersion(strings.TrimSpace(version)); err != nil {
		return err
	}
	allowlist, allowlistSet, err := configString(conf, stateBetaAllowlist)
	if err != nil {
		return err
	}
	required, _, err := configString(conf, stateBetaRequired)
	if err != nil {
		return err
	}
	policy, err := buildBetaPolicy(allowlist, allowlistSet, required)
	if err != nil {
		return err
	}
	profileKey, _, err := configString(conf, stateProfileKey)
	if err != nil {
		return err
	}
	return checkProfilePairing(strings.TrimSpace(profileKey), policy.required)
}
