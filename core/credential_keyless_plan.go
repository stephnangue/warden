package core

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// A keyless plan describes, without writing anything, the keyless objects to
// create in place of keyed ones: a keyless source with its specs, or a spec that
// fetches its secret through chaining. The operator creates them under new
// names next to the keyed ones, points roles at them, and deletes the keyed
// ones once they work. Until then the keyed objects are the way back, so
// nothing has to be kept to roll back to — not a snapshot, and not a rotated key
// that only this server knew.

// keylessNameSuffix names a proposed object after the one it replaces.
const keylessNameSuffix = "-keyless"

// nameInput is the per-object input that overrides a proposed name. It is not a
// config key, so it is taken out before the inputs reach a planner.
const nameInput = "name"

// KeylessPlanInputs is what the operator asks a plan for. It carries no secrets:
// the values it sets are names, role names, audiences, provider ids and spec
// references.
type KeylessPlanInputs struct {
	// Name is the name for the proposed source (or spec); default
	// "<name>-keyless".
	Name string `json:"name,omitempty"`

	// Target sets inputs for the proposed source (or spec).
	Target map[string]string `json:"target,omitempty"`

	// Specs sets inputs per bound spec, keyed by the keyed spec's name; its
	// "name" key names the proposed spec.
	Specs map[string]map[string]string `json:"specs,omitempty"`
}

// KeylessObject is a source or spec a plan proposes to create.
type KeylessObject struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Source   string            `json:"source,omitempty"`
	Replaces string            `json:"replaces"`
	Config   map[string]string `json:"config"`

	// MinTTL and MaxTTL, in seconds, carry over from the spec replaced.
	MinTTL int64 `json:"min_ttl,omitempty"`
	MaxTTL int64 `json:"max_ttl,omitempty"`

	Behaviour string   `json:"behaviour,omitempty"`
	Choices   []string `json:"choices,omitempty"`
}

// KeylessPlan is a plan's result.
type KeylessPlan struct {
	Source        *KeylessObject            `json:"source,omitempty"`
	Specs         []KeylessObject           `json:"specs"`
	Prerequisites []credential.Prerequisite `json:"prerequisites,omitempty"`
	Leftovers     []credential.Leftover     `json:"leftovers,omitempty"`
	Notes         []string                  `json:"notes,omitempty"`
	Blockers      []string                  `json:"blockers,omitempty"`
}

// PlanKeylessSource plans the keyless replacement of a source and every spec
// bound to it.
func (c *Core) PlanKeylessSource(ctx context.Context, name string, in KeylessPlanInputs) (*KeylessPlan, error) {
	store := c.credConfigStore
	if store == nil || store.isClosed() {
		return nil, ErrConfigStoreClosed
	}
	source, err := store.GetSource(ctx, name)
	if err != nil {
		if errors.Is(err, ErrSourceNotFound) {
			return nil, logical.ErrNotFoundf("credential source %q not found", name)
		}
		return nil, err
	}
	if store.isBuiltinSource(source.Name) {
		return nil, logical.ErrBadRequestf("the built-in %q source holds nothing; plan each of its specs instead", source.Name)
	}

	factory, err := c.credentialDriverRegistry.GetFactory(source.Type)
	if err != nil {
		return nil, err
	}
	if err := checkTargetInputs(in.Target, factory.SensitiveConfigFields()); err != nil {
		return nil, err
	}

	plan := &KeylessPlan{Specs: []KeylessObject{}}
	planner, ok := factory.(credential.KeylessPlanner)
	if !ok {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("source type %q has no keyless form", source.Type))
		return plan, nil
	}
	if len(factory.StoredSecrets(source.Config)) == 0 {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("credential source %q already stores no secret", source.Name))
	}

	sourcePlan, err := planner.PlanKeyless(source.Config, in.Target)
	if err != nil {
		return nil, logical.ErrBadRequest(err.Error())
	}
	for _, need := range sourcePlan.NeedsInput {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("the source needs input %q", need))
	}
	keylessCfg := source.Config.WithAll(sourcePlan.Delta)
	newSource := &credential.CredSource{
		Name:   proposedName(in.Name, source.Name),
		Type:   source.Type,
		Config: freshConfig(keylessCfg),
	}
	plan.Source = &KeylessObject{
		Name:     newSource.Name,
		Type:     newSource.Type,
		Replaces: source.Name,
		Config:   newSource.Config.Map(),
	}
	plan.Leftovers = sourcePlan.Leftovers
	plan.Notes = sourcePlan.Notes
	if source.RotationPeriod > 0 {
		plan.Notes = append(plan.Notes, fmt.Sprintf(
			"the keyless source holds no secret to rotate, so source %q's rotation_period is not carried over", source.Name))
	}

	checkProposedName(plan, "source", newSource.Name)
	switch _, err := store.GetSource(ctx, newSource.Name); {
	case err == nil:
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("a credential source named %q already exists; pass another name", newSource.Name))
	case !errors.Is(err, ErrSourceNotFound):
		return nil, err
	}
	// Validation waits for the inputs: a source missing one fails on it, which
	// would repeat the needs-input blocker, and every spec validated against it
	// would fail on its absence too. The plan run with the inputs validates all.
	sourceComplete := len(sourcePlan.NeedsInput) == 0
	if sourceComplete {
		if err := store.validateSource(ctx, newSource, true); err != nil {
			plan.Blockers = append(plan.Blockers, "the keyless source would not validate: "+err.Error())
		}
	}
	if left := factory.StoredSecrets(newSource.Config); len(left) > 0 {
		plan.Blockers = append(plan.Blockers, "the keyless source would still store "+strings.Join(left, ", "))
	}

	specs, err := store.CheckSourceReferences(ctx, source.Name)
	if err != nil {
		return nil, err
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	bound := make(map[string]bool, len(specs))
	for _, spec := range specs {
		bound[spec.Name] = true
	}
	for specName := range in.Specs {
		if !bound[specName] {
			return nil, logical.ErrBadRequestf("specs names %q, which is not a spec of source %q", specName, source.Name)
		}
	}

	var planned []credential.PlannedSpec
	proposed := make(map[string]string, len(specs))
	for _, spec := range specs {
		inputs := maps.Clone(in.Specs[spec.Name])
		newName := proposedName(inputs[nameInput], spec.Name)
		delete(inputs, nameInput)
		if other, dup := proposed[newName]; dup {
			plan.Blockers = append(plan.Blockers, fmt.Sprintf("specs %q and %q would both be replaced by %q; name one of them", other, spec.Name, newName))
		}
		proposed[newName] = spec.Name
		if err := refuseSecretInputs(inputs, c.specSensitiveFields(spec.Type, inputs), "spec "+spec.Name); err != nil {
			return nil, err
		}

		specPlan, err := planner.PlanKeylessSpec(spec.Type, spec.Config, source.Config, keylessCfg, inputs)
		if err != nil {
			return nil, logical.ErrBadRequestf("spec %q: %s", spec.Name, err.Error())
		}
		plan.Leftovers = append(plan.Leftovers, specPlan.Leftovers...)
		if specPlan.Blocker != "" {
			plan.Blockers = append(plan.Blockers, fmt.Sprintf("spec %q: %s", spec.Name, specPlan.Blocker))
			continue
		}
		for _, need := range specPlan.NeedsInput {
			plan.Blockers = append(plan.Blockers, fmt.Sprintf("spec %q needs input %q", spec.Name, need))
		}

		newSpec := &credential.CredSpec{
			Name:   newName,
			Type:   spec.Type,
			Source: newSource.Name,
			Config: freshConfig(spec.Config.WithAll(specPlan.Delta)),
			MinTTL: spec.MinTTL,
			MaxTTL: spec.MaxTTL,
		}
		plan.Specs = append(plan.Specs, specObject(newSpec, spec.Name, specPlan.Behaviour, specPlan.Choices))
		if err := c.checkProposedSpec(ctx, plan, newSpec, newSource, sourceComplete && len(specPlan.NeedsInput) == 0); err != nil {
			return nil, err
		}
		planned = append(planned, credential.PlannedSpec{Name: newSpec.Name, Type: newSpec.Type, Config: newSpec.Config})
		if spec.RotationPeriod > 0 {
			plan.Notes = append(plan.Notes, fmt.Sprintf(
				"spec %q's rotation_period is not carried over: the keyless spec is minted per request, not rotated", spec.Name))
		}
	}

	env, federated := c.trustEnv(ctx, newSource.Config)
	if federated && env == nil {
		plan.Blockers = append(plan.Blockers, "enable the OIDC issuer first: the keyless source authenticates with assertions it issues")
	}
	if env != nil {
		plan.Prerequisites = planner.KeylessPrerequisites(newSource.Config, planned, *env)
		if note := issuerPathNote(env); note != "" && federated {
			plan.Notes = append(plan.Notes, note)
		}
	}
	return plan, nil
}

// PlanKeylessSpec plans the keyless replacement of a spec that holds its own
// secret: a spec of the same type, on the same source, that fetches the secret
// through credential chaining. It is the same for every type — remove what the
// type reports as stored, set the reference the operator names — and the spec
// validation every write goes through judges the result.
func (c *Core) PlanKeylessSpec(ctx context.Context, name string, in KeylessPlanInputs) (*KeylessPlan, error) {
	store := c.credConfigStore
	if store == nil || store.isClosed() {
		return nil, ErrConfigStoreClosed
	}
	spec, err := store.GetSpec(ctx, name)
	if err != nil {
		if errors.Is(err, ErrSpecNotFound) {
			return nil, logical.ErrNotFoundf("credential spec %q not found", name)
		}
		return nil, err
	}
	source, err := store.GetSource(ctx, spec.Source)
	if err != nil {
		return nil, err
	}
	if err := checkTargetInputs(in.Target, c.specSensitiveFields(spec.Type, in.Target)); err != nil {
		return nil, err
	}

	plan := &KeylessPlan{Specs: []KeylessObject{}}
	switch {
	case source.Type == credential.SourceTypeLocal:
		where := "a keyless source"
		if homes := c.keylessSourceTypesFor(spec); len(homes) > 0 {
			where = fmt.Sprintf("a keyless source (for %s, a source of type %s)", spec.Type, strings.Join(homes, " or "))
		}
		plan.Blockers = append(plan.Blockers, fmt.Sprintf(
			"spec %q is on the local source, whose spec config is the credential itself. Plan it on %s instead: "+
				"create a spec of the same type there, with secret_spec naming the spec that reads the stored secret", spec.Name, where))
		return plan, nil
	case spec.Type == credential.TypeAzureBearerToken:
		plan.Blockers = append(plan.Blockers, fmt.Sprintf(
			"spec %q holds an Azure client secret, which goes keyless by federating its source: plan source %q instead",
			spec.Name, spec.Source))
		return plan, nil
	}

	stored := c.specStoredSecrets(spec.Type, spec.Config)
	if len(stored) == 0 {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("credential spec %q already stores no secret", spec.Name))
	}
	delta := make(map[string]string, len(stored)+len(in.Target))
	for _, field := range stored {
		if field == credential.StoredSecretSealedRefreshToken || field == "refresh_token" || field == "access_token" {
			plan.Blockers = append(plan.Blockers, fmt.Sprintf("spec %q holds a token sealed by connect, which has no keyless form", spec.Name))
			continue
		}
		delta[field] = ""
		plan.Leftovers = append(plan.Leftovers, credential.Leftover{
			Kind:          field,
			ID:            "stored on spec " + spec.Name,
			WhereToDelete: "revoke it at the provider once the keyless spec works",
		})
	}
	maps.Copy(delta, in.Target)
	hasRef := delta[credential.ConfigSecretSpec] != ""
	if !hasRef {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("the spec needs input %q: the spec that reads its secret per request", credential.ConfigSecretSpec))
	}

	newSpec := &credential.CredSpec{
		Name:   proposedName(in.Name, spec.Name),
		Type:   spec.Type,
		Source: spec.Source,
		Config: freshConfig(spec.Config.WithAll(delta)),
		MinTTL: spec.MinTTL,
		MaxTTL: spec.MaxTTL,
	}
	plan.Specs = append(plan.Specs, specObject(newSpec, spec.Name,
		"the secret is fetched per request through the referenced spec, as the calling agent, and cached for secret_cache_ttl at most", nil))
	if err := c.checkProposedSpec(ctx, plan, newSpec, source, hasRef); err != nil {
		return nil, err
	}
	if spec.RotationPeriod > 0 {
		plan.Notes = append(plan.Notes, fmt.Sprintf(
			"spec %q's rotation_period is not carried over: the keyless spec fetches its secret per request, and the referenced spec's owner rotates it", spec.Name))
	}

	// The spec stays on its source, and a spec create is judged together with
	// the source's own secrets: a new spec widens their use.
	if held := c.sourceStoredSecrets(source.Type, source.Config); len(held) > 0 {
		msg := fmt.Sprintf("source %q still stores %s", source.Name, strings.Join(held, ", "))
		if c.KeylessEnforcementLevel() == KeylessEnforcementEnforce {
			plan.Blockers = append(plan.Blockers, msg+
				", so keyless_enforcement_level=enforce would refuse the create: plan that source first with 'warden cred source keyless-plan'")
		} else {
			plan.Notes = append(plan.Notes, msg+
				", so the create will warn, and keyless_enforcement_level=enforce would refuse it: plan that source too with 'warden cred source keyless-plan'")
		}
	}
	return plan, nil
}

// checkProposedSpec records blockers for a proposed spec: a name that cannot
// be created or is already taken, a config that would not validate against the
// proposed source, or a secret still stored. validate is false while an input
// is missing, which already blocks the plan and which the validator would only
// report again.
func (c *Core) checkProposedSpec(ctx context.Context, plan *KeylessPlan, spec *credential.CredSpec, source *credential.CredSource, validate bool) error {
	checkProposedName(plan, "spec", spec.Name)
	switch _, err := c.credConfigStore.GetSpec(ctx, spec.Name); {
	case err == nil:
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("a credential spec named %q already exists; pass another name", spec.Name))
	case !errors.Is(err, ErrSpecNotFound):
		return err
	}
	if validate {
		if err := c.credConfigStore.validateSpecWithSource(ctx, spec, source, true); err != nil {
			plan.Blockers = append(plan.Blockers, fmt.Sprintf("spec %q would not validate: %s", spec.Name, err.Error()))
		}
	}
	if left := c.specStoredSecrets(spec.Type, spec.Config); len(left) > 0 {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("spec %q would still store %s", spec.Name, strings.Join(left, ", ")))
	}
	return nil
}

// keylessSourceTypesFor names the source types a local spec can move to: those
// whose specs are of its type by default, which hold nothing of their own, and
// on which the type accepts the spec in chained form — its stored secrets
// removed and a secret_spec set. The last condition is what keeps out a source
// that serves the type by minting rather than by fetching (an elastic source
// mints api_key credentials but refuses a spec-level secret_spec). A source that
// needs more than that, such as a mint_method a local spec never carries, is
// left out too: the message then stays generic rather than pointing somewhere
// the spec cannot go as it is. Sorted, so the message is stable.
func (c *Core) keylessSourceTypesFor(spec *credential.CredSpec) []string {
	if c.credentialDriverRegistry == nil || c.credentialTypeRegistry == nil {
		return nil
	}
	credType, err := c.credentialTypeRegistry.GetByName(spec.Type)
	if err != nil {
		return nil
	}
	// The chained form carries none of the credential itself: not the secrets,
	// and not the identifiers beside them (an R2 access_key_id, a Scaleway
	// access_key), which a chained spec gets from the referenced one too.
	chained := spec.Config
	for _, field := range credType.StoredSecrets(spec.Config) {
		chained = chained.With(field, "")
	}
	for field := range credType.FieldSchemas() {
		chained = chained.With(field, "")
	}
	chained = freshConfig(chained.With(credential.ConfigSecretSpec, "the-spec-that-reads-it"))

	var homes []string
	for _, sourceType := range c.credentialDriverRegistry.ListFactories() {
		if sourceType == credential.SourceTypeLocal {
			continue
		}
		factory, err := c.credentialDriverRegistry.GetFactory(sourceType)
		if err != nil {
			continue
		}
		inferred, err := factory.InferCredentialType(credential.Config{})
		if err != nil || inferred != spec.Type || len(factory.StoredSecrets(credential.Config{})) > 0 {
			continue
		}
		if credType.ValidateConfig(chained, sourceType) != nil {
			continue
		}
		homes = append(homes, sourceType)
	}
	sort.Strings(homes)
	return homes
}

// credentialNameRE is the name the create routes accept.
var credentialNameRE = regexp.MustCompile("^" + framework.GenericNameRegex("name") + "$")

// checkProposedName records a blocker for a name no create route would match:
// the create would miss its route rather than fail validation.
func checkProposedName(plan *KeylessPlan, kind, name string) {
	if !credentialNameRE.MatchString(name) {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf(
			"%q is not a valid credential %s name: use letters, digits, '-', '_' and '.', starting and ending with a letter or digit", name, kind))
	}
}

// checkTargetInputs refuses target inputs that set a secret field, or that set
// "name", which names a proposed spec among per-spec inputs but is new_name
// for the target.
func checkTargetInputs(inputs map[string]string, sensitive []string) error {
	if _, ok := inputs[nameInput]; ok {
		return logical.ErrBadRequest(`target sets "name"; name the proposed object with new_name`)
	}
	return refuseSecretInputs(inputs, sensitive, "target")
}

func specObject(spec *credential.CredSpec, replaces, behaviour string, choices []string) KeylessObject {
	return KeylessObject{
		Name:      spec.Name,
		Type:      spec.Type,
		Source:    spec.Source,
		Replaces:  replaces,
		Config:    spec.Config.Map(),
		MinTTL:    int64(spec.MinTTL.Seconds()),
		MaxTTL:    int64(spec.MaxTTL.Seconds()),
		Behaviour: behaviour,
		Choices:   choices,
	}
}

// proposedName is the operator's name for a proposed object, or the replaced
// object's name with the keyless suffix.
func proposedName(requested, replaced string) string {
	if requested != "" {
		return requested
	}
	return replaced + keylessNameSuffix
}

// freshConfig drops the keys a delta emptied. The proposed objects are created,
// not updated, so a removed key is simply absent.
func freshConfig(cfg credential.Config) credential.Config {
	out := make(map[string]string, cfg.Len())
	for k, v := range cfg.All() {
		if v != "" {
			out[k] = v
		}
	}
	return credential.NewConfig(out)
}

// refuseSecretInputs rejects plan inputs that set a secret field. A plan is
// returned as it was asked for, so a secret passed in would be echoed back in
// the clear, and a keyless object never needs one. ca_data is masked for
// tidiness, not because it is secret, so it may be passed.
func refuseSecretInputs(inputs map[string]string, sensitive []string, what string) error {
	for _, key := range sensitive {
		if key == "ca_data" {
			continue
		}
		if inputs[key] != "" {
			return logical.ErrBadRequestf("%s input %q is a secret field; a keyless object never sets one", what, key)
		}
	}
	return nil
}

// specSensitiveFields returns the keys of inputs a credential type masks, as a
// read would decide them: a type whose specs carry operator-declared fields
// masks any it does not know, since it cannot tell whether one is a secret.
func (c *Core) specSensitiveFields(specType string, inputs map[string]string) []string {
	if c.credentialTypeRegistry == nil {
		return nil
	}
	credType, err := c.credentialTypeRegistry.GetByName(specType)
	if err != nil {
		return nil
	}
	if dynamic, ok := credType.(credential.ConfigSensitivity); ok {
		return dynamic.SensitiveConfigFieldsFor(credential.NewConfig(inputs))
	}
	return credType.SensitiveConfigFields()
}

// trustEnv returns what the issuer contributes to rendered prerequisites, and
// whether the keyless config federates. env is nil when the issuer is off.
func (c *Core) trustEnv(ctx context.Context, keyless credential.Config) (env *credential.TrustEnv, federated bool) {
	federated = isFederationSource(keyless)
	issuer := c.OIDCIssuer()
	if issuer == nil || issuer.IssuerURL() == "" {
		return nil, federated
	}
	nsID, nsPath := namespace.RootNamespaceID, ""
	if ns, err := namespace.FromContext(ctx); err == nil {
		nsID, nsPath = ns.ID, ns.Path
	}
	issuerURL := strings.TrimRight(issuer.IssuerURL(), "/")
	return &credential.TrustEnv{
		IssuerURL:      issuerURL,
		JWKSURL:        issuerOrigin(issuerURL) + "/oidc/jwks",
		SubjectPrefix:  "wid:" + nsID + ":",
		NamespaceClaim: credential.NamespaceClaim(nsPath),
	}, federated
}

// issuerOrigin returns scheme://host of the issuer URL. Discovery and the key
// set are served at the origin root, whatever path issuer_url carries.
func issuerOrigin(issuerURL string) string {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Host == "" {
		return issuerURL
	}
	return u.Scheme + "://" + u.Host
}

// issuerPathNote warns when issuer_url carries a path: upstreams that look for
// discovery under the issuer URL will not find it, since it is served at the
// origin root.
func issuerPathNote(env *credential.TrustEnv) string {
	if env == nil || issuerOrigin(env.IssuerURL) == env.IssuerURL {
		return ""
	}
	return "issuer_url " + env.IssuerURL + " has a path, but discovery is served at " + issuerOrigin(env.IssuerURL) +
		"/.well-known/openid-configuration. Upstreams that read discovery under the issuer URL (AWS, Azure, GCP, " +
		"Kubernetes, Alibaba Cloud) will not find it: set issuer_url without a path, or serve discovery at that path from your proxy."
}
