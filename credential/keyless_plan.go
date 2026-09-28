package credential

// KeylessPlanner is implemented by the factory of a source type that can hold
// a secret and has a keyless form: federation, where the source presents a
// caller's identity assertion, or credential chaining, where a referenced spec
// supplies the secret per request.
//
// A plan only describes. It never writes: the operator creates the keyless
// source and specs it proposes next to the keyed ones, points roles at them,
// and deletes the keyed ones once they work — which keeps the keyed objects as
// the rollback until then. Planning works from configs alone, with no driver
// instance and no upstream call, and what it proposes is checked by the same
// validation every write goes through, so a delta that misses a field shows as
// a blocker rather than as a config that fails at create.
type KeylessPlanner interface {
	// PlanKeyless returns the delta that turns a keyed source config, current,
	// into its keyless form, given the operator's inputs. A value of "" in the
	// delta removes that key.
	PlanKeyless(current Config, inputs map[string]string) (*KeylessSourcePlan, error)

	// PlanKeylessSpec returns the delta for one spec of the source, whose keyed
	// config is current and keyless config is keyless. specType is the spec's
	// credential type. A spec with no keyless form reports a Blocker.
	PlanKeylessSpec(specType string, spec, current, keyless Config, inputs map[string]string) (*KeylessSpecPlan, error)

	// KeylessPrerequisites renders what the upstream must be configured with
	// before the keyless source can work: the trust it has to place in the
	// issuer, per target the specs name. It reads configs and env only.
	KeylessPrerequisites(keyless Config, specs []PlannedSpec, env TrustEnv) []Prerequisite
}

// StoredSecretSealedRefreshToken is what a connect-gated type's StoredSecrets
// reports for the refresh token its connect flow will seal: not a config key an
// operator can clear, and with no keyless form.
const StoredSecretSealedRefreshToken = "refresh_token (sealed by connect)"

// KeylessSourcePlan is a source's part of a keyless plan.
type KeylessSourcePlan struct {
	// Delta is applied over the keyed config; "" removes a key.
	Delta map[string]string

	// NeedsInput names inputs the operator must supply, such as a JWT role or
	// a workload identity provider.
	NeedsInput []string

	// Leftovers are the credentials the keyed source holds, which stay live
	// upstream until deleted there.
	Leftovers []Leftover

	// Notes are behaviour differences the operator should know about.
	Notes []string
}

// KeylessSpecPlan is one spec's part of a keyless plan.
type KeylessSpecPlan struct {
	// Delta is applied over the keyed spec's config; "" removes a key.
	Delta map[string]string

	// NeedsInput names per-spec inputs the operator must supply.
	NeedsInput []string

	// Blocker, when set, says why this spec has no keyless form.
	Blocker string

	// Behaviour describes what the keyless spec does differently.
	Behaviour string

	// Choices lists alternatives the operator may pick through the "choice"
	// input; the first is the default.
	Choices []string

	// Leftovers are credentials the keyed spec itself holds.
	Leftovers []Leftover
}

// PlannedSpec is a spec in its proposed keyless form, for rendering
// prerequisites.
type PlannedSpec struct {
	Name   string
	Type   string
	Config Config
}

// TrustEnv is what the issuer side contributes to rendered prerequisites.
type TrustEnv struct {
	// IssuerURL and JWKSURL are Warden's OIDC issuer and key set.
	IssuerURL string
	JWKSURL   string

	// SubjectPrefix is the fixed start of every subject this namespace's
	// agents present, "wid:<namespace>:"; the mount and principal follow.
	SubjectPrefix string
}

// Prerequisite is one piece of upstream configuration a keyless source needs.
type Prerequisite struct {
	// Title says what it is, e.g. "Trust policy".
	Title string `json:"title"`

	// Where names the upstream object it applies to, e.g. "IAM role DeployRole".
	Where string `json:"where"`

	// Format is "json", "shell", "yaml" or "text".
	Format string `json:"format"`

	// Body is the rendered snippet.
	Body string `json:"body"`
}

// Leftover is a credential the keyed objects hold that the keyless ones do not
// use. Nothing deletes it automatically.
type Leftover struct {
	// Kind says what it is, e.g. "access key".
	Kind string `json:"kind"`

	// ID identifies it without revealing it, e.g. an access key id.
	ID string `json:"id"`

	// WhereToDelete says where an operator deletes it.
	WhereToDelete string `json:"where_to_delete"`
}
