package anthropic

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	profileKey  = "anthropic_user_profile_id"
	profileID   = "uprof_011CZkZCu8hGbp5mYRQgUmz9"
	profileBeta = "user-profiles-2026-09-04"
)

// profiledMount is the state of a mount attributing requests from profileKey.
func profiledMount(t *testing.T) map[string]any {
	t.Helper()
	return mustWrite(t, map[string]any{}, map[string]any{
		"beta_required":             profileBeta,
		"user_profile_metadata_key": profileKey,
	})
}

// asUser returns a request carrying an api_key credential made on behalf of a
// user whose verified token metadata is meta. A nil meta means no user at all.
func asUser(meta map[string]string) *logical.Request {
	req := betaRequest()
	if meta != nil {
		req.User = &logical.UserPrincipal{TokenEntry: &logical.TokenEntry{Metadata: meta}}
	}
	return req
}

func profileSent(t *testing.T, state map[string]any, req *logical.Request) (string, bool) {
	t.Helper()
	headers, err := extractorFor(t, state)(req)
	require.NoError(t, err)
	v, ok := headers["anthropic-user-profile-id"]
	return v, ok
}

func TestProfile_SentFromUserMetadata(t *testing.T) {
	got, sent := profileSent(t, profiledMount(t), asUser(map[string]string{profileKey: profileID}))
	assert.True(t, sent)
	assert.Equal(t, profileID, got)
}

// A mount that has not named a key attributes no one, whatever the user's
// metadata happens to hold.
func TestProfile_NotSentWhenKeyUnset(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_required": profileBeta})
	_, sent := profileSent(t, state, asUser(map[string]string{profileKey: profileID}))
	assert.False(t, sent)
}

// The agent's metadata is never a source. It is the tempting fallback when a
// request carries no user, and the wrong one: it would attribute the agent's own
// traffic to an end user's profile — and the grants that come with it — whenever
// the agent's role mapped the same key. So an agent holding a perfectly valid
// profile id, on a request with no user, still sends none.
func TestProfile_NeverTakenFromTheAgent(t *testing.T) {
	req := asUser(nil)
	req.TokenMetadata = map[string]string{profileKey: profileID}

	_, sent := profileSent(t, profiledMount(t), req)
	assert.False(t, sent)
}

func TestProfile_UserWithoutTokenEntry(t *testing.T) {
	req := betaRequest()
	req.User = &logical.UserPrincipal{}
	_, sent := profileSent(t, profiledMount(t), req)
	assert.False(t, sent)
}

// A metadata key that is named on the mount but absent for this user is
// ordinary — a claim the identity provider did not issue is skipped at login,
// not refused. The request goes ahead unattributed.
func TestProfile_MissingFromMetadata(t *testing.T) {
	_, sent := profileSent(t, profiledMount(t), asUser(map[string]string{"team": "platform"}))
	assert.False(t, sent)
}

// Anything that is not a profile id is dropped. A line break matters most: the
// value comes from an identity-provider claim, and must not reach a header.
func TestProfile_ValueThatIsNotAProfileIsDropped(t *testing.T) {
	for name, v := range map[string]string{
		"no prefix":      "user-12345",
		"bare prefix":    "uprof_",
		"prefix mid-way": "x-uprof_011C",
		"line break":     "uprof_011C\r\nx-injected: 1",
		"inner space":    "uprof_011C Z",
		"empty":          "",
	} {
		_, sent := profileSent(t, profiledMount(t), asUser(map[string]string{profileKey: v}))
		assert.False(t, sent, name)
	}
}

// Attribution is independent of how the mount authenticates.
func TestProfile_SentWithBearerCredential(t *testing.T) {
	req := asUser(map[string]string{profileKey: profileID})
	req.Credential = &credential.Credential{
		Type: credential.TypeOAuthBearerToken,
		Data: map[string]string{"api_key": notARealKey},
	}
	headers, err := extractorFor(t, profiledMount(t))(req)
	require.NoError(t, err)
	assert.Equal(t, profileID, headers["anthropic-user-profile-id"])
	assert.Equal(t, "Bearer "+notARealKey, headers["Authorization"])
}

// The beta the upstream requires for the header is sent with it.
func TestProfile_BetaSentAlongside(t *testing.T) {
	headers, err := extractorFor(t, profiledMount(t))(asUser(map[string]string{profileKey: profileID}))
	require.NoError(t, err)
	assert.Equal(t, profileBeta, headers["anthropic-beta"])
}

// ---- pairing ----

// A key with no beta enabling the header would attribute nothing while reading
// as configured.
func TestPairing_KeyRequiresProfileBeta(t *testing.T) {
	_, err := write(map[string]any{}, map[string]any{"user_profile_metadata_key": profileKey})
	assert.ErrorContains(t, err, "user-profiles-")

	_, err = write(map[string]any{}, map[string]any{
		"user_profile_metadata_key": profileKey,
		"beta_required":             "context-management-2025-06-27",
	})
	assert.ErrorContains(t, err, "user-profiles-", "some other beta does not enable the header")
}

// A name that only starts like the family is not a member. It would pass a prefix
// check and then be refused upstream on every request, attributing no one.
func TestPairing_UndatedProfileBetaRefused(t *testing.T) {
	for _, b := range []string{"user-profiles-", "user-profiles-x", "user-profiles-2026-09", "user-profiles-2026-09-04x"} {
		_, err := write(map[string]any{}, map[string]any{
			"user_profile_metadata_key": profileKey,
			"beta_required":             b,
		})
		assert.ErrorContains(t, err, "user-profiles-YYYY-MM-DD", b)
	}
}

// Every dated version of the beta is accepted; the mount checks the family.
func TestPairing_AnyDatedProfileBeta(t *testing.T) {
	for _, b := range []string{"user-profiles-2026-03-24", "user-profiles-2026-08-18", "user-profiles-2026-09-04"} {
		_, err := write(map[string]any{}, map[string]any{
			"user_profile_metadata_key": profileKey,
			"beta_required":             b,
		})
		assert.NoError(t, err, b)
	}
}

// The pairing holds across partial writes. Writes carry only the fields that
// change, so a later write dropping the beta — and naming nothing about the
// profile — must be checked against the key already in force.
func TestPairing_CheckedOverMergedState(t *testing.T) {
	state := profiledMount(t)
	_, err := write(state, map[string]any{"beta_required": ""})
	assert.ErrorContains(t, err, "user-profiles-")

	// Clearing the key and the beta together is fine.
	_, err = write(state, map[string]any{"beta_required": "", "user_profile_metadata_key": ""})
	assert.NoError(t, err)
}

// An empty key disables attribution and needs no beta.
func TestPairing_EmptyKeyDisables(t *testing.T) {
	state := mustWrite(t, profiledMount(t), map[string]any{"user_profile_metadata_key": "  "})
	_, sent := profileSent(t, state, asUser(map[string]string{profileKey: profileID}))
	assert.False(t, sent)
	assert.Equal(t, "", onConfigRead(state)["user_profile_metadata_key"])
}

func TestPairing_EnableTimeValidation(t *testing.T) {
	assert.ErrorContains(t, validateExtraConfig(map[string]any{"user_profile_metadata_key": profileKey}), "user-profiles-")
	assert.NoError(t, validateExtraConfig(map[string]any{
		"user_profile_metadata_key": profileKey,
		"beta_required":             profileBeta,
	}))
	assert.ErrorContains(t,
		validateExtraConfig(map[string]any{"user_profile_metadata_key": []any{profileKey}}),
		"must be a string")
}

// ---- persistence ----

func TestProfile_SurvivesRestart(t *testing.T) {
	reloaded := persistAndReload(t, profiledMount(t))
	got, sent := profileSent(t, reloaded, asUser(map[string]string{profileKey: profileID}))
	assert.True(t, sent)
	assert.Equal(t, profileID, got)
}

// A stored key without its beta cannot have come from a validated write; this
// guards storage edited by hand, or a later release checking more strictly.
// Failing closed means attributing no one as well as passing no client beta: a
// profile is sent only from a config known to be sound. The operator's own
// required betas still go, as they do whenever a stored config fails to load.
func TestProfile_UnpairedStoredConfigFailsClosed(t *testing.T) {
	state := onInitialize(map[string]any{
		"user_profile_metadata_key": profileKey,
		"beta_required":             "context-management-2025-06-27",
	}, map[string]any{})
	req := asUser(map[string]string{profileKey: profileID})
	req.HTTPRequest.Header.Add("anthropic-beta", "a-2026-01-01")

	headers, err := extractorFor(t, state)(req)
	require.NoError(t, err)
	assert.NotContains(t, headers, "anthropic-user-profile-id")
	assert.Equal(t, "context-management-2025-06-27", headers["anthropic-beta"],
		"the client's beta is dropped, the operator's kept")
}
