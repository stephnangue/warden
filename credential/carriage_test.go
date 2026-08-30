package credential

import (
	"fmt"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// carriageParser builds a parser over a lenient mock type — one whose Parse
// copies every string key it is handed, like the real key_value type. That
// leniency is what makes the stripping tests meaningful: if the reserved key were
// still in rawData when Parse ran, it would land in the credential's Data.
func carriageParser(t *testing.T) *CredentialParser {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	reg := NewTypeRegistry()
	require.NoError(t, reg.Register(newMockCredentialType(TypeVaultToken, CategoryAPI)))
	return NewCredentialParser(reg, log)
}

// strictCarriageType copies only its primary field, like BaseTokenType. The
// lenient mock cannot show what carriage did and did not add, since its Parse
// copies everything in rawData; anything reaching Data under this type came from
// carriage.
type strictCarriageType struct{ *mockCredentialType }

func (t strictCarriageType) Parse(rawData, _ map[string]interface{}, leaseTTL time.Duration, leaseID string) (*Credential, error) {
	token, _ := rawData["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("%w: missing token", ErrInvalidCredential)
	}
	return &Credential{
		Type:     t.name,
		Category: t.category,
		LeaseTTL: leaseTTL,
		LeaseID:  leaseID,
		IssuedAt: time.Now(),
		Data:     map[string]string{"token": token},
	}, nil
}

func strictCarriageParser(t *testing.T) *CredentialParser {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	reg := NewTypeRegistry()
	require.NoError(t, reg.Register(strictCarriageType{newMockCredentialType(TypeVaultToken, CategoryAPI)}))
	return NewCredentialParser(reg, log)
}

func carriageSpec() *CredSpec {
	return &CredSpec{Name: "spec", Type: TypeVaultToken, Source: "src"}
}

func carriageDriver(driverType string) *mockSourceDriver {
	return newMockSourceDriverFactory(driverType).driver
}

// TestCarriage_DeclaredFieldReachesData is the mechanism working: the apikey
// driver names what it resolved, and those fields become credential data.
func TestCarriage_DeclaredFieldReachesData(t *testing.T) {
	rawData := map[string]interface{}{
		"token":             "the-secret",
		"application_key":   "app-key",
		"email":             "svc@corp.com",
		RawAdjunctFieldsKey: "application_key,email",
	}

	// Strict, so anything beyond the primary field can only have come from
	// carriage. Under the lenient type this would pass with carriage deleted.
	cred, err := strictCarriageParser(t).ParseAndValidate(
		t.Context(), carriageSpec(), rawData, nil, 0, "", carriageDriver(SourceTypeAPIKey))
	require.NoError(t, err)

	assert.Equal(t, "app-key", cred.Data["application_key"])
	assert.Equal(t, "svc@corp.com", cred.Data["email"])
	assert.NotContains(t, cred.Data, RawAdjunctFieldsKey, "the declaration is plumbing, not a credential field")
}

// TestCarriage_ForgedDeclarationFromAnotherDriverIsIgnored is the security
// property of the whole mechanism.
//
// The vault and aws drivers return fetched secret payloads verbatim, so this key
// can arrive from someone's stored secret rather than from Warden. Honouring it
// there would let whoever writes that secret decide what becomes credential data
// — and would reopen the route deliberately left unsupported, where a Vault
// secret's fields cannot be carried because nothing declares them.
//
// It must also be stripped, not merely disregarded: the lenient type here would
// otherwise copy the key itself into Data.
func TestCarriage_ForgedDeclarationFromAnotherDriverIsIgnored(t *testing.T) {
	for _, driverType := range []string{SourceTypeVault, SourceTypeLocal, SourceTypeAWS} {
		t.Run(driverType, func(t *testing.T) {
			rawData := func() map[string]interface{} {
				return map[string]interface{}{
					"token":             "the-secret",
					"owner":             "someone",
					"application_key":   "app-key",
					RawAdjunctFieldsKey: "application_key,owner",
				}
			}

			// Under a strict type, anything beyond the primary field in Data can
			// only have come from carriage — so this is what shows the forged
			// declaration was disregarded, not merely deleted.
			strict := rawData()
			cred, err := strictCarriageParser(t).ParseAndValidate(
				t.Context(), carriageSpec(), strict, nil, 0, "", carriageDriver(driverType))
			require.NoError(t, err)
			assert.NotContains(t, cred.Data, "application_key",
				"a declaration from a driver that does not own credential_fields must not be honoured")
			assert.NotContains(t, cred.Data, "owner")
			assert.Len(t, cred.Data, 1)

			// Under a lenient type — key_value's shape — the key must also be gone
			// from rawData before Parse runs, or Parse copies it into Data itself.
			lenient := rawData()
			cred, err = carriageParser(t).ParseAndValidate(
				t.Context(), carriageSpec(), lenient, nil, 0, "", carriageDriver(driverType))
			require.NoError(t, err)
			assert.NotContains(t, cred.Data, RawAdjunctFieldsKey,
				"the reserved key must be stripped whatever the driver, or a lenient Parse copies it")
			assert.NotContains(t, lenient, RawAdjunctFieldsKey, "stripped from rawData itself")
		})
	}
}

// TestCarriage_ReservedNamesAreNeverCarried holds the denylist at mint time, not
// only at config-write time: a source stored before the check existed, or edited
// around it, must still not be able to move a mint locator into credential data
// where a provider reading that field name would send it upstream.
func TestCarriage_ReservedNamesAreNeverCarried(t *testing.T) {
	rawData := map[string]interface{}{
		"token":             "the-secret",
		"secret_path":       "apikeys/prod",
		ConfigSecretSpec:    "another-spec",
		"__something":       "internal",
		RawAdjunctFieldsKey: "secret_path," + ConfigSecretSpec + ",__something",
	}

	cred, err := strictCarriageParser(t).ParseAndValidate(
		t.Context(), carriageSpec(), rawData, nil, 0, "", carriageDriver(SourceTypeAPIKey))
	require.NoError(t, err)

	assert.NotContains(t, cred.Data, "secret_path")
	assert.NotContains(t, cred.Data, ConfigSecretSpec)
	assert.NotContains(t, cred.Data, "__something")
}

// TestCarriage_NeverOverwritesWhatParseProduced protects the primary field above
// all: a declaration naming it must not be able to replace the credential's own
// secret with some other value from rawData.
func TestCarriage_NeverOverwritesWhatParseProduced(t *testing.T) {
	// The two values must differ, or the assertion holds whether carriage skips
	// the field or overwrites it with an identical string.
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	reg := NewTypeRegistry()
	require.NoError(t, reg.Register(rewritingCarriageType{newMockCredentialType(TypeVaultToken, CategoryAPI)}))

	rawData := map[string]interface{}{
		"token":             "raw-value",
		RawAdjunctFieldsKey: "token",
	}

	cred, err := NewCredentialParser(reg, log).ParseAndValidate(
		t.Context(), carriageSpec(), rawData, nil, 0, "", carriageDriver(SourceTypeAPIKey))
	require.NoError(t, err)
	assert.Equal(t, "parsed-value", cred.Data["token"],
		"a declaration naming a field the type produced must not replace it")
}

// rewritingCarriageType produces a value of its own rather than echoing rawData,
// so a carriage overwrite is visible.
type rewritingCarriageType struct{ *mockCredentialType }

func (t rewritingCarriageType) Parse(_, _ map[string]interface{}, leaseTTL time.Duration, leaseID string) (*Credential, error) {
	return &Credential{
		Type:     t.name,
		Category: t.category,
		LeaseTTL: leaseTTL,
		LeaseID:  leaseID,
		IssuedAt: time.Now(),
		Data:     map[string]string{"token": "parsed-value"},
	}, nil
}

// A declared field that resolved to nothing is skipped rather than written empty.
// An empty credential field is worse than an absent one: a provider reading it
// builds a malformed header instead of taking its fallback branch.
func TestCarriage_AbsentOrEmptyDeclaredFieldIsSkipped(t *testing.T) {
	rawData := map[string]interface{}{
		"token":             "the-secret",
		"blank":             "",
		RawAdjunctFieldsKey: "blank,never_resolved",
	}

	cred, err := strictCarriageParser(t).ParseAndValidate(
		t.Context(), carriageSpec(), rawData, nil, 0, "", carriageDriver(SourceTypeAPIKey))
	require.NoError(t, err)

	assert.NotContains(t, cred.Data, "blank")
	assert.NotContains(t, cred.Data, "never_resolved")
}

// Without a declaration nothing changes, which is what every existing credential
// type and driver relies on.
func TestCarriage_NoDeclarationLeavesParseUntouched(t *testing.T) {
	rawData := map[string]interface{}{"token": "the-secret", "extra": "value"}

	cred, err := carriageParser(t).ParseAndValidate(
		t.Context(), carriageSpec(), rawData, nil, 0, "", carriageDriver(SourceTypeAPIKey))
	require.NoError(t, err)

	// The lenient mock type copies everything, so "extra" is here because Parse
	// put it there — not because carriage did.
	assert.Equal(t, "value", cred.Data["extra"])
}

func TestIsReservedSpecConfigKey(t *testing.T) {
	reserved := []string{
		ConfigSecretSpec, ConfigSecretField, ConfigSecretCacheTTL,
		ConfigSubjectTokenSource, ConfigSubjectTokenType,
		ConfigActorTokenSource, ConfigActorTokenType,
		ConfigAssertionAudience, ConfigAssertionMetadataClaims,
		ConfigAssertionUserClaims, ConfigAssertionAlgorithm, ConfigAssertionResource,
		"mint_method", "kv2_mount", "secret_path", "secret_id", "role_arn",
		"version_stage", "version_id", "secret_version", "credential_type", "json_key_map",
		RawAdjunctFieldsKey, RawRotatedRefreshTokenKey, "__anything",
	}
	for _, k := range reserved {
		assert.True(t, IsReservedSpecConfigKey(k), "%q must be reserved", k)
	}

	for _, k := range []string{"api_key", "organization_id", "email", "application_key", "username"} {
		assert.False(t, IsReservedSpecConfigKey(k), "%q must not be reserved", k)
	}
}

func TestParseAdjunctNames(t *testing.T) {
	assert.Nil(t, ParseAdjunctNames(""))
	assert.Nil(t, ParseAdjunctNames("  ,, "))
	assert.Equal(t, []string{"a", "b"}, ParseAdjunctNames("a,b"))
	assert.Equal(t, []string{"a", "b"}, ParseAdjunctNames(" a , b "))
}

// TestUncarriedAdjunctFields covers the write-time guard that turns a field the
// source will not carry into a rejected spec rather than a credential quietly
// missing it — and distinguishes the two reasons, since only one of them has a
// fix the operator can apply to the source they already have.
func TestUncarriedAdjunctFields(t *testing.T) {
	carrier := stubAdjunctCarrier{fields: []string{"organization_id", "email"}}

	// An apikey source declaring nothing: fixable where it stands.
	fields, carriable := UncarriedAdjunctFields(carrier,
		map[string]string{"api_key": "k", "organization_id": "org", "email": "a@b.c"},
		map[string]string{}, SourceTypeAPIKey)
	assert.ElementsMatch(t, []string{"organization_id", "email"}, fields)
	assert.True(t, carriable)

	// Declared: carried, so not reported.
	fields, _ = UncarriedAdjunctFields(carrier,
		map[string]string{"api_key": "k", "organization_id": "org"},
		map[string]string{"credential_fields": "organization_id"}, SourceTypeAPIKey)
	assert.Empty(t, fields)

	// A source whose driver has no declaration mechanism cannot carry the field
	// however it is configured, so a declaration on it must not satisfy the check
	// — following that advice would change nothing and look like it had.
	for _, srcType := range []string{SourceTypeLocal, SourceTypeVault, SourceTypeAWS} {
		fields, carriable = UncarriedAdjunctFields(carrier,
			map[string]string{"api_key": "k", "organization_id": "org"},
			map[string]string{"credential_fields": "organization_id"}, srcType)
		assert.Equal(t, []string{"organization_id"}, fields, "source type %q", srcType)
		assert.False(t, carriable, "source type %q", srcType)
	}

	// Unset fields are not reported, and neither is a key the type does not know.
	fields, _ = UncarriedAdjunctFields(carrier,
		map[string]string{"api_key": "k", "some_other_key": "v"},
		map[string]string{}, SourceTypeAPIKey)
	assert.Empty(t, fields)

	// A type that does not carry adjuncts is left alone entirely.
	fields, carriable = UncarriedAdjunctFields(struct{}{},
		map[string]string{"organization_id": "org"}, map[string]string{}, SourceTypeLocal)
	assert.Nil(t, fields)
	assert.True(t, carriable)
}

type stubAdjunctCarrier struct{ fields []string }

func (s stubAdjunctCarrier) KnownAdjunctFields() []string { return s.fields }
