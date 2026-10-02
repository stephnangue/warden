package core

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// putLegacySkill writes a record straight to storage, bypassing validation,
// so tests can stage names the current rule rejects.
func putLegacySkill(t *testing.T, store *SkillStore, ctx context.Context, skill *Skill) {
	t.Helper()
	if skill.Version == 0 {
		skill.Version = 1
	}
	data, err := json.Marshal(&storedSkill{Version: 1, Skill: skill})
	require.NoError(t, err)
	require.NoError(t, store.storage.Put(ctx, &sdklogical.StorageEntry{Key: skill.Name, Value: data}))
}

func legacySkill(name string, requires ...string) *Skill {
	s := validSkill(name)
	s.Requires = requires
	s.Origin = SkillOriginSeed
	return s
}

func TestSkillStore_MigrateSkillNames_RenamesAndRewritesRequires(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	putLegacySkill(t, store, ctx, legacySkill("mcp_aws"))
	putLegacySkill(t, store, ctx, legacySkill("ansible_tower", "mcp_aws"))
	putLegacySkill(t, store, ctx, legacySkill("runbook", "ansible_tower", "vault"))
	putLegacySkill(t, store, ctx, legacySkill("vault"))

	require.NoError(t, store.MigrateSkillNames(ctx))

	for _, gone := range []string{"mcp_aws", "ansible_tower"} {
		_, err := store.Get(ctx, gone)
		assert.True(t, errors.Is(err, ErrSkillNotFound), "%s should be gone, got %v", gone, err)
	}
	mcpAWS, err := store.Get(ctx, "mcp-aws")
	require.NoError(t, err)
	assert.Equal(t, "mcp-aws", mcpAWS.Name)
	assert.Equal(t, 2, mcpAWS.Version)

	tower, err := store.Get(ctx, "ansible-tower")
	require.NoError(t, err)
	assert.Equal(t, []string{"mcp-aws"}, tower.Requires)

	runbook, err := store.Get(ctx, "runbook")
	require.NoError(t, err)
	assert.Equal(t, []string{"ansible-tower", "vault"}, runbook.Requires)
	assert.Equal(t, 2, runbook.Version)

	vault, err := store.Get(ctx, "vault")
	require.NoError(t, err)
	assert.Equal(t, 1, vault.Version, "an untouched skill keeps its version")
}

func TestSkillStore_MigrateSkillNames_SkipsCollisionAndInvalid(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	putLegacySkill(t, store, ctx, legacySkill("my_skill"))
	other := legacySkill("my-skill")
	other.Body = "# a different skill\n"
	putLegacySkill(t, store, ctx, other)
	putLegacySkill(t, store, ctx, legacySkill("bad__name"))

	require.NoError(t, store.MigrateSkillNames(ctx))

	kept, err := store.Get(ctx, "my_skill")
	require.NoError(t, err, "a clashing skill stays under its old name")
	assert.Equal(t, "# body\n", kept.Body)
	taken, err := store.Get(ctx, "my-skill")
	require.NoError(t, err)
	assert.Equal(t, "# a different skill\n", taken.Body)
	_, err = store.Get(ctx, "bad__name")
	require.NoError(t, err, "a name that stays invalid after hyphenation is left alone")
}

// A run interrupted after writing the new record but before deleting the old
// one is completed by the next run.
func TestSkillStore_MigrateSkillNames_CompletesInterruptedRun(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	putLegacySkill(t, store, ctx, legacySkill("mcp_aws"))
	putLegacySkill(t, store, ctx, legacySkill("mcp-aws"))

	require.NoError(t, store.MigrateSkillNames(ctx))

	_, err := store.Get(ctx, "mcp_aws")
	assert.True(t, errors.Is(err, ErrSkillNotFound), "got %v", err)
	_, err = store.Get(ctx, "mcp-aws")
	require.NoError(t, err)
}

func TestSkillStore_MigrateSkillNames_RunsOnce(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	require.NoError(t, store.MigrateSkillNames(ctx))

	// A legacy record written after the marker is not touched.
	putLegacySkill(t, store, ctx, legacySkill("late_skill"))
	require.NoError(t, store.MigrateSkillNames(ctx))

	_, err := store.Get(ctx, "late_skill")
	require.NoError(t, err)

	skills, err := store.List(ctx)
	require.NoError(t, err)
	for _, s := range skills {
		assert.NotEqual(t, "names-agentskills", s.Name, "the marker must not surface as a skill")
	}
}

func TestSkillStore_MigrateSkillNames_ClosedStoreReturnsError(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	_ = store.Close()
	assert.ErrorIs(t, store.MigrateSkillNames(ctx), ErrSkillStoreClosed)
}
