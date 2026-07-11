package core

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

func TestParseSkillMarkdown_Minimal(t *testing.T) {
	raw := []byte(`---
name: foo
description: "bar"
category: custom
---

body text
`)
	skill, err := parseSkillMarkdown(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skill.Name != "foo" {
		t.Errorf("Name = %q, want foo", skill.Name)
	}
	if skill.Description != "bar" {
		t.Errorf("Description = %q, want bar", skill.Description)
	}
	if skill.Category != "custom" {
		t.Errorf("Category = %q, want custom", skill.Category)
	}
	if !strings.Contains(skill.Body, "body text") {
		t.Errorf("Body missing body text, got %q", skill.Body)
	}
}

func TestParseSkillMarkdown_WithList(t *testing.T) {
	raw := []byte(`---
name: foo
description: "bar"
category: custom
requires: [foundation, troubleshooting]
upstream: example.com
---
body
`)
	skill, err := parseSkillMarkdown(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(skill.Requires) != 2 {
		t.Fatalf("Requires len = %d, want 2", len(skill.Requires))
	}
	if skill.Requires[0] != "foundation" || skill.Requires[1] != "troubleshooting" {
		t.Errorf("Requires = %v", skill.Requires)
	}
	if skill.Upstream != "example.com" {
		t.Errorf("Upstream = %q", skill.Upstream)
	}
}

func TestParseSkillMarkdown_UnquotedDescription(t *testing.T) {
	raw := []byte(`---
name: foo
description: bare value with spaces
category: shared
---
b
`)
	skill, err := parseSkillMarkdown(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skill.Description != "bare value with spaces" {
		t.Errorf("Description = %q", skill.Description)
	}
}

func TestParseSkillMarkdown_RejectsMissingDelimiter(t *testing.T) {
	raw := []byte(`name: foo
description: bar
category: custom
`)
	_, err := parseSkillMarkdown(raw)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "opening frontmatter") {
		t.Errorf("error %q does not mention opening frontmatter", err.Error())
	}
}

func TestParseSkillMarkdown_RejectsMissingClosingDelimiter(t *testing.T) {
	raw := []byte(`---
name: foo
description: bar
category: custom
`)
	_, err := parseSkillMarkdown(raw)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "closing frontmatter") {
		t.Errorf("error %q does not mention closing frontmatter", err.Error())
	}
}

func TestParseSkillMarkdown_TolerateUnknownKeys(t *testing.T) {
	raw := []byte(`---
name: foo
description: bar
category: shared
extra_field: ignored
another_unknown: 42
---
b
`)
	skill, err := parseSkillMarkdown(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skill.Name != "foo" {
		t.Errorf("Name = %q, want foo", skill.Name)
	}
	if skill.Description != "bar" {
		t.Errorf("Description = %q, want bar", skill.Description)
	}
}

func TestParseSkillMarkdown_EmptyList(t *testing.T) {
	raw := []byte(`---
name: foo
description: bar
category: shared
requires: []
---
b
`)
	skill, err := parseSkillMarkdown(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(skill.Requires) != 0 {
		t.Errorf("Requires = %v, want empty", skill.Requires)
	}
}

func TestParseSkillMarkdown_SingleQuotedDescription(t *testing.T) {
	raw := []byte(`---
name: foo
description: 'hello world'
category: shared
---
b
`)
	skill, err := parseSkillMarkdown(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skill.Description != "hello world" {
		t.Errorf("Description = %q, want hello world", skill.Description)
	}
}

func TestParseSkillMarkdown_BodyWithHorizontalRule(t *testing.T) {
	raw := []byte(`---
name: foo
description: bar
category: shared
---

# Section A

---

# Section B
`)
	skill, err := parseSkillMarkdown(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The body must include both sections — the second "---" is a markdown
	// horizontal rule, not a frontmatter delimiter.
	if !strings.Contains(skill.Body, "# Section A") {
		t.Errorf("Body missing Section A: %q", skill.Body)
	}
	if !strings.Contains(skill.Body, "# Section B") {
		t.Errorf("Body missing Section B: %q", skill.Body)
	}
}

func TestLoadEmbeddedFoundationSkills_ParsesAll(t *testing.T) {
	skills, err := loadEmbeddedFoundationSkills()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Expected foundation set: troubleshooting (foundation + discovery were
	// retired when discovery moved to the /v1/sys/mcp tools).
	names := make([]string, 0, len(skills))
	for _, s := range skills {
		names = append(names, s.Name)
		if err := validateSkill(s); err != nil {
			t.Errorf("validateSkill(%q): %v", s.Name, err)
		}
	}
	sort.Strings(names)
	want := []string{"troubleshooting"}
	if !equalStringSlices(names, want) {
		t.Errorf("foundation skill names = %v, want %v", names, want)
	}
}

func TestSkillStore_SeedFoundation_WritesAllSkills(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("SeedFoundation: %v", err)
	}

	skills, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := make(map[string]string, len(skills))
	for _, s := range skills {
		got[s.Name] = s.Origin
		if s.Version != 1 {
			t.Errorf("Version of %q = %d, want 1", s.Name, s.Version)
		}
		if s.Body == "" {
			t.Errorf("Body of %q is empty", s.Name)
		}
	}
	for _, want := range []string{"troubleshooting"} {
		if origin, ok := got[want]; !ok {
			t.Errorf("missing seeded skill %q", want)
		} else if origin != SkillOriginSeed {
			t.Errorf("Origin of %q = %q, want %q", want, origin, SkillOriginSeed)
		}
	}
}

func TestSkillStore_SeedFoundation_IsIdempotent(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("first SeedFoundation: %v", err)
	}
	first, err := store.Get(ctx, "troubleshooting")
	if err != nil {
		t.Fatalf("Get troubleshooting: %v", err)
	}

	// Second call must be a no-op (marker short-circuits).
	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("second SeedFoundation: %v", err)
	}
	second, err := store.Get(ctx, "troubleshooting")
	if err != nil {
		t.Fatalf("Get troubleshooting (second): %v", err)
	}
	if first.Version != second.Version {
		t.Errorf("Version changed across seed calls: %d -> %d", first.Version, second.Version)
	}
	if !first.UpdatedAt.Equal(second.UpdatedAt) {
		t.Errorf("UpdatedAt changed across seed calls: %v -> %v", first.UpdatedAt, second.UpdatedAt)
	}
}

func TestSkillStore_SeedFoundation_RespectsDeletion(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("first SeedFoundation: %v", err)
	}
	if err := store.Delete(ctx, "troubleshooting"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// The marker is set, so a second seed must NOT revive troubleshooting.
	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("second SeedFoundation: %v", err)
	}
	_, err := store.Get(ctx, "troubleshooting")
	if !errors.Is(err, ErrSkillNotFound) {
		t.Errorf("Get(troubleshooting) = %v, want ErrSkillNotFound (deletion must persist across seed)", err)
	}
}

func TestSkillStore_SeedFoundation_PreservesOperatorEdits(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("first SeedFoundation: %v", err)
	}
	if _, err := store.Update(ctx, "troubleshooting", &Skill{Description: "edited"}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("second SeedFoundation: %v", err)
	}
	got, err := store.Get(ctx, "troubleshooting")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Description != "edited" {
		t.Errorf("Description = %q, operator edit was clobbered", got.Description)
	}
}

func TestSkillStore_SeedFoundation_NotInitializedReturnsError(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	store.storage = nil

	err := store.SeedFoundation(ctx)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestSkillStore_SeedFoundation_ClosedStoreReturnsError(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	_ = store.Close()

	err := store.SeedFoundation(ctx)
	if !errors.Is(err, ErrSkillStoreClosed) {
		t.Errorf("err = %v, want ErrSkillStoreClosed", err)
	}
}

// providerSkillMD is the canonical fixture for SeedProviderSkill tests.
const providerSkillMD = `---
name: testprov
description: "fixture skill for tests"
category: provider-guide
provider: testprov
---

# Testprov

body content
`

func TestSkillStore_SeedProviderSkill_WritesSkillOnFirstCall(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedProviderSkill(ctx, "testprov", providerSkillMD); err != nil {
		t.Fatalf("SeedProviderSkill: %v", err)
	}

	got, err := store.Get(ctx, "testprov")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Origin != SkillOriginSeed {
		t.Errorf("Origin = %q, want seed", got.Origin)
	}
	if got.Category != SkillCategoryProviderGuide {
		t.Errorf("Category = %q, want provider-guide", got.Category)
	}
	if got.Provider != "testprov" {
		t.Errorf("Provider = %q, want testprov", got.Provider)
	}
	if !strings.Contains(got.Body, "body content") {
		t.Errorf("Body missing fixture text: %q", got.Body)
	}
}

func TestSkillStore_SeedProviderSkill_IdempotentOnReMount(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedProviderSkill(ctx, "testprov", providerSkillMD); err != nil {
		t.Fatalf("first SeedProviderSkill: %v", err)
	}
	first, err := store.Get(ctx, "testprov")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if err := store.SeedProviderSkill(ctx, "testprov", providerSkillMD); err != nil {
		t.Fatalf("second SeedProviderSkill: %v", err)
	}
	second, err := store.Get(ctx, "testprov")
	if err != nil {
		t.Fatalf("Get (second): %v", err)
	}
	if first.Version != second.Version {
		t.Errorf("Version changed across re-seed: %d -> %d", first.Version, second.Version)
	}
	if !first.UpdatedAt.Equal(second.UpdatedAt) {
		t.Errorf("UpdatedAt changed across re-seed: %v -> %v", first.UpdatedAt, second.UpdatedAt)
	}
}

func TestSkillStore_SeedProviderSkill_PreservesOperatorEdits(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedProviderSkill(ctx, "testprov", providerSkillMD); err != nil {
		t.Fatalf("SeedProviderSkill: %v", err)
	}
	if _, err := store.Update(ctx, "testprov", &Skill{Description: "operator override"}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Re-mount of same provider type must not clobber the operator's edit.
	if err := store.SeedProviderSkill(ctx, "testprov", providerSkillMD); err != nil {
		t.Fatalf("second SeedProviderSkill: %v", err)
	}
	got, err := store.Get(ctx, "testprov")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Description != "operator override" {
		t.Errorf("Description = %q, operator edit lost", got.Description)
	}
}

func TestSkillStore_SeedProviderSkill_ReSeedsAfterDeletion(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedProviderSkill(ctx, "testprov", providerSkillMD); err != nil {
		t.Fatalf("first SeedProviderSkill: %v", err)
	}
	if err := store.Delete(ctx, "testprov"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Deletion + new mount of same provider type re-seeds the skill.
	// (Unlike foundation skills, provider seeding has no sticky marker.)
	if err := store.SeedProviderSkill(ctx, "testprov", providerSkillMD); err != nil {
		t.Fatalf("second SeedProviderSkill: %v", err)
	}
	got, err := store.Get(ctx, "testprov")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "testprov" {
		t.Errorf("Name = %q, want testprov", got.Name)
	}
}

func TestSkillStore_SeedProviderSkill_RejectsInvalidMarkdown(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	cases := []struct {
		name     string
		provType string
		md       string
	}{
		{"missing opening delimiter", "foo", "name: foo\ndescription: bar\ncategory: shared\n"},
		{"missing closing delimiter", "foo", "---\nname: foo\ndescription: bar\ncategory: shared\n"},
		{"missing body", "ok", "---\nname: ok\ndescription: bar\ncategory: shared\n---\n"},
		{"provider-guide without provider", "gw", "---\nname: gw\ndescription: bar\ncategory: provider-guide\n---\n\nbody\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.SeedProviderSkill(ctx, tc.provType, tc.md)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

// TestSkillStore_SeedProviderSkill_RejectsNameMismatch verifies the new
// providerType-vs-skill.Name guard catches wire-up errors where the
// markdown's declared name does not match the registered provider type.
func TestSkillStore_SeedProviderSkill_RejectsNameMismatch(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	// providerSkillMD declares `name: testprov` — pass a different type.
	err := store.SeedProviderSkill(ctx, "wronglabel", providerSkillMD)
	if err == nil {
		t.Fatalf("expected name-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "does not match provider type") {
		t.Errorf("error %q does not mention mismatch", err.Error())
	}
	// And no skill should have been persisted.
	if _, err := store.Get(ctx, "testprov"); !errors.Is(err, ErrSkillNotFound) {
		t.Errorf("Get after rejected seed: got %v, want ErrSkillNotFound", err)
	}
}

func TestSkillStore_SeedProviderSkill_ClosedStoreReturnsError(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	_ = store.Close()

	err := store.SeedProviderSkill(ctx, "testprov", providerSkillMD)
	if !errors.Is(err, ErrSkillStoreClosed) {
		t.Errorf("err = %v, want ErrSkillStoreClosed", err)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
