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
requires: [warden-shared, troubleshooting]
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
	if skill.Requires[0] != "warden-shared" || skill.Requires[1] != "troubleshooting" {
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
	// Expected foundation set: discovery, warden-shared, troubleshooting.
	names := make([]string, 0, len(skills))
	for _, s := range skills {
		names = append(names, s.Name)
		if err := validateSkill(s); err != nil {
			t.Errorf("validateSkill(%q): %v", s.Name, err)
		}
	}
	sort.Strings(names)
	want := []string{"discovery", "troubleshooting", "warden-shared"}
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
	for _, want := range []string{"discovery", "warden-shared", "troubleshooting"} {
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
	first, err := store.Get(ctx, "discovery")
	if err != nil {
		t.Fatalf("Get discovery: %v", err)
	}

	// Second call must be a no-op (marker short-circuits).
	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("second SeedFoundation: %v", err)
	}
	second, err := store.Get(ctx, "discovery")
	if err != nil {
		t.Fatalf("Get discovery (second): %v", err)
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
	if err := store.Delete(ctx, "discovery"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// The marker is set, so a second seed must NOT revive discovery.
	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("second SeedFoundation: %v", err)
	}
	_, err := store.Get(ctx, "discovery")
	if !errors.Is(err, ErrSkillNotFound) {
		t.Errorf("Get(discovery) = %v, want ErrSkillNotFound (deletion must persist across seed)", err)
	}
}

func TestSkillStore_SeedFoundation_PreservesOperatorEdits(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("first SeedFoundation: %v", err)
	}
	if _, err := store.Update(ctx, "discovery", &Skill{Description: "edited"}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if err := store.SeedFoundation(ctx); err != nil {
		t.Fatalf("second SeedFoundation: %v", err)
	}
	got, err := store.Get(ctx, "discovery")
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
