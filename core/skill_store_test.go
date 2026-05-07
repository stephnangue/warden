package core

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stephnangue/warden/logger"
)

// setupTestSkillStore creates a SkillStore backed by an unsealed in-memory
// barrier — enough to exercise CRUD without spinning up a full Core.
func setupTestSkillStore(t *testing.T) (*SkillStore, context.Context) {
	t.Helper()

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	physical, _ := inmem.NewInmem(nil, nil)
	barrier, err := NewAESGCMBarrier(physical)
	if err != nil {
		t.Fatalf("create barrier: %v", err)
	}
	testKey, _ := barrier.GenerateKey(rand.Reader)
	if err := barrier.Initialize(context.Background(), testKey, nil, rand.Reader); err != nil {
		t.Fatalf("initialize barrier: %v", err)
	}
	if err := barrier.Unseal(context.Background(), testKey); err != nil {
		t.Fatalf("unseal barrier: %v", err)
	}

	core := &Core{
		barrier: barrier,
		logger:  log,
	}
	store := NewSkillStore(core)
	store.storage = NewBarrierView(barrier, skillStorePath)

	return store, context.Background()
}

// validSkill returns a fresh, schema-valid Skill suitable for CRUD tests.
func validSkill(name string) *Skill {
	return &Skill{
		Name:        name,
		Description: "test skill",
		Category:    SkillCategoryCustom,
		Body:        "# body\n",
	}
}

func TestSkillStore_CreateAndGet(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	skill := validSkill("runbook-1")
	if err := store.Create(ctx, skill); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, "runbook-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "runbook-1" {
		t.Errorf("Name = %q, want runbook-1", got.Name)
	}
	if got.Origin != SkillOriginUser {
		t.Errorf("Origin = %q, want %q (default for empty)", got.Origin, SkillOriginUser)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("timestamps not set: created=%v updated=%v", got.CreatedAt, got.UpdatedAt)
	}
}

func TestSkillStore_CreateDuplicateRejected(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.Create(ctx, validSkill("dup")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := store.Create(ctx, validSkill("dup"))
	if !errors.Is(err, ErrSkillAlreadyExists) {
		t.Fatalf("expected ErrSkillAlreadyExists, got %v", err)
	}
}

func TestSkillStore_GetMissingReturnsNotFound(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	_, err := store.Get(ctx, "missing")
	if !errors.Is(err, ErrSkillNotFound) {
		t.Fatalf("expected ErrSkillNotFound, got %v", err)
	}
}

func TestSkillStore_UpdateMergesAndBumpsVersion(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	original := validSkill("evolves")
	original.Description = "first"
	original.Body = "# v1\n"
	if err := store.Create(ctx, original); err != nil {
		t.Fatalf("Create: %v", err)
	}

	patch := &Skill{Description: "second"}
	updated, err := store.Update(ctx, "evolves", patch)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Description != "second" {
		t.Errorf("Description = %q, want second", updated.Description)
	}
	if updated.Body != "# v1\n" {
		t.Errorf("Body should be preserved, got %q", updated.Body)
	}
	if updated.Version != 2 {
		t.Errorf("Version = %d, want 2", updated.Version)
	}
	if !updated.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt drift: original=%v updated=%v", original.CreatedAt, updated.CreatedAt)
	}
}

func TestSkillStore_UpdatePreservesOrigin(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	seed := validSkill("seedling")
	seed.Origin = SkillOriginSeed
	if err := store.Create(ctx, seed); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Operator tries to flip Origin to user — must be ignored.
	patch := &Skill{Origin: SkillOriginUser, Description: "patched"}
	updated, err := store.Update(ctx, "seedling", patch)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Origin != SkillOriginSeed {
		t.Errorf("Origin = %q, want %q (must be preserved)", updated.Origin, SkillOriginSeed)
	}
}

func TestSkillStore_UpdateMissingReturnsNotFound(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	_, err := store.Update(ctx, "ghost", &Skill{Description: "x"})
	if !errors.Is(err, ErrSkillNotFound) {
		t.Fatalf("expected ErrSkillNotFound, got %v", err)
	}
}

func TestSkillStore_Delete(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.Create(ctx, validSkill("trash")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Delete(ctx, "trash"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := store.Get(ctx, "trash")
	if !errors.Is(err, ErrSkillNotFound) {
		t.Fatalf("expected ErrSkillNotFound after delete, got %v", err)
	}
}

func TestSkillStore_DeleteMissingReturnsNotFound(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	err := store.Delete(ctx, "ghost")
	if !errors.Is(err, ErrSkillNotFound) {
		t.Fatalf("expected ErrSkillNotFound, got %v", err)
	}
}

func TestSkillStore_List(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	for _, name := range []string{"alpha", "bravo", "charlie"} {
		if err := store.Create(ctx, validSkill(name)); err != nil {
			t.Fatalf("Create %q: %v", name, err)
		}
	}

	skills, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(skills) != 3 {
		t.Fatalf("len = %d, want 3", len(skills))
	}
	seen := map[string]bool{}
	for _, s := range skills {
		seen[s.Name] = true
	}
	for _, want := range []string{"alpha", "bravo", "charlie"} {
		if !seen[want] {
			t.Errorf("missing %q in list", want)
		}
	}
}

func TestSkillStore_ListFiltersInternalMetaKeys(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	if err := store.Create(ctx, validSkill("real")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Simulate a future _meta/seeded marker; List must skip it.
	if err := store.storage.Put(ctx, &sdklogical.StorageEntry{
		Key:   "_meta/seeded",
		Value: []byte("1"),
	}); err != nil {
		t.Fatalf("put marker: %v", err)
	}

	skills, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(skills) != 1 {
		t.Fatalf("len = %d, want 1 (real only)", len(skills))
	}
	if skills[0].Name != "real" {
		t.Errorf("name = %q, want real", skills[0].Name)
	}
}

func TestValidateSkill_Rejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(s *Skill)
		wantSub string
	}{
		{"empty name", func(s *Skill) { s.Name = "" }, "invalid skill name"},
		{"bad name uppercase", func(s *Skill) { s.Name = "BadName" }, "invalid skill name"},
		{"bad name leading hyphen", func(s *Skill) { s.Name = "-bad" }, "invalid skill name"},
		{"empty description", func(s *Skill) { s.Description = "" }, "description"},
		{"unknown category", func(s *Skill) { s.Category = "weird" }, "invalid skill category"},
		{"empty body", func(s *Skill) { s.Body = "" }, "body"},
		{"oversize body", func(s *Skill) { s.Body = strings.Repeat("x", maxSkillBodyBytes+1) }, "body exceeds"},
		{"too many requires", func(s *Skill) {
			s.Requires = make([]string, maxSkillRequiresLen+1)
			for i := range s.Requires {
				s.Requires[i] = "ok"
			}
		}, "requires exceeds"},
		{"bad require entry", func(s *Skill) { s.Requires = []string{"BAD"} }, "invalid requires entry"},
		{"provider-guide missing provider", func(s *Skill) {
			s.Category = SkillCategoryProviderGuide
			s.Provider = ""
		}, "provider field is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSkill("ok")
			tc.mutate(s)
			err := validateSkill(s)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestValidateSkill_Accepts(t *testing.T) {
	good := validSkill("good")
	if err := validateSkill(good); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	providerGuide := validSkill("aws")
	providerGuide.Category = SkillCategoryProviderGuide
	providerGuide.Provider = "aws"
	if err := validateSkill(providerGuide); err != nil {
		t.Errorf("provider-guide with provider should pass: %v", err)
	}
}

func TestSkillStore_CreateRejectsInvalid(t *testing.T) {
	store, ctx := setupTestSkillStore(t)

	bad := validSkill("ok")
	bad.Body = ""
	err := store.Create(ctx, bad)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "body") {
		t.Errorf("error should mention body, got %q", err.Error())
	}
}

func TestSkillStore_ClosedStoreReturnsError(t *testing.T) {
	store, ctx := setupTestSkillStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := store.Create(ctx, validSkill("late")); !errors.Is(err, ErrSkillStoreClosed) {
		t.Errorf("Create after close: got %v, want ErrSkillStoreClosed", err)
	}
	if _, err := store.Get(ctx, "x"); !errors.Is(err, ErrSkillStoreClosed) {
		t.Errorf("Get after close: got %v, want ErrSkillStoreClosed", err)
	}
	if _, err := store.List(ctx); !errors.Is(err, ErrSkillStoreClosed) {
		t.Errorf("List after close: got %v, want ErrSkillStoreClosed", err)
	}
	if err := store.Delete(ctx, "x"); !errors.Is(err, ErrSkillStoreClosed) {
		t.Errorf("Delete after close: got %v, want ErrSkillStoreClosed", err)
	}
	if _, err := store.Update(ctx, "x", &Skill{}); !errors.Is(err, ErrSkillStoreClosed) {
		t.Errorf("Update after close: got %v, want ErrSkillStoreClosed", err)
	}
}
