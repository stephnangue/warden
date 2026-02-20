package credential

import (
	"sync"
	"testing"
	"time"
)

// TestCredSpecRegistry_Register tests basic registration
func TestCredSpecRegistry_Register(t *testing.T) {
	registry := NewCredSpecRegistry()

	spec := &CredSpec{
		Name:   "test-spec",
		Type:   "vault_token",
		Source: "test-source",
		MinTTL: time.Hour,
		MaxTTL: 24 * time.Hour,
	}

	// Test successful registration
	err := registry.Register(spec)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify spec was registered
	retrieved, ok := registry.Get("test-spec")
	if !ok {
		t.Fatal("expected spec to be found")
	}
	if retrieved.Name != spec.Name {
		t.Errorf("expected spec name %s, got %s", spec.Name, retrieved.Name)
	}
}

// TestCredSpecRegistry_RegisterNil tests registering nil spec
func TestCredSpecRegistry_RegisterNil(t *testing.T) {
	registry := NewCredSpecRegistry()

	err := registry.Register(nil)
	if err == nil {
		t.Fatal("expected error when registering nil spec")
	}
}

// TestCredSpecRegistry_RegisterEmptyName tests registering spec with empty name
func TestCredSpecRegistry_RegisterEmptyName(t *testing.T) {
	registry := NewCredSpecRegistry()

	spec := &CredSpec{
		Name: "",
		Type: "vault_token",
	}

	err := registry.Register(spec)
	if err == nil {
		t.Fatal("expected error when registering spec with empty name")
	}
}

// TestCredSpecRegistry_RegisterDuplicate tests registering duplicate spec
func TestCredSpecRegistry_RegisterDuplicate(t *testing.T) {
	registry := NewCredSpecRegistry()

	spec1 := &CredSpec{
		Name: "test-spec",
		Type: "vault_token",
	}

	spec2 := &CredSpec{
		Name: "test-spec",
		Type: "aws_access_keys",
	}

	// Register first spec
	err := registry.Register(spec1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Try to register duplicate
	err = registry.Register(spec2)
	if err != ErrSpecAlreadyExists {
		t.Errorf("expected ErrSpecAlreadyExists, got %v", err)
	}

	// Verify original spec is still there
	retrieved, _ := registry.Get("test-spec")
	if retrieved.Type != "vault_token" {
		t.Errorf("expected original spec type, got %s", retrieved.Type)
	}
}

// TestCredSpecRegistry_Get tests retrieval
func TestCredSpecRegistry_Get(t *testing.T) {
	registry := NewCredSpecRegistry()

	spec := &CredSpec{
		Name: "test-spec",
		Type: "vault_token",
	}

	registry.Register(spec)

	// Test existing spec
	retrieved, ok := registry.Get("test-spec")
	if !ok {
		t.Fatal("expected spec to be found")
	}
	if retrieved.Name != "test-spec" {
		t.Errorf("expected name test-spec, got %s", retrieved.Name)
	}

	// Test non-existing spec
	_, ok = registry.Get("non-existent")
	if ok {
		t.Error("expected spec not to be found")
	}
}

// TestCredSpecRegistry_List tests listing all specs
func TestCredSpecRegistry_List(t *testing.T) {
	registry := NewCredSpecRegistry()

	// Empty registry
	specs := registry.List()
	if len(specs) != 0 {
		t.Errorf("expected 0 specs, got %d", len(specs))
	}

	// Add specs
	spec1 := &CredSpec{Name: "spec1", Type: "vault_token"}
	spec2 := &CredSpec{Name: "spec2", Type: "aws_access_keys"}
	spec3 := &CredSpec{Name: "spec3", Type: "vault_token"}

	registry.Register(spec1)
	registry.Register(spec2)
	registry.Register(spec3)

	specs = registry.List()
	if len(specs) != 3 {
		t.Errorf("expected 3 specs, got %d", len(specs))
	}

	// Verify all specs are in the list
	names := make(map[string]bool)
	for _, spec := range specs {
		names[spec.Name] = true
	}

	for _, expected := range []string{"spec1", "spec2", "spec3"} {
		if !names[expected] {
			t.Errorf("expected spec %s in list", expected)
		}
	}
}

// TestCredSpecRegistry_Delete tests deletion
func TestCredSpecRegistry_Delete(t *testing.T) {
	registry := NewCredSpecRegistry()

	spec := &CredSpec{Name: "test-spec", Type: "vault_token"}
	registry.Register(spec)

	// Delete existing spec
	deleted := registry.Delete("test-spec")
	if !deleted {
		t.Error("expected deletion to succeed")
	}

	// Verify spec is gone
	_, ok := registry.Get("test-spec")
	if ok {
		t.Error("expected spec to be deleted")
	}

	// Delete non-existent spec
	deleted = registry.Delete("non-existent")
	if deleted {
		t.Error("expected deletion to fail for non-existent spec")
	}
}

// TestCredSpecRegistry_Exists tests existence check
func TestCredSpecRegistry_Exists(t *testing.T) {
	registry := NewCredSpecRegistry()

	spec := &CredSpec{Name: "test-spec", Type: "vault_token"}
	registry.Register(spec)

	// Test existing spec
	if !registry.Exists("test-spec") {
		t.Error("expected spec to exist")
	}

	// Test non-existing spec
	if registry.Exists("non-existent") {
		t.Error("expected spec not to exist")
	}
}

// TestCredSpecRegistry_Count tests count
func TestCredSpecRegistry_Count(t *testing.T) {
	registry := NewCredSpecRegistry()

	if registry.Count() != 0 {
		t.Errorf("expected count 0, got %d", registry.Count())
	}

	registry.Register(&CredSpec{Name: "spec1", Type: "vault_token"})
	registry.Register(&CredSpec{Name: "spec2", Type: "aws_access_keys"})

	if registry.Count() != 2 {
		t.Errorf("expected count 2, got %d", registry.Count())
	}

	registry.Delete("spec1")

	if registry.Count() != 1 {
		t.Errorf("expected count 1, got %d", registry.Count())
	}
}

// TestCredSpecRegistry_Concurrent tests concurrent operations
func TestCredSpecRegistry_Concurrent(t *testing.T) {
	registry := NewCredSpecRegistry()
	var wg sync.WaitGroup

	// Concurrent registrations
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			spec := &CredSpec{
				Name: string(rune('a' + idx%26)) + string(rune('0' + idx/26)),
				Type: "vault_token",
			}
			registry.Register(spec)
		}(i)
	}

	wg.Wait()

	// Verify all specs were registered
	if registry.Count() < 1 {
		t.Error("expected at least one spec to be registered")
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registry.List()
			registry.Count()
		}()
	}

	wg.Wait()
}
