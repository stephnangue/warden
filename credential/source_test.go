package credential

import (
	"sync"
	"testing"
)

// TestCredSourceRegistry_Register tests basic registration
func TestCredSourceRegistry_Register(t *testing.T) {
	registry := NewCredSourceRegistry()

	source := CredSource{
		Name: "test-source",
		Type: "local",
		Config: map[string]string{
			"path": "/secrets",
		},
	}

	// Test successful registration
	err := registry.Register(source)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify source was registered
	retrieved, ok := registry.Get("test-source")
	if !ok {
		t.Fatal("expected source to be found")
	}
	if retrieved.Name != source.Name {
		t.Errorf("expected source name %s, got %s", source.Name, retrieved.Name)
	}
	if retrieved.Type != source.Type {
		t.Errorf("expected source type %s, got %s", source.Type, retrieved.Type)
	}
}

// TestCredSourceRegistry_RegisterEmptyName tests registering source with empty name
func TestCredSourceRegistry_RegisterEmptyName(t *testing.T) {
	registry := NewCredSourceRegistry()

	source := CredSource{
		Name: "",
		Type: "local",
	}

	err := registry.Register(source)
	if err == nil {
		t.Fatal("expected error when registering source with empty name")
	}
}

// TestCredSourceRegistry_RegisterDuplicate tests registering duplicate source
func TestCredSourceRegistry_RegisterDuplicate(t *testing.T) {
	registry := NewCredSourceRegistry()

	source1 := CredSource{
		Name: "test-source",
		Type: "local",
	}

	source2 := CredSource{
		Name: "test-source",
		Type: "hashicorp_vault",
	}

	// Register first source
	err := registry.Register(source1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Try to register duplicate
	err = registry.Register(source2)
	if err != ErrSourceAlreadyExists {
		t.Errorf("expected ErrSourceAlreadyExists, got %v", err)
	}

	// Verify original source is still there
	retrieved, _ := registry.Get("test-source")
	if retrieved.Type != "local" {
		t.Errorf("expected original source type, got %s", retrieved.Type)
	}
}

// TestCredSourceRegistry_Get tests retrieval
func TestCredSourceRegistry_Get(t *testing.T) {
	registry := NewCredSourceRegistry()

	source := CredSource{
		Name: "test-source",
		Type: "local",
	}

	registry.Register(source)

	// Test existing source
	retrieved, ok := registry.Get("test-source")
	if !ok {
		t.Fatal("expected source to be found")
	}
	if retrieved.Name != "test-source" {
		t.Errorf("expected name test-source, got %s", retrieved.Name)
	}

	// Test non-existing source
	_, ok = registry.Get("non-existent")
	if ok {
		t.Error("expected source not to be found")
	}
}

// TestCredSourceRegistry_GetSource tests GetSource alias
func TestCredSourceRegistry_GetSource(t *testing.T) {
	registry := NewCredSourceRegistry()

	source := CredSource{
		Name: "test-source",
		Type: "local",
	}

	registry.Register(source)

	// Test GetSource (should be same as Get)
	retrieved, ok := registry.GetSource("test-source")
	if !ok {
		t.Fatal("expected source to be found")
	}
	if retrieved.Name != "test-source" {
		t.Errorf("expected name test-source, got %s", retrieved.Name)
	}
}

// TestCredSourceRegistry_List tests listing all sources
func TestCredSourceRegistry_List(t *testing.T) {
	registry := NewCredSourceRegistry()

	// Empty registry
	sources := registry.List()
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}

	// Add sources
	source1 := CredSource{Name: "source1", Type: "local"}
	source2 := CredSource{Name: "source2", Type: "hashicorp_vault"}
	source3 := CredSource{Name: "source3", Type: "aws_secret_manager"}

	registry.Register(source1)
	registry.Register(source2)
	registry.Register(source3)

	sources = registry.List()
	if len(sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(sources))
	}

	// Verify all sources are in the list
	names := make(map[string]bool)
	for _, source := range sources {
		names[source.Name] = true
	}

	for _, expected := range []string{"source1", "source2", "source3"} {
		if !names[expected] {
			t.Errorf("expected source %s in list", expected)
		}
	}
}

// TestCredSourceRegistry_Delete tests deletion
func TestCredSourceRegistry_Delete(t *testing.T) {
	registry := NewCredSourceRegistry()

	source := CredSource{Name: "test-source", Type: "local"}
	registry.Register(source)

	// Delete existing source
	deleted := registry.Delete("test-source")
	if !deleted {
		t.Error("expected deletion to succeed")
	}

	// Verify source is gone
	_, ok := registry.Get("test-source")
	if ok {
		t.Error("expected source to be deleted")
	}

	// Delete non-existent source
	deleted = registry.Delete("non-existent")
	if deleted {
		t.Error("expected deletion to fail for non-existent source")
	}
}

// TestCredSourceRegistry_Exists tests existence check
func TestCredSourceRegistry_Exists(t *testing.T) {
	registry := NewCredSourceRegistry()

	source := CredSource{Name: "test-source", Type: "local"}
	registry.Register(source)

	// Test existing source
	if !registry.Exists("test-source") {
		t.Error("expected source to exist")
	}

	// Test non-existing source
	if registry.Exists("non-existent") {
		t.Error("expected source not to exist")
	}
}

// TestCredSourceRegistry_Count tests count
func TestCredSourceRegistry_Count(t *testing.T) {
	registry := NewCredSourceRegistry()

	if registry.Count() != 0 {
		t.Errorf("expected count 0, got %d", registry.Count())
	}

	registry.Register(CredSource{Name: "source1", Type: "local"})
	registry.Register(CredSource{Name: "source2", Type: "hashicorp_vault"})

	if registry.Count() != 2 {
		t.Errorf("expected count 2, got %d", registry.Count())
	}

	registry.Delete("source1")

	if registry.Count() != 1 {
		t.Errorf("expected count 1, got %d", registry.Count())
	}
}

// TestCredSourceRegistry_Concurrent tests concurrent operations
func TestCredSourceRegistry_Concurrent(t *testing.T) {
	registry := NewCredSourceRegistry()
	var wg sync.WaitGroup

	// Concurrent registrations
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			source := CredSource{
				Name: string(rune('a'+idx%26)) + string(rune('0'+idx/26)),
				Type: "local",
			}
			registry.Register(source)
		}(i)
	}

	wg.Wait()

	// Verify at least one source was registered
	if registry.Count() < 1 {
		t.Error("expected at least one source to be registered")
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
