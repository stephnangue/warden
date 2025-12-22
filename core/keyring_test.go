package core

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestNewKeyring(t *testing.T) {
	kr := NewKeyring()
	if kr == nil {
		t.Fatal("expected non-nil keyring")
	}
	if kr.keys == nil {
		t.Fatal("expected initialized keys map")
	}
	if kr.activeTerm != 0 {
		t.Errorf("expected activeTerm to be 0, got %d", kr.activeTerm)
	}
	if kr.rotationConfig.MaxOperations != absoluteOperationMaximum {
		t.Errorf("expected default MaxOperations, got %d", kr.rotationConfig.MaxOperations)
	}
}

func TestKeyring_Clone(t *testing.T) {
	original := NewKeyring()
	rootKey := []byte("test-root-key")
	original = original.SetRootKey(rootKey)

	key1 := &Key{
		Term:        1,
		Version:     1,
		Value:       []byte("key-value-1"),
		InstallTime: time.Now(),
		Encryptions: 100,
	}
	original, _ = original.AddKey(key1)

	clone := original.Clone()

	// Verify clone is not the same instance
	if original == clone {
		t.Fatal("clone should not be the same instance as original")
	}

	// Verify values are equal
	if !bytes.Equal(original.rootKey, clone.rootKey) {
		t.Error("root keys should be equal")
	}
	if original.activeTerm != clone.activeTerm {
		t.Error("active terms should be equal")
	}
	if len(original.keys) != len(clone.keys) {
		t.Error("keys maps should have same length")
	}
	if original.rotationConfig.MaxOperations != clone.rotationConfig.MaxOperations {
		t.Error("rotation configs should be equal")
	}

	// Note: Clone() creates a shallow copy - rootKey slice is shared
	// Modifying the underlying slice will affect both original and clone
	// This is why SetRootKey() creates a new copy of the key
	clone.rootKey[0] = 'X'
	if !bytes.Equal(original.rootKey, clone.rootKey) {
		t.Error("Clone creates shallow copy - rootKey slice is shared between original and clone")
	}

	// Verify that keys map itself is independent (but key objects are shared)
	if &original.keys == &clone.keys {
		t.Error("keys map should be a different instance")
	}

	// Verify key objects are shared (shallow copy)
	if original.TermKey(1) != clone.TermKey(1) {
		t.Error("key objects should be shared in shallow copy")
	}
}

func TestKeyring_AddKey(t *testing.T) {
	t.Run("add new key", func(t *testing.T) {
		kr := NewKeyring()
		key := &Key{
			Term:    1,
			Version: 1,
			Value:   []byte("test-key"),
		}

		newKr, err := kr.AddKey(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if newKr == kr {
			t.Error("AddKey should return a new keyring instance")
		}
		if newKr.activeTerm != 1 {
			t.Errorf("expected activeTerm to be 1, got %d", newKr.activeTerm)
		}
		if newKr.TermKey(1) == nil {
			t.Error("key should be added to keyring")
		}
	})

	t.Run("add key with existing term and same value", func(t *testing.T) {
		kr := NewKeyring()
		key := &Key{
			Term:    1,
			Version: 1,
			Value:   []byte("test-key"),
		}
		kr, _ = kr.AddKey(key)

		// Add same key again
		sameKr, err := kr.AddKey(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sameKr != kr {
			t.Error("adding same key should return original keyring")
		}
	})

	t.Run("add key with conflicting term", func(t *testing.T) {
		kr := NewKeyring()
		key1 := &Key{
			Term:    1,
			Version: 1,
			Value:   []byte("test-key-1"),
		}
		kr, _ = kr.AddKey(key1)

		key2 := &Key{
			Term:    1,
			Version: 1,
			Value:   []byte("different-key"),
		}
		_, err := kr.AddKey(key2)
		if err == nil {
			t.Fatal("expected error for conflicting key")
		}
	})

	t.Run("add key updates active term", func(t *testing.T) {
		kr := NewKeyring()
		key1 := &Key{Term: 1, Value: []byte("key1")}
		key2 := &Key{Term: 2, Value: []byte("key2")}

		kr, _ = kr.AddKey(key1)
		if kr.activeTerm != 1 {
			t.Errorf("expected activeTerm 1, got %d", kr.activeTerm)
		}

		kr, _ = kr.AddKey(key2)
		if kr.activeTerm != 2 {
			t.Errorf("expected activeTerm 2, got %d", kr.activeTerm)
		}
	})

	t.Run("add key sets install time", func(t *testing.T) {
		kr := NewKeyring()
		key := &Key{Term: 1, Value: []byte("key1")}

		before := time.Now()
		kr, _ = kr.AddKey(key)
		after := time.Now()

		addedKey := kr.TermKey(1)
		if addedKey.InstallTime.IsZero() {
			t.Error("InstallTime should be set")
		}
		if addedKey.InstallTime.Before(before) || addedKey.InstallTime.After(after) {
			t.Error("InstallTime should be set to current time")
		}
	})

	t.Run("add key zeros previous encryptions", func(t *testing.T) {
		kr := NewKeyring()
		key1 := &Key{Term: 1, Value: []byte("key1"), Encryptions: 100}
		key2 := &Key{Term: 2, Value: []byte("key2")}

		kr, _ = kr.AddKey(key1)
		kr, _ = kr.AddKey(key2)

		if kr.TermKey(1).Encryptions != 0 {
			t.Error("previous key encryptions should be zeroed")
		}
	})
}

func TestKeyring_RemoveKey(t *testing.T) {
	t.Run("remove non-active key", func(t *testing.T) {
		kr := NewKeyring()
		key1 := &Key{Term: 1, Value: []byte("key1")}
		key2 := &Key{Term: 2, Value: []byte("key2")}
		kr, _ = kr.AddKey(key1)
		kr, _ = kr.AddKey(key2)

		newKr, err := kr.RemoveKey(1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if newKr == kr {
			t.Error("RemoveKey should return new keyring instance")
		}
		if newKr.TermKey(1) != nil {
			t.Error("key should be removed")
		}
		if newKr.TermKey(2) == nil {
			t.Error("active key should remain")
		}
	})

	t.Run("remove active key fails", func(t *testing.T) {
		kr := NewKeyring()
		key := &Key{Term: 1, Value: []byte("key1")}
		kr, _ = kr.AddKey(key)

		_, err := kr.RemoveKey(1)
		if err == nil {
			t.Fatal("expected error when removing active key")
		}
	})

	t.Run("remove non-existent key", func(t *testing.T) {
		kr := NewKeyring()
		key := &Key{Term: 1, Value: []byte("key1")}
		kr, _ = kr.AddKey(key)

		sameKr, err := kr.RemoveKey(99)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sameKr != kr {
			t.Error("removing non-existent key should return original keyring")
		}
	})
}

func TestKeyring_ActiveTerm(t *testing.T) {
	kr := NewKeyring()
	if kr.ActiveTerm() != 0 {
		t.Errorf("expected initial active term 0, got %d", kr.ActiveTerm())
	}

	key := &Key{Term: 5, Value: []byte("key")}
	kr, _ = kr.AddKey(key)
	if kr.ActiveTerm() != 5 {
		t.Errorf("expected active term 5, got %d", kr.ActiveTerm())
	}
}

func TestKeyring_ActiveKey(t *testing.T) {
	kr := NewKeyring()
	if kr.ActiveKey() != nil {
		t.Error("expected nil active key for empty keyring")
	}

	key := &Key{Term: 1, Value: []byte("key")}
	kr, _ = kr.AddKey(key)
	activeKey := kr.ActiveKey()
	if activeKey == nil {
		t.Fatal("expected non-nil active key")
	}
	if !bytes.Equal(activeKey.Value, key.Value) {
		t.Error("active key value mismatch")
	}
}

func TestKeyring_TermKey(t *testing.T) {
	kr := NewKeyring()
	key1 := &Key{Term: 1, Value: []byte("key1")}
	key2 := &Key{Term: 2, Value: []byte("key2")}
	kr, _ = kr.AddKey(key1)
	kr, _ = kr.AddKey(key2)

	if kr.TermKey(1) == nil {
		t.Error("expected to find key for term 1")
	}
	if kr.TermKey(2) == nil {
		t.Error("expected to find key for term 2")
	}
	if kr.TermKey(99) != nil {
		t.Error("expected nil for non-existent term")
	}
}

func TestKeyring_SetRootKey(t *testing.T) {
	kr := NewKeyring()
	rootKey := []byte("test-root-key")

	newKr := kr.SetRootKey(rootKey)
	if newKr == kr {
		t.Error("SetRootKey should return new keyring instance")
	}
	if !bytes.Equal(newKr.RootKey(), rootKey) {
		t.Error("root key mismatch")
	}

	// Verify original is not modified
	if !bytes.Equal(kr.RootKey(), nil) {
		t.Error("original keyring should not be modified")
	}

	// Verify it's a copy
	rootKey[0] = 'X'
	if newKr.RootKey()[0] == 'X' {
		t.Error("root key should be copied, not referenced")
	}
}

func TestKeyring_RootKey(t *testing.T) {
	kr := NewKeyring()
	if kr.RootKey() != nil {
		t.Error("expected nil root key for new keyring")
	}

	rootKey := []byte("test-root-key")
	kr = kr.SetRootKey(rootKey)
	if !bytes.Equal(kr.RootKey(), rootKey) {
		t.Error("root key mismatch")
	}
}

func TestKeyring_Serialize(t *testing.T) {
	kr := NewKeyring()
	rootKey := []byte("test-root-key")
	kr = kr.SetRootKey(rootKey)

	key1 := &Key{
		Term:        1,
		Version:     1,
		Value:       []byte("key1"),
		InstallTime: time.Now(),
		Encryptions: 50,
	}
	key2 := &Key{
		Term:        2,
		Version:     1,
		Value:       []byte("key2"),
		InstallTime: time.Now(),
		Encryptions: 0,
	}
	kr, _ = kr.AddKey(key1)
	kr, _ = kr.AddKey(key2)

	data, err := kr.Serialize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty serialized data")
	}

	// Verify it's valid JSON
	var enc EncodedKeyring
	if err := json.Unmarshal(data, &enc); err != nil {
		t.Fatalf("serialized data is not valid JSON: %v", err)
	}
	if !bytes.Equal(enc.RootKey, rootKey) {
		t.Error("serialized root key mismatch")
	}
	if len(enc.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(enc.Keys))
	}
}

func TestKeyring_DeserializeKeyring(t *testing.T) {
	t.Run("valid keyring", func(t *testing.T) {
		original := NewKeyring()
		rootKey := []byte("test-root-key")
		original = original.SetRootKey(rootKey)

		key1 := &Key{Term: 1, Value: []byte("key1"), InstallTime: time.Now()}
		key2 := &Key{Term: 2, Value: []byte("key2"), InstallTime: time.Now()}
		original, _ = original.AddKey(key1)
		original, _ = original.AddKey(key2)

		data, _ := original.Serialize()

		restored, err := DeserializeKeyring(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(restored.RootKey(), original.RootKey()) {
			t.Error("root key mismatch after deserialization")
		}
		if restored.ActiveTerm() != original.ActiveTerm() {
			t.Error("active term mismatch after deserialization")
		}
		if len(restored.keys) != len(original.keys) {
			t.Error("keys count mismatch after deserialization")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := DeserializeKeyring([]byte("invalid json"))
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("empty keyring", func(t *testing.T) {
		kr := NewKeyring()
		data, _ := kr.Serialize()

		restored, err := DeserializeKeyring(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(restored.keys) != 0 {
			t.Error("expected empty keys map")
		}
	})

	t.Run("rotation config sanitization", func(t *testing.T) {
		enc := EncodedKeyring{
			RootKey: []byte("test"),
			RotationConfig: KeyRotationConfig{
				MaxOperations: 0, // Invalid, should be sanitized
			},
		}
		data, _ := json.Marshal(enc)

		kr, err := DeserializeKeyring(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if kr.rotationConfig.MaxOperations != absoluteOperationMaximum {
			t.Error("rotation config should be sanitized")
		}
	})
}

func TestKeyring_Zeroize(t *testing.T) {
	t.Run("zeroize nil keyring", func(t *testing.T) {
		var kr *Keyring
		kr.Zeroize(true) // Should not panic
	})

	t.Run("zeroize root key only", func(t *testing.T) {
		kr := NewKeyring()
		rootKey := []byte("test-root-key")
		kr = kr.SetRootKey(rootKey)

		key := &Key{Term: 1, Value: []byte("test-key")}
		kr, _ = kr.AddKey(key)

		kr.Zeroize(false)

		// Root key should be zeroed
		allZero := true
		for _, b := range kr.rootKey {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			t.Error("root key should be zeroed")
		}

		// Key values should not be zeroed
		keyValue := kr.TermKey(1).Value
		if bytes.Equal(keyValue, make([]byte, len(keyValue))) {
			t.Error("key values should not be zeroed when keysToo is false")
		}
	})

	t.Run("zeroize all keys", func(t *testing.T) {
		kr := NewKeyring()
		rootKey := []byte("test-root-key")
		kr = kr.SetRootKey(rootKey)

		key := &Key{Term: 1, Value: []byte("test-key")}
		kr, _ = kr.AddKey(key)

		kr.Zeroize(true)

		// Root key should be zeroed
		allZero := true
		for _, b := range kr.rootKey {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			t.Error("root key should be zeroed")
		}

		// Key values should be zeroed
		keyValue := kr.TermKey(1).Value
		if !bytes.Equal(keyValue, make([]byte, len(keyValue))) {
			t.Error("key values should be zeroed when keysToo is true")
		}
	})
}

func TestKey_Serialize(t *testing.T) {
	key := &Key{
		Term:        1,
		Version:     1,
		Value:       []byte("test-key"),
		InstallTime: time.Now(),
		Encryptions: 100,
	}

	data, err := key.Serialize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty serialized data")
	}

	// Verify it's valid JSON
	var decoded Key
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("serialized data is not valid JSON: %v", err)
	}
	if decoded.Term != key.Term {
		t.Error("term mismatch")
	}
	if !bytes.Equal(decoded.Value, key.Value) {
		t.Error("value mismatch")
	}
}

func TestKey_DeserializeKey(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		original := &Key{
			Term:        1,
			Version:     1,
			Value:       []byte("test-key"),
			InstallTime: time.Now(),
			Encryptions: 100,
		}

		data, _ := original.Serialize()

		restored, err := DeserializeKey(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if restored.Term != original.Term {
			t.Error("term mismatch")
		}
		if !bytes.Equal(restored.Value, original.Value) {
			t.Error("value mismatch")
		}
		if restored.Encryptions != original.Encryptions {
			t.Error("encryptions mismatch")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := DeserializeKey([]byte("invalid json"))
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestKeyRotationConfig_Clone(t *testing.T) {
	original := KeyRotationConfig{
		MaxOperations: 1000000,
		Interval:      48 * time.Hour,
		Disabled:      true,
	}

	clone := original.Clone()

	if clone.MaxOperations != original.MaxOperations {
		t.Error("MaxOperations mismatch")
	}
	if clone.Interval != original.Interval {
		t.Error("Interval mismatch")
	}
	if clone.Disabled != original.Disabled {
		t.Error("Disabled mismatch")
	}
}

func TestKeyRotationConfig_Sanitize(t *testing.T) {
	t.Run("zero max operations", func(t *testing.T) {
		config := KeyRotationConfig{MaxOperations: 0}
		config.Sanitize()
		if config.MaxOperations != absoluteOperationMaximum {
			t.Errorf("expected %d, got %d", absoluteOperationMaximum, config.MaxOperations)
		}
	})

	t.Run("max operations too high", func(t *testing.T) {
		config := KeyRotationConfig{MaxOperations: absoluteOperationMaximum + 1000}
		config.Sanitize()
		if config.MaxOperations != absoluteOperationMaximum {
			t.Errorf("expected %d, got %d", absoluteOperationMaximum, config.MaxOperations)
		}
	})

	t.Run("max operations too low", func(t *testing.T) {
		config := KeyRotationConfig{MaxOperations: 100}
		config.Sanitize()
		if config.MaxOperations != absoluteOperationMinimum {
			t.Errorf("expected %d, got %d", absoluteOperationMinimum, config.MaxOperations)
		}
	})

	t.Run("valid max operations", func(t *testing.T) {
		targetOps := int64(2_000_000)
		config := KeyRotationConfig{MaxOperations: targetOps}
		config.Sanitize()
		if config.MaxOperations != targetOps {
			t.Errorf("expected %d, got %d", targetOps, config.MaxOperations)
		}
	})

	t.Run("interval too short", func(t *testing.T) {
		config := KeyRotationConfig{Interval: 1 * time.Hour}
		config.Sanitize()
		if config.Interval != minimumRotationInterval {
			t.Errorf("expected %v, got %v", minimumRotationInterval, config.Interval)
		}
	})

	t.Run("valid interval", func(t *testing.T) {
		targetInterval := 48 * time.Hour
		config := KeyRotationConfig{Interval: targetInterval}
		config.Sanitize()
		if config.Interval != targetInterval {
			t.Errorf("expected %v, got %v", targetInterval, config.Interval)
		}
	})

	t.Run("zero interval unchanged", func(t *testing.T) {
		config := KeyRotationConfig{Interval: 0}
		config.Sanitize()
		if config.Interval != 0 {
			t.Errorf("expected 0, got %v", config.Interval)
		}
	})
}

func TestKeyRotationConfig_Equals(t *testing.T) {
	t.Run("equal configs", func(t *testing.T) {
		c1 := KeyRotationConfig{
			MaxOperations: 1000000,
			Interval:      24 * time.Hour,
		}
		c2 := KeyRotationConfig{
			MaxOperations: 1000000,
			Interval:      24 * time.Hour,
		}
		if !c1.Equals(c2) {
			t.Error("configs should be equal")
		}
	})

	t.Run("different max operations", func(t *testing.T) {
		c1 := KeyRotationConfig{MaxOperations: 1000000}
		c2 := KeyRotationConfig{MaxOperations: 2000000}
		if c1.Equals(c2) {
			t.Error("configs should not be equal")
		}
	})

	t.Run("different intervals", func(t *testing.T) {
		c1 := KeyRotationConfig{Interval: 24 * time.Hour}
		c2 := KeyRotationConfig{Interval: 48 * time.Hour}
		if c1.Equals(c2) {
			t.Error("configs should not be equal")
		}
	})

	t.Run("disabled field not compared", func(t *testing.T) {
		c1 := KeyRotationConfig{
			MaxOperations: 1000000,
			Interval:      24 * time.Hour,
			Disabled:      true,
		}
		c2 := KeyRotationConfig{
			MaxOperations: 1000000,
			Interval:      24 * time.Hour,
			Disabled:      false,
		}
		if !c1.Equals(c2) {
			t.Error("configs should be equal (Disabled field not compared)")
		}
	})
}
