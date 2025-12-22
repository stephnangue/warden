package seal

import (
	"context"
	"errors"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Mock wrapper for testing
type mockWrapper struct {
	keyID           string
	wrapperType     wrapping.WrapperType
	encryptFunc     func(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error)
	decryptFunc     func(ctx context.Context, data *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error)
	setConfigFunc   func(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error)
	initCalled      bool
	finalizeCalled  bool
	shouldFailInit  bool
	shouldFailFinalize bool
}

func (m *mockWrapper) KeyId(ctx context.Context) (string, error) {
	if m.keyID == "" {
		return "test-key-id", nil
	}
	return m.keyID, nil
}

func (m *mockWrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	if m.setConfigFunc != nil {
		return m.setConfigFunc(ctx, options...)
	}
	return &wrapping.WrapperConfig{}, nil
}

func (m *mockWrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	if m.wrapperType == "" {
		return wrapping.WrapperType("mock"), nil
	}
	return m.wrapperType, nil
}

func (m *mockWrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(ctx, plaintext, options...)
	}
	return &wrapping.BlobInfo{
		Ciphertext: append([]byte("encrypted:"), plaintext...),
		KeyInfo: &wrapping.KeyInfo{
			KeyId: "test-key-id",
		},
	}, nil
}

func (m *mockWrapper) Decrypt(ctx context.Context, data *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ctx, data, options...)
	}
	if len(data.Ciphertext) > 10 {
		return data.Ciphertext[10:], nil
	}
	return []byte("decrypted"), nil
}

func (m *mockWrapper) Init(ctx context.Context, options ...wrapping.Option) error {
	m.initCalled = true
	if m.shouldFailInit {
		return errors.New("init failed")
	}
	return nil
}

func (m *mockWrapper) Finalize(ctx context.Context, options ...wrapping.Option) error {
	m.finalizeCalled = true
	if m.shouldFailFinalize {
		return errors.New("finalize failed")
	}
	return nil
}

func TestStoredKeysSupport_String(t *testing.T) {
	tests := []struct {
		name     string
		support  StoredKeysSupport
		expected string
	}{
		{
			name:     "AutoUnseal",
			support:  StoredKeysSupportedGeneric,
			expected: "AutoUnseal",
		},
		{
			name:     "Shamir",
			support:  StoredKeysSupportedShamirRoot,
			expected: "Shamir",
		},
		{
			name:     "Invalid",
			support:  StoredKeysInvalid,
			expected: "Invalid StoredKeys type",
		},
		{
			name:     "Unknown value",
			support:  StoredKeysSupport(99),
			expected: "Invalid StoredKeys type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.support.String()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestNewAccess(t *testing.T) {
	t.Run("creates access with wrapper", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		if access == nil {
			t.Fatal("NewAccess returned nil")
		}

		// Verify the wrapper is set correctly by calling GetWrapper
		if access.GetWrapper() != wrapper {
			t.Error("wrapper was not set correctly")
		}
	})
}

func TestAccess_GetWrapper(t *testing.T) {
	t.Run("returns underlying wrapper", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		retrieved := access.GetWrapper()
		if retrieved != wrapper {
			t.Error("GetWrapper did not return the correct wrapper")
		}
	})
}

func TestAccess_KeyId(t *testing.T) {
	t.Run("returns key ID from wrapper", func(t *testing.T) {
		wrapper := &mockWrapper{keyID: "custom-key-123"}
		access := NewAccess(wrapper)

		ctx := context.Background()
		keyID, err := access.KeyId(ctx)
		if err != nil {
			t.Fatalf("KeyId failed: %v", err)
		}

		if keyID != "custom-key-123" {
			t.Errorf("expected key ID custom-key-123, got %s", keyID)
		}
	})
}

func TestAccess_SetConfig(t *testing.T) {
	t.Run("calls SetConfig on underlying wrapper", func(t *testing.T) {
		called := false
		wrapper := &mockWrapper{
			setConfigFunc: func(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
				called = true
				return &wrapping.WrapperConfig{}, nil
			},
		}
		access := NewAccess(wrapper)

		ctx := context.Background()
		_, err := access.SetConfig(ctx)
		if err != nil {
			t.Fatalf("SetConfig failed: %v", err)
		}

		if !called {
			t.Error("SetConfig was not called on underlying wrapper")
		}
	})
}

func TestAccess_Type(t *testing.T) {
	t.Run("returns type from wrapper", func(t *testing.T) {
		wrapper := &mockWrapper{wrapperType: wrapping.WrapperType("test-type")}
		access := NewAccess(wrapper)

		ctx := context.Background()
		wType, err := access.Type(ctx)
		if err != nil {
			t.Fatalf("Type failed: %v", err)
		}

		if wType != "test-type" {
			t.Errorf("expected type test-type, got %s", wType)
		}
	})
}

func TestAccess_Init(t *testing.T) {
	t.Run("calls Init when wrapper implements InitFinalizer", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		ctx := context.Background()
		err := access.Init(ctx)
		if err != nil {
			t.Fatalf("Init failed: %v", err)
		}

		if !wrapper.initCalled {
			t.Error("Init was not called on wrapper")
		}
	})

	t.Run("returns error when Init fails", func(t *testing.T) {
		wrapper := &mockWrapper{shouldFailInit: true}
		access := NewAccess(wrapper)

		ctx := context.Background()
		err := access.Init(ctx)
		if err == nil {
			t.Error("expected error from Init")
		}
	})

	t.Run("does not fail when wrapper does not implement InitFinalizer", func(t *testing.T) {
		// Create a wrapper that doesn't implement InitFinalizer
		simpleWrapper := &simpleWrapper{}
		access := NewAccess(simpleWrapper)

		ctx := context.Background()
		err := access.Init(ctx)
		if err != nil {
			t.Fatalf("Init should not fail when wrapper doesn't implement InitFinalizer: %v", err)
		}
	})
}

func TestAccess_Finalize(t *testing.T) {
	t.Run("calls Finalize when wrapper implements InitFinalizer", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		ctx := context.Background()
		err := access.Finalize(ctx)
		if err != nil {
			t.Fatalf("Finalize failed: %v", err)
		}

		if !wrapper.finalizeCalled {
			t.Error("Finalize was not called on wrapper")
		}
	})

	t.Run("returns error when Finalize fails", func(t *testing.T) {
		wrapper := &mockWrapper{shouldFailFinalize: true}
		access := NewAccess(wrapper)

		ctx := context.Background()
		err := access.Finalize(ctx)
		if err == nil {
			t.Error("expected error from Finalize")
		}
	})

	t.Run("does not fail when wrapper does not implement InitFinalizer", func(t *testing.T) {
		simpleWrapper := &simpleWrapper{}
		access := NewAccess(simpleWrapper)

		ctx := context.Background()
		err := access.Finalize(ctx)
		if err != nil {
			t.Fatalf("Finalize should not fail when wrapper doesn't implement InitFinalizer: %v", err)
		}
	})
}

func TestAccess_Encrypt(t *testing.T) {
	t.Run("encrypts plaintext successfully", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		ctx := context.Background()
		plaintext := []byte("secret data")

		blob, err := access.Encrypt(ctx, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if blob == nil {
			t.Fatal("Encrypt returned nil blob")
		}

		if blob.KeyInfo == nil {
			t.Error("expected KeyInfo to be set")
		}
	})

	t.Run("returns error when encryption fails", func(t *testing.T) {
		wrapper := &mockWrapper{
			encryptFunc: func(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
				return nil, errors.New("encryption failed")
			},
		}
		access := NewAccess(wrapper)

		ctx := context.Background()
		_, err := access.Encrypt(ctx, []byte("data"))
		if err == nil {
			t.Error("expected error from Encrypt")
		}
	})

	t.Run("encrypts empty data", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		ctx := context.Background()
		blob, err := access.Encrypt(ctx, []byte{})
		if err != nil {
			t.Fatalf("Encrypt failed for empty data: %v", err)
		}

		if blob == nil {
			t.Fatal("Encrypt returned nil blob for empty data")
		}
	})
}

func TestAccess_Decrypt(t *testing.T) {
	t.Run("decrypts ciphertext successfully", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		ctx := context.Background()
		blob := &wrapping.BlobInfo{
			Ciphertext: []byte("encrypted:secret data"),
		}

		plaintext, err := access.Decrypt(ctx, blob)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if plaintext == nil {
			t.Fatal("Decrypt returned nil plaintext")
		}

		expected := []byte("secret data")
		if string(plaintext) != string(expected) {
			t.Errorf("expected plaintext %s, got %s", expected, plaintext)
		}
	})

	t.Run("returns error when decryption fails", func(t *testing.T) {
		wrapper := &mockWrapper{
			decryptFunc: func(ctx context.Context, data *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
				return nil, errors.New("decryption failed")
			},
		}
		access := NewAccess(wrapper)

		ctx := context.Background()
		blob := &wrapping.BlobInfo{
			Ciphertext: []byte("invalid"),
		}

		_, err := access.Decrypt(ctx, blob)
		if err == nil {
			t.Error("expected error from Decrypt")
		}
	})

	t.Run("handles empty ciphertext", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		ctx := context.Background()
		blob := &wrapping.BlobInfo{
			Ciphertext: []byte{},
		}

		plaintext, err := access.Decrypt(ctx, blob)
		if err != nil {
			t.Fatalf("Decrypt failed for empty ciphertext: %v", err)
		}

		if plaintext == nil {
			t.Error("expected plaintext to be non-nil for empty ciphertext")
		}
	})
}

func TestAccess_EncryptDecryptRoundTrip(t *testing.T) {
	t.Run("encrypt and decrypt round trip", func(t *testing.T) {
		wrapper := &mockWrapper{}
		access := NewAccess(wrapper)

		ctx := context.Background()
		original := []byte("sensitive information")

		// Encrypt
		blob, err := access.Encrypt(ctx, original)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		// Decrypt
		decrypted, err := access.Decrypt(ctx, blob)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if string(decrypted) != string(original) {
			t.Errorf("round trip failed: expected %s, got %s", original, decrypted)
		}
	})
}

func TestAccess_Interface(t *testing.T) {
	t.Run("implements Access interface", func(t *testing.T) {
		wrapper := &mockWrapper{}
		var _ Access = NewAccess(wrapper)
	})

	t.Run("implements wrapping.Wrapper interface", func(t *testing.T) {
		wrapper := &mockWrapper{}
		var _ wrapping.Wrapper = NewAccess(wrapper)
	})

	t.Run("implements wrapping.InitFinalizer interface", func(t *testing.T) {
		wrapper := &mockWrapper{}
		var _ wrapping.InitFinalizer = NewAccess(wrapper)
	})
}

// simpleWrapper is a wrapper that doesn't implement InitFinalizer
type simpleWrapper struct{}

func (s *simpleWrapper) KeyId(ctx context.Context) (string, error) {
	return "simple-key", nil
}

func (s *simpleWrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	return &wrapping.WrapperConfig{}, nil
}

func (s *simpleWrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperType("simple"), nil
}

func (s *simpleWrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	return &wrapping.BlobInfo{
		Ciphertext: plaintext,
	}, nil
}

func (s *simpleWrapper) Decrypt(ctx context.Context, data *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	return data.Ciphertext, nil
}
