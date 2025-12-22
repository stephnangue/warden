package seal

import (
	"bytes"
	"sync"
	"testing"
)

func TestNewEnvelope(t *testing.T) {
	t.Run("creates new envelope", func(t *testing.T) {
		env := NewEnvelope()

		if env == nil {
			t.Fatal("NewEnvelope returned nil")
		}

		if env.envelope != nil {
			t.Error("envelope should be nil before initialization")
		}
	})
}

func TestEnvelope_Init(t *testing.T) {
	t.Run("initializes envelope once", func(t *testing.T) {
		env := NewEnvelope()
		env.init()

		if env.envelope == nil {
			t.Error("envelope should be initialized after init()")
		}
	})

	t.Run("initializes only once with sync.Once", func(t *testing.T) {
		env := NewEnvelope()

		// Call init multiple times
		env.once.Do(env.init)
		firstEnvelope := env.envelope

		env.once.Do(env.init)
		secondEnvelope := env.envelope

		if firstEnvelope != secondEnvelope {
			t.Error("envelope should only be initialized once")
		}
	})
}

func TestEnvelope_Encrypt(t *testing.T) {
	t.Run("encrypts plaintext successfully", func(t *testing.T) {
		env := NewEnvelope()
		plaintext := []byte("sensitive data")
		aad := []byte("additional authenticated data")

		envelopeInfo, err := env.Encrypt(plaintext, aad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if envelopeInfo == nil {
			t.Fatal("Encrypt returned nil envelope info")
		}

		if envelopeInfo.Ciphertext == nil {
			t.Error("ciphertext should not be nil")
		}

		if len(envelopeInfo.Ciphertext) == 0 {
			t.Error("ciphertext should not be empty")
		}

		if envelopeInfo.Key == nil {
			t.Error("key should not be nil")
		}
	})

	t.Run("encrypts without AAD", func(t *testing.T) {
		env := NewEnvelope()
		plaintext := []byte("data without aad")

		envelopeInfo, err := env.Encrypt(plaintext, nil)
		if err != nil {
			t.Fatalf("Encrypt failed without AAD: %v", err)
		}

		if envelopeInfo == nil {
			t.Fatal("Encrypt returned nil envelope info")
		}

		if envelopeInfo.Ciphertext == nil {
			t.Error("ciphertext should not be nil")
		}
	})

	t.Run("encrypts empty plaintext", func(t *testing.T) {
		env := NewEnvelope()
		plaintext := []byte{}
		aad := []byte("aad")

		envelopeInfo, err := env.Encrypt(plaintext, aad)
		if err != nil {
			t.Fatalf("Encrypt failed for empty plaintext: %v", err)
		}

		if envelopeInfo == nil {
			t.Fatal("Encrypt returned nil for empty plaintext")
		}
	})

	t.Run("initializes envelope on first encrypt", func(t *testing.T) {
		env := NewEnvelope()

		if env.envelope != nil {
			t.Error("envelope should be nil before first encrypt")
		}

		_, err := env.Encrypt([]byte("test"), nil)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if env.envelope == nil {
			t.Error("envelope should be initialized after first encrypt")
		}
	})

	t.Run("produces different ciphertexts for same plaintext", func(t *testing.T) {
		env := NewEnvelope()
		plaintext := []byte("same data")
		aad := []byte("same aad")

		envelopeInfo1, err := env.Encrypt(plaintext, aad)
		if err != nil {
			t.Fatalf("First encrypt failed: %v", err)
		}

		envelopeInfo2, err := env.Encrypt(plaintext, aad)
		if err != nil {
			t.Fatalf("Second encrypt failed: %v", err)
		}

		// Ciphertexts should be different due to random IV/nonce
		if bytes.Equal(envelopeInfo1.Ciphertext, envelopeInfo2.Ciphertext) {
			t.Error("encrypting same plaintext should produce different ciphertexts")
		}

		// Keys should be different
		if bytes.Equal(envelopeInfo1.Key, envelopeInfo2.Key) {
			t.Error("each encryption should use a different key")
		}
	})
}

func TestEnvelope_Decrypt(t *testing.T) {
	t.Run("decrypts ciphertext successfully", func(t *testing.T) {
		env := NewEnvelope()
		original := []byte("secret message")
		aad := []byte("aad data")

		// First encrypt
		envelopeInfo, err := env.Encrypt(original, aad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		// Then decrypt
		decrypted, err := env.Decrypt(envelopeInfo, aad)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Errorf("decrypted data does not match original: expected %s, got %s", original, decrypted)
		}
	})

	t.Run("decrypts without AAD", func(t *testing.T) {
		env := NewEnvelope()
		original := []byte("message without aad")

		envelopeInfo, err := env.Encrypt(original, nil)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		decrypted, err := env.Decrypt(envelopeInfo, nil)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Errorf("decrypted data does not match original")
		}
	})

	t.Run("fails with wrong AAD", func(t *testing.T) {
		env := NewEnvelope()
		original := []byte("authenticated message")
		correctAAD := []byte("correct aad")
		wrongAAD := []byte("wrong aad")

		envelopeInfo, err := env.Encrypt(original, correctAAD)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		_, err = env.Decrypt(envelopeInfo, wrongAAD)
		if err == nil {
			t.Error("Decrypt should fail with wrong AAD")
		}
	})

	t.Run("fails with nil envelope info", func(t *testing.T) {
		env := NewEnvelope()

		_, err := env.Decrypt(nil, []byte("aad"))
		if err == nil {
			t.Error("Decrypt should fail with nil envelope info")
		}
	})

	t.Run("initializes envelope on first decrypt", func(t *testing.T) {
		env := NewEnvelope()

		if env.envelope != nil {
			t.Error("envelope should be nil before first decrypt")
		}

		// Create a valid envelope info from another instance
		env2 := NewEnvelope()
		envelopeInfo, err := env2.Encrypt([]byte("test"), nil)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		// Decrypt with the first instance
		_, err = env.Decrypt(envelopeInfo, nil)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if env.envelope == nil {
			t.Error("envelope should be initialized after first decrypt")
		}
	})

	t.Run("decrypts empty plaintext", func(t *testing.T) {
		env := NewEnvelope()
		original := []byte{}
		aad := []byte("aad")

		envelopeInfo, err := env.Encrypt(original, aad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		decrypted, err := env.Decrypt(envelopeInfo, aad)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Error("decrypted empty data does not match original")
		}
	})
}

func TestEnvelope_EncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("hello world"),
			aad:       []byte("context"),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
			aad:       []byte{0xAA, 0xBB, 0xCC},
		},
		{
			name:      "large data",
			plaintext: bytes.Repeat([]byte("large data "), 1000),
			aad:       []byte("large"),
		},
		{
			name:      "empty plaintext",
			plaintext: []byte{},
			aad:       []byte("empty"),
		},
		{
			name:      "empty aad",
			plaintext: []byte("data"),
			aad:       []byte{},
		},
		{
			name:      "nil aad",
			plaintext: []byte("data"),
			aad:       nil,
		},
		{
			name:      "unicode text",
			plaintext: []byte("Hello 世界 🌍"),
			aad:       []byte("unicode"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := NewEnvelope()

			// Encrypt
			envelopeInfo, err := env.Encrypt(tt.plaintext, tt.aad)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Decrypt
			decrypted, err := env.Decrypt(envelopeInfo, tt.aad)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("round trip failed: expected %v, got %v", tt.plaintext, decrypted)
			}
		})
	}
}

func TestEnvelope_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent encrypts", func(t *testing.T) {
		env := NewEnvelope()
		var wg sync.WaitGroup
		errors := make(chan error, 100)

		// Perform concurrent encrypts
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				plaintext := []byte("concurrent data")
				aad := []byte("aad")

				_, err := env.Encrypt(plaintext, aad)
				if err != nil {
					errors <- err
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("concurrent encrypt failed: %v", err)
		}
	})

	t.Run("concurrent decrypts", func(t *testing.T) {
		env := NewEnvelope()
		plaintext := []byte("concurrent decrypt test")
		aad := []byte("aad")

		// Pre-create encrypted data
		envelopeInfo, err := env.Encrypt(plaintext, aad)
		if err != nil {
			t.Fatalf("setup encrypt failed: %v", err)
		}

		var wg sync.WaitGroup
		errors := make(chan error, 100)

		// Perform concurrent decrypts
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				decrypted, err := env.Decrypt(envelopeInfo, aad)
				if err != nil {
					errors <- err
					return
				}

				if !bytes.Equal(decrypted, plaintext) {
					errors <- err
				}
			}()
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("concurrent decrypt failed: %v", err)
		}
	})

	t.Run("concurrent encrypt and decrypt", func(t *testing.T) {
		env := NewEnvelope()
		var wg sync.WaitGroup
		errors := make(chan error, 200)

		// Concurrent encrypts
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				plaintext := []byte("encrypt test")
				aad := []byte("aad")

				envelopeInfo, err := env.Encrypt(plaintext, aad)
				if err != nil {
					errors <- err
					return
				}

				// Also decrypt what we just encrypted
				decrypted, err := env.Decrypt(envelopeInfo, aad)
				if err != nil {
					errors <- err
					return
				}

				if !bytes.Equal(decrypted, plaintext) {
					errors <- err
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("concurrent encrypt/decrypt failed: %v", err)
		}
	})
}

func TestEnvelope_InitializationSafety(t *testing.T) {
	t.Run("multiple encrypts initialize once", func(t *testing.T) {
		env := NewEnvelope()

		_, err := env.Encrypt([]byte("first"), nil)
		if err != nil {
			t.Fatalf("first encrypt failed: %v", err)
		}

		firstEnvelope := env.envelope

		_, err = env.Encrypt([]byte("second"), nil)
		if err != nil {
			t.Fatalf("second encrypt failed: %v", err)
		}

		if env.envelope != firstEnvelope {
			t.Error("envelope should not be reinitialized")
		}
	})

	t.Run("multiple decrypts initialize once", func(t *testing.T) {
		env := NewEnvelope()
		env2 := NewEnvelope()

		envelopeInfo, err := env2.Encrypt([]byte("test"), nil)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		_, err = env.Decrypt(envelopeInfo, nil)
		if err != nil {
			t.Fatalf("first decrypt failed: %v", err)
		}

		firstEnvelope := env.envelope

		envelopeInfo2, err := env2.Encrypt([]byte("test2"), nil)
		if err != nil {
			t.Fatalf("second encrypt failed: %v", err)
		}

		_, err = env.Decrypt(envelopeInfo2, nil)
		if err != nil {
			t.Fatalf("second decrypt failed: %v", err)
		}

		if env.envelope != firstEnvelope {
			t.Error("envelope should not be reinitialized")
		}
	})
}

func BenchmarkEnvelope_Encrypt(b *testing.B) {
	env := NewEnvelope()
	plaintext := []byte("benchmark data for encryption testing")
	aad := []byte("additional authenticated data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := env.Encrypt(plaintext, aad)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
	}
}

func BenchmarkEnvelope_Decrypt(b *testing.B) {
	env := NewEnvelope()
	plaintext := []byte("benchmark data for decryption testing")
	aad := []byte("additional authenticated data")

	envelopeInfo, err := env.Encrypt(plaintext, aad)
	if err != nil {
		b.Fatalf("setup encrypt failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := env.Decrypt(envelopeInfo, aad)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}

func BenchmarkEnvelope_EncryptDecrypt(b *testing.B) {
	env := NewEnvelope()
	plaintext := []byte("benchmark data for round trip testing")
	aad := []byte("additional authenticated data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		envelopeInfo, err := env.Encrypt(plaintext, aad)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}

		_, err = env.Decrypt(envelopeInfo, aad)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}
