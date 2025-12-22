// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/physical/inmem"
	"github.com/stretchr/testify/require"
)

// getAESGCMBarrier extracts the AESGCMBarrier from a SecurityBarrier
func getAESGCMBarrier(sb SecurityBarrier) *AESGCMBarrier {
	if tb, ok := sb.(*TransactionalAESGCMBarrier); ok {
		return tb.AESGCMBarrier
	}
	return sb.(*AESGCMBarrier)
}

// mockBarrier returns a physical backend, security barrier, and root key
func mockBarrier(t testing.TB) (physical.Backend, SecurityBarrier, []byte) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)
	b.Unseal(context.Background(), key)
	return inm, b, key
}

func TestAESGCMBarrier_Basic(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	testBarrier(t, b)
}

func TestAESGCMBarrier_Rotate_Test(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	testBarrier_Rotate(t, b)
}

func TestAESGCMBarrier_MissingRotateConfig(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	b := getAESGCMBarrier(sb)

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)
	b.Unseal(context.Background(), key)

	// Write a keyring which lacks rotation config settings
	oldKeyring := b.keyring.Clone()
	oldKeyring.rotationConfig = KeyRotationConfig{}
	b.persistKeyring(context.Background(), oldKeyring)

	b.ReloadKeyring(context.Background())

	// At this point, the rotation config should match the default
	if !defaultRotationConfig.Equals(b.keyring.rotationConfig) {
		t.Fatal("expected empty rotation config to recover as default config")
	}
}

func TestAESGCMBarrier_Upgrade_Test(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b1, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b2, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	testBarrier_Upgrade(t, b1, b2)
}

func TestAESGCMBarrier_Upgrade_RotateRootKey_Test(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b1, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b2, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	testBarrier_Upgrade_RotateRootKey(t, b1, b2)
}

func TestAESGCMBarrier_RotateRootKey_Test(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	testBarrier_RotateRootKey(t, b)
}

// Verify data sent through is encrypted
func TestAESGCMBarrier_Confidential(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)
	b.Unseal(context.Background(), key)

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	err = b.Put(context.Background(), entry)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the physical entry
	pe, err := inm.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pe == nil {
		t.Fatal("missing physical entry")
	}

	if pe.Key != "test" {
		t.Fatalf("bad: %#v", pe)
	}
	if bytes.Equal(pe.Value, entry.Value) {
		t.Fatalf("bad: %#v", pe)
	}
}

// Verify data sent through cannot be tampered with
func TestAESGCMBarrier_Integrity(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)
	b.Unseal(context.Background(), key)

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	err = b.Put(context.Background(), entry)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Change a byte in the underlying physical entry
	pe, _ := inm.Get(context.Background(), "test")
	pe.Value[15]++
	err = inm.Put(context.Background(), pe)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Read from the barrier
	_, err = b.Get(context.Background(), "test")
	if err == nil {
		t.Fatal("should fail!")
	}
}

// Verify data sent through cannot be moved (version 1)
func TestAESGCMBarrier_MoveIntegrityV1(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)
	b.currentAESGCMVersionByte = AESGCMVersion1

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	err = b.Initialize(context.Background(), key, nil, rand.Reader)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	err = b.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	err = b.Put(context.Background(), entry)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Change the location of the underlying physical entry
	pe, _ := inm.Get(context.Background(), "test")
	pe.Key = "moved"
	err = inm.Put(context.Background(), pe)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Read from the barrier
	_, err = b.Get(context.Background(), "moved")
	if err != nil {
		t.Fatal("should succeed with version 1!")
	}
}

// Verify data sent through cannot be moved (version 2)
func TestAESGCMBarrier_MoveIntegrityV2(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)
	b.currentAESGCMVersionByte = AESGCMVersion2

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	err = b.Initialize(context.Background(), key, nil, rand.Reader)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	err = b.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	err = b.Put(context.Background(), entry)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Change the location of the underlying physical entry
	pe, _ := inm.Get(context.Background(), "test")
	pe.Key = "moved"
	err = inm.Put(context.Background(), pe)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Read from the barrier
	_, err = b.Get(context.Background(), "moved")
	if err == nil {
		t.Fatal("should fail with version 2!")
	}
}

// Test upgrading from V1 to V2
func TestAESGCMBarrier_UpgradeV1toV2(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)
	b.currentAESGCMVersionByte = AESGCMVersion1

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	err = b.Initialize(context.Background(), key, nil, rand.Reader)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	err = b.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	err = b.Put(context.Background(), entry)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Seal
	err = b.Seal()
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Open again as version 2
	sb, err = NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b = getAESGCMBarrier(sb)
	b.currentAESGCMVersionByte = AESGCMVersion2

	// Unseal
	err = b.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check successful decryption
	_, err = b.Get(context.Background(), "test")
	if err != nil {
		t.Fatal("Upgrade unsuccessful")
	}
}

// Test encryption uniqueness (nonce randomness)
func TestEncrypt_Unique(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)

	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)
	b.Unseal(context.Background(), key)

	if b.keyring == nil {
		t.Fatal("barrier is sealed")
	}

	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	term := b.keyring.ActiveTerm()
	primary, _ := b.aeadForTerm(term)

	first, err := b.encrypt("test", term, primary, entry.Value)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.encrypt("test", term, primary, entry.Value)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("improper random seeding detected")
	}
}

// Test key length validation during initialization
func TestInitialize_KeyLength(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)

	long := []byte("ThisKeyDoesNotHaveTheRightLength!")
	middle := []byte("ThisIsASecretKeyAndMore")
	short := []byte("Key")

	err = b.Initialize(context.Background(), long, nil, rand.Reader)

	if err == nil {
		t.Fatal("key length protection failed")
	}

	err = b.Initialize(context.Background(), middle, nil, rand.Reader)

	if err == nil {
		t.Fatal("key length protection failed")
	}

	err = b.Initialize(context.Background(), short, nil, rand.Reader)

	if err == nil {
		t.Fatal("key length protection failed")
	}
}

// Test BarrierEncryptor interface
func TestEncrypt_BarrierEncryptor(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)

	// Initialize and unseal
	key, err := b.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("err generating key: %v", err)
	}
	ctx := context.Background()
	b.Initialize(ctx, key, nil, rand.Reader)
	b.Unseal(ctx, key)

	cipher, err := b.Encrypt(ctx, "foo", []byte("quick brown fox"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	plain, err := b.Decrypt(ctx, "foo", cipher)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if string(plain) != "quick brown fox" {
		t.Fatalf("bad: %s", plain)
	}
}

// Ensure Decrypt returns an error when given invalid ciphertext
func TestDecrypt_InvalidCipherLength(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)

	key, err := b.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("err generating key: %v", err)
	}
	ctx := context.Background()
	b.Initialize(ctx, key, nil, rand.Reader)
	b.Unseal(ctx, key)

	var nilCipher []byte
	if _, err = b.Decrypt(ctx, "", nilCipher); err == nil {
		t.Fatal("expected error when given nil cipher")
	}
	emptyCipher := []byte{}
	if _, err = b.Decrypt(ctx, "", emptyCipher); err == nil {
		t.Fatal("expected error when given empty cipher")
	}

	badTermLengthCipher := make([]byte, 3)
	if _, err = b.Decrypt(ctx, "", badTermLengthCipher); err == nil {
		t.Fatal("expected error when given cipher with too short term")
	}
}

// Test ReloadKeyring functionality
func TestAESGCMBarrier_ReloadKeyring(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)
	b.Unseal(context.Background(), key)

	keyringRaw, err := inm.Get(context.Background(), keyringPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Encrypt something to test cache invalidation
	_, err = b.Encrypt(context.Background(), "foo", []byte("quick brown fox"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	{
		// Create a second barrier and rotate the keyring
		sb2, err := NewAESGCMBarrier(inm)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		b2 := getAESGCMBarrier(sb2)
		b2.Unseal(context.Background(), key)
		_, err = b2.Rotate(context.Background(), rand.Reader)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
	}

	// Reload the keyring on the first
	err = b.ReloadKeyring(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if b.keyring.ActiveTerm() != 2 {
		t.Fatal("failed to reload keyring")
	}
	if len(b.cache) != 0 {
		t.Fatal("failed to clear cache")
	}

	// Encrypt something to test cache invalidation
	_, err = b.Encrypt(context.Background(), "foo", []byte("quick brown fox"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Restore old keyring to test rolling back
	err = inm.Put(context.Background(), keyringRaw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Reload the keyring on the first
	err = b.ReloadKeyring(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if b.keyring.ActiveTerm() != 1 {
		t.Fatal("failed to reload keyring")
	}
	if len(b.cache) != 0 {
		t.Fatal("failed to clear cache")
	}
}

// Test legacy rotation check
func TestBarrier_LegacyRotate(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb1, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b1 := getAESGCMBarrier(sb1)
	key, _ := b1.GenerateKey(rand.Reader)
	b1.Initialize(context.Background(), key, nil, rand.Reader)
	err = b1.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	k1 := b1.keyring.TermKey(1)
	k1.Encryptions = 0
	k1.InstallTime = time.Now().Add(-24 * 366 * time.Hour)
	b1.persistKeyring(context.Background(), b1.keyring)
	b1.Seal()

	err = b1.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	reason, err := b1.CheckBarrierAutoRotate(context.Background())
	if err != nil || reason != legacyRotateReason {
		t.Fatalf("expected legacy rotate reason, got: %s, err: %v", reason, err)
	}
}

// Test encryption counting
func TestAESGCMBarrier_EncryptionCounting(t *testing.T) {
	_, b, _ := mockBarrier(t)
	barrier := getAESGCMBarrier(b)

	// Get initial encryption count (may not be 0 due to initialization)
	initialCount := barrier.TotalLocalEncryptions()

	// Perform some encryptions
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		_, err := barrier.Encrypt(ctx, "key", []byte("data"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
	}

	// Check encryption count increased by at least 10
	count := barrier.TotalLocalEncryptions()
	if count < initialCount+10 {
		t.Fatalf("expected at least %d encryptions, got %d", initialCount+10, count)
	}
}

// Test SetReadOnly functionality
func TestAESGCMBarrier_ReadOnly(t *testing.T) {
	_, b, _ := mockBarrier(t)
	barrier := getAESGCMBarrier(b)

	ctx := context.Background()

	// Should be able to write
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	err := barrier.Put(ctx, entry)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Set to read-only
	barrier.SetReadOnly(true)

	// Write should fail
	err = barrier.Put(ctx, entry)
	if err != logical.ErrReadOnly {
		t.Fatalf("expected ErrReadOnly, got: %v", err)
	}

	// Read should still work
	_, err = barrier.Get(ctx, "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Set back to read-write
	barrier.SetReadOnly(false)

	// Write should work again
	err = barrier.Put(ctx, entry)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

// Test AddRemoteEncryptions
func TestAESGCMBarrier_RemoteEncryptions(t *testing.T) {
	_, b, _ := mockBarrier(t)
	barrier := getAESGCMBarrier(b)

	// Add remote encryptions
	barrier.AddRemoteEncryptions(100)

	// Check that unaccounted encryptions increased
	count := barrier.UnaccountedEncryptions.Load()
	if count < 100 {
		t.Fatalf("expected at least 100 unaccounted encryptions, got %d", count)
	}

	// Check remote encryptions
	remoteCount := barrier.RemoteEncryptions.Load()
	if remoteCount < 100 {
		t.Fatalf("expected at least 100 remote encryptions, got %d", remoteCount)
	}
}

// Test ConsumeEncryptionCount
func TestAESGCMBarrier_ConsumeEncryptionCount(t *testing.T) {
	_, b, _ := mockBarrier(t)
	barrier := getAESGCMBarrier(b)

	// Get initial unaccounted count
	initial := barrier.UnaccountedEncryptions.Load()

	// Add some encryptions
	barrier.UnaccountedEncryptions.Add(50)

	var consumed int64
	err := barrier.ConsumeEncryptionCount(func(count int64) error {
		consumed = count
		return nil
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Should have consumed at least the 50 we added
	if consumed < initial+50 {
		t.Fatalf("expected to consume at least %d, got %d", initial+50, consumed)
	}

	// After successful consumption, count should be reduced to 0
	remaining := barrier.UnaccountedEncryptions.Load()
	if remaining != 0 {
		t.Fatalf("expected 0 remaining, got %d", remaining)
	}
}

// Test ActiveKeyInfo
func TestAESGCMBarrier_ActiveKeyInfo(t *testing.T) {
	_, b, _ := mockBarrier(t)

	info, err := b.ActiveKeyInfo()
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if info.Term != 1 {
		t.Fatalf("expected term 1, got %d", info.Term)
	}

	if info.InstallTime.IsZero() {
		t.Fatal("expected non-zero install time")
	}

	if time.Since(info.InstallTime) > time.Second {
		t.Fatalf("install time too old: %v", info.InstallTime)
	}
}

// Test Keyring retrieval
func TestAESGCMBarrier_Keyring(t *testing.T) {
	_, b, _ := mockBarrier(t)

	keyring, err := b.Keyring()
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if keyring == nil {
		t.Fatal("expected non-nil keyring")
	}

	if keyring.ActiveTerm() != 1 {
		t.Fatalf("expected active term 1, got %d", keyring.ActiveTerm())
	}
}

// Test RotationConfig
func TestAESGCMBarrier_RotationConfig(t *testing.T) {
	_, b, _ := mockBarrier(t)

	config, err := b.RotationConfig()
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if config.MaxOperations <= 0 {
		t.Fatalf("expected positive MaxOperations, got %d", config.MaxOperations)
	}

	// Set new config
	newConfig := KeyRotationConfig{
		MaxOperations: 1000000,
		Interval:      24 * time.Hour,
	}

	err = b.SetRotationConfig(context.Background(), newConfig)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify config was updated
	config, err = b.RotationConfig()
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if config.MaxOperations != 1000000 {
		t.Fatalf("expected MaxOperations 1000000, got %d", config.MaxOperations)
	}

	if config.Interval != 24*time.Hour {
		t.Fatalf("expected Interval 24h, got %v", config.Interval)
	}
}

// Test sealed barrier operations fail
func TestAESGCMBarrier_SealedOperations(t *testing.T) {
	inm, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sb, err := NewAESGCMBarrier(inm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := getAESGCMBarrier(sb)

	// Initialize but don't unseal
	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)

	ctx := context.Background()

	// All operations should fail when sealed
	_, err = b.Encrypt(ctx, "key", []byte("data"))
	require.Equal(t, ErrBarrierSealed, err)

	_, err = b.Decrypt(ctx, "key", []byte("data"))
	require.Equal(t, ErrBarrierSealed, err)

	_, err = b.ActiveKeyInfo()
	require.Equal(t, ErrBarrierSealed, err)

	_, err = b.Keyring()
	require.Equal(t, ErrBarrierSealed, err)

	_, err = b.Rotate(ctx, rand.Reader)
	require.Equal(t, ErrBarrierSealed, err)
}
