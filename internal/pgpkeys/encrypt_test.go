package pgpkeys

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// generateTestKey creates a PGP key pair for testing and returns
// the base64-encoded public key and the private entity.
func generateTestKey(t *testing.T, name string) (string, *openpgp.Entity) {
	t.Helper()
	entity, err := openpgp.NewEntity(name, "", name+"@test.com", &packet.Config{
		DefaultHash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("failed to generate PGP key: %v", err)
	}

	// Serialize public key
	var pubBuf bytes.Buffer
	if err := entity.Serialize(&pubBuf); err != nil {
		t.Fatalf("failed to serialize public key: %v", err)
	}

	return base64.StdEncoding.EncodeToString(pubBuf.Bytes()), entity
}

func TestEncryptShares_SingleShare(t *testing.T) {
	pubKey, _ := generateTestKey(t, "test-user")

	input := [][]byte{[]byte("secret-data")}
	pgpKeys := []string{pubKey}

	fingerprints, encrypted, err := EncryptShares(input, pgpKeys)
	if err != nil {
		t.Fatalf("EncryptShares failed: %v", err)
	}

	if len(fingerprints) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(fingerprints))
	}
	if len(fingerprints[0]) == 0 {
		t.Fatal("fingerprint is empty")
	}

	if len(encrypted) != 1 {
		t.Fatalf("expected 1 encrypted share, got %d", len(encrypted))
	}
	if len(encrypted[0]) == 0 {
		t.Fatal("encrypted share is empty")
	}
}

func TestEncryptShares_MultipleShares(t *testing.T) {
	pub1, _ := generateTestKey(t, "user-1")
	pub2, _ := generateTestKey(t, "user-2")
	pub3, _ := generateTestKey(t, "user-3")

	input := [][]byte{
		[]byte("share-1"),
		[]byte("share-2"),
		[]byte("share-3"),
	}
	pgpKeys := []string{pub1, pub2, pub3}

	fingerprints, encrypted, err := EncryptShares(input, pgpKeys)
	if err != nil {
		t.Fatalf("EncryptShares failed: %v", err)
	}

	if len(fingerprints) != 3 {
		t.Fatalf("expected 3 fingerprints, got %d", len(fingerprints))
	}
	if len(encrypted) != 3 {
		t.Fatalf("expected 3 encrypted shares, got %d", len(encrypted))
	}
}

func TestEncryptShares_MismatchedCount(t *testing.T) {
	pubKey, _ := generateTestKey(t, "test-user")

	input := [][]byte{[]byte("a"), []byte("b")}
	pgpKeys := []string{pubKey}

	_, _, err := EncryptShares(input, pgpKeys)
	if err == nil {
		t.Fatal("expected error for mismatched count")
	}
}

func TestEncryptShares_InvalidKey(t *testing.T) {
	input := [][]byte{[]byte("secret")}
	pgpKeys := []string{"not-valid-base64!!!"}

	_, _, err := EncryptShares(input, pgpKeys)
	if err == nil {
		t.Fatal("expected error for invalid PGP key")
	}
}

func TestEncryptShares_InvalidPGPData(t *testing.T) {
	input := [][]byte{[]byte("secret")}
	// Valid base64 but not a PGP key
	pgpKeys := []string{base64.StdEncoding.EncodeToString([]byte("not a pgp key"))}

	_, _, err := EncryptShares(input, pgpKeys)
	if err == nil {
		t.Fatal("expected error for invalid PGP data")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	pubKey, privEntity := generateTestKey(t, "round-trip-user")

	plaintext := "this is a secret message for round-trip testing"
	input := [][]byte{[]byte(plaintext)}
	pgpKeys := []string{pubKey}

	_, encrypted, err := EncryptShares(input, pgpKeys)
	if err != nil {
		t.Fatalf("EncryptShares failed: %v", err)
	}

	// Serialize the private key for DecryptBytes
	var privBuf bytes.Buffer
	if err := privEntity.SerializePrivate(&privBuf, nil); err != nil {
		t.Fatalf("failed to serialize private key: %v", err)
	}
	privKeyB64 := base64.StdEncoding.EncodeToString(privBuf.Bytes())
	encryptedB64 := base64.StdEncoding.EncodeToString(encrypted[0])

	decrypted, err := DecryptBytes(encryptedB64, privKeyB64)
	if err != nil {
		t.Fatalf("DecryptBytes failed: %v", err)
	}

	if decrypted.String() != plaintext {
		t.Fatalf("round-trip failed: expected %q, got %q", plaintext, decrypted.String())
	}
}

func TestGetEntities_Empty(t *testing.T) {
	entities, err := GetEntities([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entities) != 0 {
		t.Fatalf("expected 0 entities, got %d", len(entities))
	}
}

func TestGetFingerprints_FromKeys(t *testing.T) {
	pub1, _ := generateTestKey(t, "fp-user-1")
	pub2, _ := generateTestKey(t, "fp-user-2")

	fingerprints, err := GetFingerprints([]string{pub1, pub2}, nil)
	if err != nil {
		t.Fatalf("GetFingerprints failed: %v", err)
	}
	if len(fingerprints) != 2 {
		t.Fatalf("expected 2 fingerprints, got %d", len(fingerprints))
	}
	for i, fp := range fingerprints {
		if len(fp) == 0 {
			t.Fatalf("fingerprint %d is empty", i)
		}
	}
}
