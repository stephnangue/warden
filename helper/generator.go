package helper

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"

	"github.com/oklog/ulid"
)

func GenerateAWSSecretAccessKey() string {
	// Generate 30 random bytes for 40-character base64
	bytes := make([]byte, 30)
	rand.Read(bytes)

	// Use StdEncoding for AWS-like format (includes + and /)
	secret := base64.StdEncoding.EncodeToString(bytes)

	// AWS secrets are exactly 40 characters
	return secret[:40]
}

func GenerateAWSAccessKeyID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	prefix := "AKIA" // IAM User prefix
	remaining := make([]byte, 16)

	for i := range remaining {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		remaining[i] = chars[n.Int64()]
	}

	return prefix + string(remaining)
}

// GenerateRandomString generates a cryptographically secure random base64-encoded string
// suitable for tokens, secrets, and other security-sensitive use cases.
// The length parameter specifies the desired output string length (not the byte count).
// Uses URL-safe base64 encoding (no padding, uses - and _ instead of + and /).
// Minimum recommended length is 32 characters for secure tokens (192 bits of entropy).
func GenerateRandomString(length int) string {
	if length < 1 {
		panic("length must be at least 1")
	}

	// Calculate required bytes for base64 encoding
	// base64 produces 4 characters for every 3 bytes
	// We need ceiling division: (length * 3 + 3) / 4
	numBytes := (length*3 + 3) / 4

	bytes := make([]byte, numBytes)
	if _, err := rand.Read(bytes); err != nil {
		panic(err) // crypto/rand.Read should never fail on supported platforms
	}

	// Use RawURLEncoding for URL-safe tokens (no padding, uses - and _ instead of + and /)
	encoded := base64.RawURLEncoding.EncodeToString(bytes)

	// Only truncate if we generated more than needed
	if len(encoded) > length {
		return encoded[:length]
	}
	return encoded
}

func GenerateRequestID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}

func GenerateShortID() string {
	bytes := make([]byte, 4) // 4 bytes = 8 hex characters
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
