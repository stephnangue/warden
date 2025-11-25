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

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) string {
    bytes := make([]byte, length)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)[:length]
}

func GenerateRequestID() string {
    return ulid.MustNew(ulid.Now(), rand.Reader).String()
}

func GenerateShortID() string {
    bytes := make([]byte, 4) // 4 bytes = 8 hex characters
    rand.Read(bytes)
    return hex.EncodeToString(bytes)
}