package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/stephnangue/warden/helper"
)

// AWSAccessKeysTokenType implements AWS-style access key generation
type AWSAccessKeysTokenType struct{}

func (t *AWSAccessKeysTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        "aws_access_keys",
		IDPrefix:    "awsk_",
		ValuePrefix: "AKIA",
		Description: "AWS-style access key/secret key pair",
		DefaultTTL:  12 * time.Hour,
	}
}

func (t *AWSAccessKeysTokenType) Generate(authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	accessKeyID := helper.GenerateAWSAccessKeyID()
	secretAccessKey := helper.GenerateAWSSecretAccessKey()

	entry.Data = map[string]string{
		"access_key_id":     accessKeyID,
		"secret_access_key": secretAccessKey,
	}

	return map[string]string{
		"access_key_id":     accessKeyID,
		"secret_access_key": secretAccessKey,
	}, nil
}

func (t *AWSAccessKeysTokenType) ExtractValue(tokenValue string) string {
	// For AWS, the access key ID is the lookup value
	return tokenValue
}

func (t *AWSAccessKeysTokenType) ValidateValue(tokenValue string) bool {
	return strings.HasPrefix(tokenValue, "AKIA") && len(tokenValue) == 20
}

func (t *AWSAccessKeysTokenType) ComputeID(lookupValue string) string {
	h := sha256.New()
	h.Write([]byte(lookupValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]
	return t.Metadata().IDPrefix + hash
}

func (t *AWSAccessKeysTokenType) LookupKey() string {
	return "access_key_id"
}
