package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HMACer provides HMAC salting functionality
type HMACer struct {
	key []byte
}

// NewHMACer creates a new HMACer with the given key
func NewHMACer(key string) *HMACer {
	return &HMACer{
		key: []byte(key),
	}
}

// Salt salts a string using HMAC-SHA256
func (h *HMACer) Salt(ctx context.Context, data string) (string, error) {
	if data == "" {
		return "", nil
	}

	mac := hmac.New(sha256.New, h.key)
	_, err := mac.Write([]byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to compute HMAC: %w", err)
	}

	// Return hex-encoded HMAC with "hmac-" prefix to indicate it's salted
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

// SaltFunc returns a SaltFunc that uses this HMACer
func (h *HMACer) SaltFunc() SaltFunc {
	return func(ctx context.Context, data string) (string, error) {
		return h.Salt(ctx, data)
	}
}
