package jwt

import (
	"encoding/json"
	"fmt"
	"time"
)

func mapToJWTAuthConfig(data map[string]any) (*JWTAuthConfig, error) {
	// Convert duration strings to actual durations before marshaling
	dataCopy := make(map[string]any)
	for k, v := range data {
		dataCopy[k] = v
	}

	// Handle token_ttl duration conversion from various source types:
	// - string: from storage if format changes, or manual config maps
	// - int: from framework's TypeDurationSecond (via d.GetOk)
	// - float64: from JSON decode when loading from storage
	// - time.Duration: from existing config copy in handleConfigWrite
	switch ttl := dataCopy["token_ttl"].(type) {
	case string:
		if d, err := time.ParseDuration(ttl); err == nil {
			dataCopy["token_ttl"] = d
		}
	case int:
		dataCopy["token_ttl"] = time.Duration(ttl) * time.Second
	case float64:
		dataCopy["token_ttl"] = time.Duration(int64(ttl)) * time.Second
	case time.Duration:
		// Already a duration, keep as-is
	}

	jsonData, err := json.Marshal(dataCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal map: %w", err)
	}

	// Unmarshal JSON to struct
	var config JWTAuthConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to JWTAuthConfig: %w", err)
	}

	// Mode validation is done in setupJWTConfig

	if config.UserClaim == "" {
		config.UserClaim = "sub"
	}

	if config.TokenTTL == 0 {
		config.TokenTTL = 1 * time.Hour
	}

	if config.TokenType == "" {
		config.TokenType = "warden_token"
	}

	return &config, nil
}
