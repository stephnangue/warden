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

	// Handle token_ttl duration conversion
	if ttl, ok := dataCopy["token_ttl"].(string); ok {
		if d, err := time.ParseDuration(ttl); err == nil {
			dataCopy["token_ttl"] = d
		}
	}

	// Handle auth_deadline duration conversion
	if deadline, ok := dataCopy["auth_deadline"].(string); ok {
		if d, err := time.ParseDuration(deadline); err == nil {
			dataCopy["auth_deadline"] = d
		}
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

	if config.AuthDeadline == 0 {
		config.AuthDeadline = config.TokenTTL
	}

	if config.TokenType == "" {
		config.TokenType = "warden_token"
	}

	return &config, nil
}
