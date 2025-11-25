package jwt

import (
	"encoding/json"
	"fmt"
)

func mapToJWTAuthConfig(data map[string]any) (*JWTAuthConfig, error) {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal map: %w", err)
    }

    // Unmarshal JSON to struct
    var config JWTAuthConfig
    if err := json.Unmarshal(jsonData, &config); err != nil {
        return nil, fmt.Errorf("failed to unmarshal to JWTAuthConfig: %w", err)
    }
    
    return &config, nil
}