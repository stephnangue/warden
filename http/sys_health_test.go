package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHealthStatusOverrides(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		initialized bool
		sealed      bool
		standby     bool
		wantCode    int
	}{
		{
			name:     "no overrides",
			query:    "",
			standby:  true,
			wantCode: 0,
		},
		{
			name:     "standbyok makes standby return 200",
			query:    "standbyok=true",
			standby:  true,
			wantCode: http.StatusOK,
		},
		{
			name:     "standbyok ignored when not standby",
			query:    "standbyok=true",
			standby:  false,
			wantCode: 0,
		},
		{
			name:     "custom standby code",
			query:    "standbycode=200",
			standby:  true,
			wantCode: 200,
		},
		{
			name:        "custom sealed code",
			query:       "sealedcode=200",
			initialized: true,
			sealed:      true,
			wantCode:    200,
		},
		{
			name:        "custom uninit code",
			query:       "uninitcode=200",
			initialized: false,
			wantCode:    200,
		},
		{
			name:     "invalid code ignored",
			query:    "standbycode=abc",
			standby:  true,
			wantCode: 0,
		},
		{
			name:     "out of range code ignored",
			query:    "standbycode=999",
			standby:  true,
			wantCode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/sys/health?"+tt.query, nil)
			got := parseHealthStatusOverrides(r, tt.initialized, tt.sealed, tt.standby)
			assert.Equal(t, tt.wantCode, got)
		})
	}
}

func TestHealthResponse_JSON(t *testing.T) {
	resp := &HealthResponse{
		Initialized:   true,
		Sealed:        false,
		Standby:       false,
		ServerTimeUTC: 1234567890,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded HealthResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.Initialized, decoded.Initialized)
	assert.Equal(t, resp.Sealed, decoded.Sealed)
	assert.Equal(t, resp.Standby, decoded.Standby)
	assert.Equal(t, resp.ServerTimeUTC, decoded.ServerTimeUTC)
}
