package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

func Get8BytesHash(value string) string {
	h := sha256.Sum256([]byte(value))

	short := h[:8]

	return hex.EncodeToString(short)
}

func GetHash(value string) string {
	h := sha256.Sum256([]byte(value))

	return hex.EncodeToString(h[:])
}

func JSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func GetMapKeys(m map[string]string) []string {
	if m == nil {
		return []string{}
	}

	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
