package api

import (
	"os"
	"strings"
)

const (
	WardenEnvPrefix  = "WARDEN_"
)

func ReadWardenVariable(name string) string {
	if strings.HasPrefix(name, WardenEnvPrefix) {
		return os.Getenv(name)
	}
	return ""
}